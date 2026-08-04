/// Fragment Assembler (RFC 4960 Section 6.9)
///
/// Reassembles fragmented SCTP user messages from multiple DATA chunks.
/// Handles both ordered and unordered delivery.
///
/// ## Caller-locked value type
///
/// This is a pure value `struct` with `mutating` methods. It holds no
/// `Synchronization.Mutex` / actor and no `ContinuousClock` / `Date`, and stores
/// payloads as `[UInt8]` (not Foundation `Data`). Reassembly is driven entirely by
/// TSN/stream-sequence ordering, so it needs no notion of wall-clock time. The
/// caller's `SCTPAssociation` holds it behind the association `Mutex`; host-only
/// compatibility overloads bridge `[UInt8]` to `Data`.

/// Assembled message ready for delivery
struct AssembledMessage: Sendable {
    /// Stream identifier
    let streamID: UInt16

    /// Stream sequence number (for ordered delivery)
    let sequenceNumber: UInt16

    /// Payload protocol identifier
    let ppid: UInt32

    /// Complete user data
    let data: [UInt8]

    /// Whether this was delivered unordered
    let unordered: Bool
}

/// Fragment information for reassembly
struct Fragment: Sendable {
    let tsn: UInt32
    let ppid: UInt32
    let data: SCTPByteView
    let isBeginning: Bool
    let isEnding: Bool
}

/// Key for identifying an ordered fragmented message.
struct FragmentKey: Hashable, Sendable {
    let streamID: UInt16
    let sequenceNumber: UInt16
}

/// One contiguous run of an unordered fragmented message.
///
/// Unordered SCTP messages do not receive distinct SSNs, so a single
/// `(streamID, SSN)` index cannot identify concurrent messages. Boundary flags
/// and TSN adjacency grow and merge these runs without crossing an E/B message
/// boundary.
struct UnorderedFragmentGroup: Sendable {
    let sequenceNumber: UInt16
    let ppid: UInt32
    var fragments: [Fragment]
}

private enum UnorderedFragmentAttachment {
    case append(leftIndex: Int)
    case prepend(rightIndex: Int)
    case bridge(leftIndex: Int, rightIndex: Int)
    case newGroup
}

/// Reassembles fragmented messages.
///
/// `SCTPAssociationEngine` bridges the typed `SCTPStateError` back to the
/// historical `SCTPError` while retaining `[UInt8]` payload ownership.
struct FragmentReassembler: Sendable {
    /// Pending ordered fragments keyed by (streamID, sequenceNumber).
    /// Fragment arrays are kept sorted by TSN (insertion order invariant).
    private var pendingFragments: [FragmentKey: [Fragment]]

    /// Pending unordered contiguous runs grouped by stream.
    private var pendingUnorderedFragmentGroups: [UInt16: [UnorderedFragmentGroup]]

    /// Expected sequence number per stream (for ordered delivery)
    private var expectedSequence: [UInt16: UInt16]

    /// Buffered complete messages waiting for in-order delivery
    private var orderedBuffer: [UInt16: [UInt16: AssembledMessage]]

    /// Total payload bytes currently held in `pendingFragments` and
    /// `orderedBuffer`. Maintained incrementally so SACK generation can
    /// report a receive window without scanning the buffers.
    private(set) var bufferedBytes: Int = 0

    /// Hard cap on concurrent pending fragment groups
    private let maxPendingFragments: Int = 1000

    /// Hard cap on buffered out-of-order messages per stream
    private let maxBufferedMessagesPerStream: Int = 1024

    /// Hard ceiling on total payload bytes held across `pendingFragments`
    /// and `orderedBuffer`. Without this a peer can exhaust memory by sending
    /// many large incomplete fragments or out-of-order messages while staying
    /// under the per-group and per-stream count caps.
    private let maxBufferedBytes: Int

    /// Default reassembly/reorder byte ceiling (16 MiB)
    static let defaultMaxBufferedBytes: Int = 16 * 1024 * 1024

    /// Maximum age for fragments (in terms of TSN distance)
    private let maxFragmentAge: UInt32 = 65535

    init() {
        self.pendingFragments = [:]
        self.pendingUnorderedFragmentGroups = [:]
        self.expectedSequence = [:]
        self.orderedBuffer = [:]
        self.maxBufferedBytes = Self.defaultMaxBufferedBytes
    }

    /// Configurable initializer (primarily for tests exercising the byte cap).
    init(maxBufferedBytes: Int) {
        self.pendingFragments = [:]
        self.pendingUnorderedFragmentGroups = [:]
        self.expectedSequence = [:]
        self.orderedBuffer = [:]
        self.maxBufferedBytes = maxBufferedBytes
    }

    /// Process a DATA chunk and return any complete messages
    /// - Parameters:
    ///   - chunk: The DATA chunk to process
    /// - Returns: Array of assembled messages ready for delivery
    /// - Throws: `SCTPStateError.receiveBufferExceeded` if the peer exceeds
    ///   reassembly or reordering buffer limits
    mutating func process(chunk: SCTPDataChunk) throws(SCTPStateError) -> [AssembledMessage] {
        let isBeginning = chunk.flags & 0x02 != 0
        let isEnding = chunk.flags & 0x01 != 0
        let isUnordered = chunk.flags & 0x04 != 0

        // Single-chunk message (both B and E flags set)
        if isBeginning && isEnding {
            let message = AssembledMessage(
                streamID: chunk.streamIdentifier,
                sequenceNumber: chunk.streamSequenceNumber,
                ppid: chunk.payloadProtocolIdentifier,
                data: chunk.userDataView.materialized(),
                unordered: isUnordered
            )

            if isUnordered {
                return [message]
            } else {
                return try deliverOrdered(message: message)
            }
        }

        // Enforce the total byte ceiling before admitting this fragment's
        // payload. Surface the overflow rather than silently dropping data.
        let (projectedBufferedBytes, overflow) = bufferedBytes.addingReportingOverflow(
            chunk.userDataByteCount
        )
        guard !overflow, projectedBufferedBytes <= maxBufferedBytes else {
            throw .receiveBufferExceeded(streamID: chunk.streamIdentifier)
        }

        let fragment = Fragment(
            tsn: chunk.tsn,
            ppid: chunk.payloadProtocolIdentifier,
            data: chunk.userDataView,
            isBeginning: isBeginning,
            isEnding: isEnding
        )

        if isUnordered {
            return try processUnorderedFragment(
                fragment,
                streamID: chunk.streamIdentifier,
                sequenceNumber: chunk.streamSequenceNumber,
                projectedBufferedBytes: projectedBufferedBytes
            )
        }

        let key = FragmentKey(
            streamID: chunk.streamIdentifier,
            sequenceNumber: chunk.streamSequenceNumber
        )

        // Enforce the group cap before creating a new group — a peer that
        // opens unbounded incomplete fragment groups is violating flow control.
        if pendingFragments[key] == nil && pendingCount >= maxPendingFragments {
            throw .receiveBufferExceeded(streamID: chunk.streamIdentifier)
        }

        // Mutate the dictionary-owned array through its modify accessor. Taking
        // a local Array value first would retain the old storage and force a
        // full copy of every prior fragment on each arrival (quadratic work for
        // a large message).
        Self.insertSorted(
            fragment,
            into: &pendingFragments[key, default: []]
        )
        bufferedBytes = projectedBufferedBytes

        // Try to assemble
        if let assembled = tryAssemble(key: key) {
            // Assembled data is the concatenation of every fragment in the
            // group, so its size equals the bytes leaving the buffer
            pendingFragments.removeValue(forKey: key)
            bufferedBytes -= assembled.data.count
            return try deliverOrdered(message: assembled)
        }

        return []
    }

    /// Try to assemble fragments into a complete message
    private func tryAssemble(key: FragmentKey) -> AssembledMessage? {
        // Fragments are maintained in TSN order by insertSorted
        guard let sorted = pendingFragments[key] else { return nil }

        // Check if we have beginning
        guard let first = sorted.first, first.isBeginning else { return nil }

        // Check if we have ending
        guard let last = sorted.last, last.isEnding else { return nil }

        // Check for contiguous TSNs
        var expectedTSN = first.tsn
        for fragment in sorted {
            if fragment.tsn != expectedTSN || fragment.ppid != first.ppid {
                return nil // Gap in TSNs
            }
            expectedTSN = expectedTSN &+ 1
        }

        // Assemble data with pre-allocation
        let totalSize = sorted.reduce(0) { $0 + $1.data.count }
        var data = [UInt8]()
        data.reserveCapacity(totalSize)
        for fragment in sorted {
            fragment.data.append(to: &data)
        }

        return AssembledMessage(
            streamID: key.streamID,
            sequenceNumber: key.sequenceNumber,
            ppid: first.ppid,
            data: data,
            unordered: false
        )
    }

    /// Admit one unordered fragment without using SSN as message identity.
    ///
    /// A fragment may extend a run on its left, its right, or bridge two runs.
    /// E/B boundaries deliberately block attachment so consecutive unordered
    /// messages with the same SSN remain distinct even under packet reordering.
    private mutating func processUnorderedFragment(
        _ fragment: Fragment,
        streamID: UInt16,
        sequenceNumber: UInt16,
        projectedBufferedBytes: Int
    ) throws(SCTPStateError) -> [AssembledMessage] {
        let attachment = Self.unorderedAttachment(
            for: fragment,
            sequenceNumber: sequenceNumber,
            in: pendingUnorderedFragmentGroups[streamID] ?? []
        )
        if case .newGroup = attachment {
            guard pendingCount < maxPendingFragments else {
                throw .receiveBufferExceeded(streamID: streamID)
            }
        }

        // Mutate the dictionary-owned group and fragment arrays in place. This
        // avoids retaining a local copy that would trigger nested Array COW on
        // every fragment arrival.
        let completedGroup = Self.admitUnorderedFragment(
            fragment,
            sequenceNumber: sequenceNumber,
            attachment: attachment,
            into: &pendingUnorderedFragmentGroups[streamID, default: []]
        )
        bufferedBytes = projectedBufferedBytes
        guard let group = completedGroup else {
            return []
        }

        let totalSize = group.fragments.reduce(0) { $0 + $1.data.count }
        var data: [UInt8] = []
        data.reserveCapacity(totalSize)
        for member in group.fragments {
            member.data.append(to: &data)
        }

        if pendingUnorderedFragmentGroups[streamID]?.isEmpty == true {
            pendingUnorderedFragmentGroups.removeValue(forKey: streamID)
        }
        bufferedBytes -= totalSize
        return [AssembledMessage(
            streamID: streamID,
            sequenceNumber: group.sequenceNumber,
            ppid: group.ppid,
            data: data,
            unordered: true
        )]
    }

    /// Deliver ordered message, buffering if out of order
    private mutating func deliverOrdered(message: AssembledMessage) throws(SCTPStateError) -> [AssembledMessage] {
        let streamID = message.streamID
        let seqNum = message.sequenceNumber

        let expected = expectedSequence[streamID] ?? 0

        if seqNum == expected {
            // In order - deliver immediately and check buffer
            var delivered = [message]
            expectedSequence[streamID] = seqNum &+ 1

            // Deliver any buffered messages that are now in order
            while let buffered = orderedBuffer[streamID]?.removeValue(forKey: expectedSequence[streamID] ?? 0) {
                bufferedBytes -= buffered.data.count
                delivered.append(buffered)
                expectedSequence[streamID] = (expectedSequence[streamID] ?? 0) &+ 1
            }

            return delivered
        } else if Self.ssnIsLessThan(expected, seqNum) {
            // Out of order - buffer for later. "Future" is decided by RFC 1982
            // serial-number comparison on the 16-bit SSN (matching the TSN path),
            // so a message that legitimately straddles the 0xFFFF→0x0000 wrap is
            // buffered instead of being dropped by a fixed 0xF000/0x1000 band.
            var streamBuffer = orderedBuffer[streamID] ?? [:]
            guard streamBuffer.count < maxBufferedMessagesPerStream else {
                throw .receiveBufferExceeded(streamID: streamID)
            }
            // Enforce the total byte ceiling before buffering this message.
            guard bufferedBytes + message.data.count <= maxBufferedBytes else {
                throw .receiveBufferExceeded(streamID: streamID)
            }
            streamBuffer[seqNum] = message
            orderedBuffer[streamID] = streamBuffer
            bufferedBytes += message.data.count
            return []
        } else {
            // Old/duplicate message - discard
            return []
        }
    }

    /// Clean up stale fragment groups by TSN age.
    ///
    /// Group count limits are enforced at insertion time (`process` throws),
    /// so this only garbage-collects abandoned incomplete groups.
    /// - Parameter currentTSN: Current cumulative TSN for age calculation
    mutating func cleanup(currentTSN: UInt32) {
        guard !pendingFragments.isEmpty || !pendingUnorderedFragmentGroups.isEmpty else {
            return
        }

        var staleKeys: [FragmentKey] = []
        for (key, fragments) in pendingFragments {
            // Fragments are TSN-sorted, so the newest is last
            guard let newest = fragments.last else {
                staleKeys.append(key)
                continue
            }
            // A gap can leave the cumulative TSN behind a newly buffered
            // fragment. Unsigned subtraction would interpret that future TSN
            // as almost UInt32.max bytes old and immediately discard it.
            guard TSNTracker.isLessThan(newest.tsn, currentTSN) else {
                continue
            }
            let age = currentTSN &- newest.tsn
            if age >= maxFragmentAge {
                staleKeys.append(key)
            }
        }

        for key in staleKeys {
            if let removed = pendingFragments.removeValue(forKey: key) {
                bufferedBytes -= removed.reduce(0) { $0 + $1.data.count }
            }
        }

        var retainedUnorderedGroups: [UInt16: [UnorderedFragmentGroup]] = [:]
        retainedUnorderedGroups.reserveCapacity(pendingUnorderedFragmentGroups.count)
        for (streamID, groups) in pendingUnorderedFragmentGroups {
            var retained: [UnorderedFragmentGroup] = []
            retained.reserveCapacity(groups.count)
            for group in groups {
                guard let newest = group.fragments.last else { continue }
                guard TSNTracker.isLessThan(newest.tsn, currentTSN) else {
                    retained.append(group)
                    continue
                }
                let age = currentTSN &- newest.tsn
                if age >= maxFragmentAge {
                    bufferedBytes -= group.fragments.reduce(0) {
                        $0 + $1.data.count
                    }
                } else {
                    retained.append(group)
                }
            }
            if !retained.isEmpty {
                retainedUnorderedGroups[streamID] = retained
            }
        }
        pendingUnorderedFragmentGroups = retainedUnorderedGroups
    }

    /// Apply the receive-side effects of an RFC 3758 FORWARD-TSN.
    ///
    /// Incomplete messages whose missing fragment was abandoned are released,
    /// then each ordered stream advances across the peer-declared SSN gap.
    /// Complete messages already buffered inside that gap are delivered rather
    /// than discarded, as required by RFC 3758 section 3.6.
    mutating func forward(
        cumulativeTSN: UInt32,
        skippedStreams: [SCTPForwardTSNSkippedStream]
    ) -> [AssembledMessage] {
        discardIncompleteMessagesMissingTSN(atOrBefore: cumulativeTSN)

        var delivered: [AssembledMessage] = []
        for skipped in skippedStreams {
            delivered.append(contentsOf: forwardOrderedStream(
                skipped.streamIdentifier,
                through: skipped.streamSequenceNumber
            ))
        }
        return delivered
    }

    /// Number of pending fragment groups
    var pendingCount: Int {
        pendingFragments.count + pendingUnorderedFragmentGroups.values.reduce(0) {
            $0 + $1.count
        }
    }

    /// Reset state for a stream
    mutating func resetStream(_ streamID: UInt16) {
        expectedSequence.removeValue(forKey: streamID)
        if let removedMessages = orderedBuffer.removeValue(forKey: streamID) {
            bufferedBytes -= removedMessages.values.reduce(0) { $0 + $1.data.count }
        }
        for (key, fragments) in pendingFragments where key.streamID == streamID {
            bufferedBytes -= fragments.reduce(0) { $0 + $1.data.count }
            pendingFragments.removeValue(forKey: key)
        }
        if let groups = pendingUnorderedFragmentGroups.removeValue(forKey: streamID) {
            bufferedBytes -= groups.reduce(0) { groupBytes, group in
                groupBytes + group.fragments.reduce(0) { $0 + $1.data.count }
            }
        }
    }

    /// Reset sequence and reassembly state for every stream without expanding
    /// an RFC 6525 "all streams" selection into 65,535 identifiers.
    mutating func resetAllStreams() {
        pendingFragments.removeAll(keepingCapacity: true)
        pendingUnorderedFragmentGroups.removeAll(keepingCapacity: true)
        expectedSequence.removeAll(keepingCapacity: true)
        orderedBuffer.removeAll(keepingCapacity: true)
        bufferedBytes = 0
    }

    /// Release every retained payload owner when the association is destroyed.
    ///
    /// Unlike a stream reset, terminal teardown also releases container capacity
    /// because the association cannot reuse it without a new handshake.
    package mutating func removeAll() {
        pendingFragments.removeAll(keepingCapacity: false)
        pendingUnorderedFragmentGroups.removeAll(keepingCapacity: false)
        expectedSequence.removeAll(keepingCapacity: false)
        orderedBuffer.removeAll(keepingCapacity: false)
        bufferedBytes = 0
    }

    // MARK: - Private helpers

    /// Discard only groups that provably need a missing TSN at or below the new
    /// cumulative acknowledgment. A group whose next missing fragment is still
    /// above the FORWARD-TSN remains valid and can complete later.
    private mutating func discardIncompleteMessagesMissingTSN(
        atOrBefore cumulativeTSN: UInt32
    ) {
        let abandonedOrderedKeys = pendingFragments.compactMap {
            key, fragments -> FragmentKey? in
            guard let missingTSN = Self.firstMissingTSN(in: fragments),
                  TSNTracker.isLessThanOrEqual(missingTSN, cumulativeTSN) else {
                return nil
            }
            return key
        }
        for key in abandonedOrderedKeys {
            if let removed = pendingFragments.removeValue(forKey: key) {
                bufferedBytes -= removed.reduce(0) { $0 + $1.data.count }
            }
        }

        var retainedUnordered: [UInt16: [UnorderedFragmentGroup]] = [:]
        retainedUnordered.reserveCapacity(pendingUnorderedFragmentGroups.count)
        for (streamID, groups) in pendingUnorderedFragmentGroups {
            var retainedGroups: [UnorderedFragmentGroup] = []
            retainedGroups.reserveCapacity(groups.count)
            for group in groups {
                if let missingTSN = Self.firstMissingTSN(in: group.fragments),
                   TSNTracker.isLessThanOrEqual(missingTSN, cumulativeTSN) {
                    bufferedBytes -= group.fragments.reduce(0) {
                        $0 + $1.data.count
                    }
                } else {
                    retainedGroups.append(group)
                }
            }
            if !retainedGroups.isEmpty {
                retainedUnordered[streamID] = retainedGroups
            }
        }
        pendingUnorderedFragmentGroups = retainedUnordered
    }

    private mutating func forwardOrderedStream(
        _ streamID: UInt16,
        through skippedSequenceNumber: UInt16
    ) -> [AssembledMessage] {
        let expected = expectedSequence[streamID] ?? 0
        let forwardDistance = skippedSequenceNumber &- expected
        guard forwardDistance < 0x8000 else {
            return []
        }

        let abandonedFragmentKeys = pendingFragments.keys.filter { key in
            guard key.streamID == streamID else { return false }
            return (key.sequenceNumber &- expected) <= forwardDistance
        }
        for key in abandonedFragmentKeys {
            if let removed = pendingFragments.removeValue(forKey: key) {
                bufferedBytes -= removed.reduce(0) { $0 + $1.data.count }
            }
        }

        var delivered: [AssembledMessage] = []
        if var streamBuffer = orderedBuffer.removeValue(forKey: streamID) {
            let availableSequenceNumbers = streamBuffer.keys
                .filter { ($0 &- expected) <= forwardDistance }
                .sorted { ($0 &- expected) < ($1 &- expected) }
            delivered.reserveCapacity(availableSequenceNumbers.count)
            for sequenceNumber in availableSequenceNumbers {
                if let message = streamBuffer.removeValue(forKey: sequenceNumber) {
                    bufferedBytes -= message.data.count
                    delivered.append(message)
                }
            }

            var nextExpected = skippedSequenceNumber &+ 1
            while let message = streamBuffer.removeValue(forKey: nextExpected) {
                bufferedBytes -= message.data.count
                delivered.append(message)
                nextExpected &+= 1
            }
            expectedSequence[streamID] = nextExpected
            if !streamBuffer.isEmpty {
                orderedBuffer[streamID] = streamBuffer
            }
        } else {
            expectedSequence[streamID] = skippedSequenceNumber &+ 1
        }
        return delivered
    }

    /// Return the earliest TSN that must still arrive for a fragment run to
    /// become complete. Fragment arrays are maintained in serial TSN order.
    private static func firstMissingTSN(
        in fragments: borrowing [Fragment]
    ) -> UInt32? {
        guard let first = fragments.first, let last = fragments.last else {
            return nil
        }
        if !first.isBeginning {
            return first.tsn &- 1
        }
        if fragments.count > 1 {
            for index in fragments.indices.dropFirst() {
                let previous = fragments[fragments.index(before: index)]
                if fragments[index].tsn != previous.tsn &+ 1 {
                    return previous.tsn &+ 1
                }
            }
        }
        if !last.isEnding {
            return last.tsn &+ 1
        }
        return nil
    }

    /// RFC 1982 serial-number comparison for the 16-bit Stream Sequence Number.
    /// Returns `true` iff `a` precedes `b` in serial order, correctly handling
    /// the 0xFFFF→0x0000 wrap. Mirrors `TSNTracker.isLessThan` for the 32-bit TSN.
    static func ssnIsLessThan(_ a: UInt16, _ b: UInt16) -> Bool {
        Int16(bitPattern: a &- b) < 0
    }

    /// Locate the TSN-adjacent run or runs without retaining their storage.
    private static func unorderedAttachment(
        for fragment: Fragment,
        sequenceNumber: UInt16,
        in groups: borrowing [UnorderedFragmentGroup]
    ) -> UnorderedFragmentAttachment {
        var leftIndex: Int?
        var rightIndex: Int?

        for index in groups.indices {
            let group = groups[index]
            guard group.sequenceNumber == sequenceNumber,
                  group.ppid == fragment.ppid,
                  let first = group.fragments.first,
                  let last = group.fragments.last else {
                continue
            }
            if last.tsn &+ 1 == fragment.tsn,
               !last.isEnding,
               !fragment.isBeginning {
                leftIndex = index
            }
            if fragment.tsn &+ 1 == first.tsn,
               !fragment.isEnding,
               !first.isBeginning {
                rightIndex = index
            }
        }

        switch (leftIndex, rightIndex) {
        case (.some(let left), .some(let right)) where left != right:
            return .bridge(leftIndex: left, rightIndex: right)
        case (.some(let left), _):
            return .append(leftIndex: left)
        case (_, .some(let right)):
            return .prepend(rightIndex: right)
        default:
            return .newGroup
        }
    }

    /// Apply a prevalidated unordered attachment and remove a complete group.
    ///
    /// The caller passes the dictionary's value through its modify accessor, so
    /// both the outer group array and the selected fragment array remain unique
    /// across the common append path.
    private static func admitUnorderedFragment(
        _ fragment: Fragment,
        sequenceNumber: UInt16,
        attachment: UnorderedFragmentAttachment,
        into groups: inout [UnorderedFragmentGroup]
    ) -> UnorderedFragmentGroup? {
        let affectedIndex: Int
        switch attachment {
        case .append(let leftIndex):
            groups[leftIndex].fragments.append(fragment)
            affectedIndex = leftIndex

        case .prepend(let rightIndex):
            groups[rightIndex].fragments.insert(fragment, at: 0)
            affectedIndex = rightIndex

        case .bridge(let leftIndex, let rightIndex):
            groups[leftIndex].fragments.append(fragment)
            groups[leftIndex].fragments.append(
                contentsOf: groups[rightIndex].fragments
            )
            groups.remove(at: rightIndex)
            affectedIndex = rightIndex < leftIndex
                ? leftIndex - 1
                : leftIndex

        case .newGroup:
            groups.append(UnorderedFragmentGroup(
                sequenceNumber: sequenceNumber,
                ppid: fragment.ppid,
                fragments: [fragment]
            ))
            affectedIndex = groups.index(before: groups.endIndex)
        }

        guard groups[affectedIndex].fragments.first?.isBeginning == true,
              groups[affectedIndex].fragments.last?.isEnding == true else {
            return nil
        }
        return groups.remove(at: affectedIndex)
    }

    /// Binary-insert a fragment keeping the array sorted by TSN
    private static func insertSorted(_ fragment: Fragment, into fragments: inout [Fragment]) {
        var low = 0
        var high = fragments.count
        while low < high {
            let mid = (low + high) / 2
            if TSNTracker.isLessThan(fragments[mid].tsn, fragment.tsn) {
                low = mid + 1
            } else {
                high = mid
            }
        }
        fragments.insert(fragment, at: low)
    }
}
