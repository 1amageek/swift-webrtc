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
/// `SCTPCore` adapter holds it behind its `Mutex` and bridges `[UInt8]` to `Data`
/// at the public boundary.

/// Assembled message ready for delivery
public struct AssembledMessage: Sendable {
    /// Stream identifier
    public let streamID: UInt16

    /// Stream sequence number (for ordered delivery)
    public let sequenceNumber: UInt16

    /// Payload protocol identifier
    public let ppid: UInt32

    /// Complete user data
    public let data: [UInt8]

    /// Whether this was delivered unordered
    public let unordered: Bool
}

/// Fragment information for reassembly
struct Fragment: Sendable {
    let tsn: UInt32
    let data: [UInt8]
    let isBeginning: Bool
    let isEnding: Bool
}

/// Key for identifying a fragmented message
struct FragmentKey: Hashable, Sendable {
    let streamID: UInt16
    let sequenceNumber: UInt16
    let unordered: Bool
    // For unordered messages, the TSN of the first-arrived fragment
    // disambiguates the group.
    let firstTSN: UInt32?

    init(streamID: UInt16, sequenceNumber: UInt16, unordered: Bool, firstTSN: UInt32? = nil) {
        self.streamID = streamID
        self.sequenceNumber = sequenceNumber
        self.unordered = unordered
        self.firstTSN = unordered ? firstTSN : nil
    }
}

/// Reassembles fragmented messages.
///
/// The `SCTPCore` adapter wraps this in a `FragmentAssembler` that bridges the
/// core's typed `SCTPStateError` back to the historical `SCTPError` and the
/// `[UInt8]` payloads to `Data` at the public boundary.
public struct FragmentReassembler: Sendable {
    /// Pending fragments keyed by (streamID, sequenceNumber, unordered).
    /// Fragment arrays are kept sorted by TSN (insertion order invariant).
    private var pendingFragments: [FragmentKey: [Fragment]]

    /// O(1) lookup of unordered fragment groups by (streamID, sequenceNumber)
    private var unorderedKeyIndex: [UInt32: FragmentKey]

    /// Expected sequence number per stream (for ordered delivery)
    private var expectedSequence: [UInt16: UInt16]

    /// Buffered complete messages waiting for in-order delivery
    private var orderedBuffer: [UInt16: [UInt16: AssembledMessage]]

    /// Total payload bytes currently held in `pendingFragments` and
    /// `orderedBuffer`. Maintained incrementally so SACK generation can
    /// report a receive window without scanning the buffers.
    public private(set) var bufferedBytes: Int = 0

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
    public static let defaultMaxBufferedBytes: Int = 16 * 1024 * 1024

    /// Maximum age for fragments (in terms of TSN distance)
    private let maxFragmentAge: UInt32 = 65535

    public init() {
        self.pendingFragments = [:]
        self.unorderedKeyIndex = [:]
        self.expectedSequence = [:]
        self.orderedBuffer = [:]
        self.maxBufferedBytes = Self.defaultMaxBufferedBytes
    }

    /// Configurable initializer (primarily for tests exercising the byte cap).
    public init(maxBufferedBytes: Int) {
        self.pendingFragments = [:]
        self.unorderedKeyIndex = [:]
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
    public mutating func process(chunk: SCTPDataChunk) throws(SCTPStateError) -> [AssembledMessage] {
        let isBeginning = chunk.flags & 0x02 != 0
        let isEnding = chunk.flags & 0x01 != 0
        let isUnordered = chunk.flags & 0x04 != 0

        // Single-chunk message (both B and E flags set)
        if isBeginning && isEnding {
            let message = AssembledMessage(
                streamID: chunk.streamIdentifier,
                sequenceNumber: chunk.streamSequenceNumber,
                ppid: chunk.payloadProtocolIdentifier,
                data: chunk.userData,
                unordered: isUnordered
            )

            if isUnordered {
                return [message]
            } else {
                return try deliverOrdered(message: message)
            }
        }

        // Multi-chunk message - find or create fragment group
        let key: FragmentKey
        var indexKey: UInt32 = 0
        if isUnordered {
            indexKey = Self.unorderedIndexKey(
                streamID: chunk.streamIdentifier,
                sequenceNumber: chunk.streamSequenceNumber
            )
            if let existing = unorderedKeyIndex[indexKey] {
                key = existing
            } else {
                key = FragmentKey(
                    streamID: chunk.streamIdentifier,
                    sequenceNumber: chunk.streamSequenceNumber,
                    unordered: true,
                    firstTSN: chunk.tsn
                )
                unorderedKeyIndex[indexKey] = key
            }
        } else {
            key = FragmentKey(
                streamID: chunk.streamIdentifier,
                sequenceNumber: chunk.streamSequenceNumber,
                unordered: false
            )
        }

        // Enforce the group cap before creating a new group — a peer that
        // opens unbounded incomplete fragment groups is violating flow control.
        if pendingFragments[key] == nil && pendingFragments.count >= maxPendingFragments {
            if isUnordered {
                unorderedKeyIndex.removeValue(forKey: indexKey)
            }
            throw .receiveBufferExceeded(streamID: chunk.streamIdentifier)
        }

        // Enforce the total byte ceiling before admitting this fragment's
        // payload. Surface the overflow rather than silently dropping data.
        guard bufferedBytes + chunk.userData.count <= maxBufferedBytes else {
            if isUnordered && pendingFragments[key] == nil {
                unorderedKeyIndex.removeValue(forKey: indexKey)
            }
            throw .receiveBufferExceeded(streamID: chunk.streamIdentifier)
        }

        let fragment = Fragment(
            tsn: chunk.tsn,
            data: chunk.userData,
            isBeginning: isBeginning,
            isEnding: isEnding
        )

        // Insert at the sorted position so assembly never needs to re-sort
        var fragments = pendingFragments[key] ?? []
        Self.insertSorted(fragment, into: &fragments)
        pendingFragments[key] = fragments
        bufferedBytes += fragment.data.count

        // Try to assemble
        if let assembled = tryAssemble(key: key, ppid: chunk.payloadProtocolIdentifier) {
            // Assembled data is the concatenation of every fragment in the
            // group, so its size equals the bytes leaving the buffer
            pendingFragments.removeValue(forKey: key)
            bufferedBytes -= assembled.data.count
            if isUnordered {
                unorderedKeyIndex.removeValue(forKey: indexKey)
            }

            if isUnordered {
                return [assembled]
            } else {
                return try deliverOrdered(message: assembled)
            }
        }

        return []
    }

    /// Try to assemble fragments into a complete message
    private func tryAssemble(key: FragmentKey, ppid: UInt32) -> AssembledMessage? {
        // Fragments are maintained in TSN order by insertSorted
        guard let sorted = pendingFragments[key] else { return nil }

        // Check if we have beginning
        guard let first = sorted.first, first.isBeginning else { return nil }

        // Check if we have ending
        guard let last = sorted.last, last.isEnding else { return nil }

        // Check for contiguous TSNs
        var expectedTSN = first.tsn
        for fragment in sorted {
            if fragment.tsn != expectedTSN {
                return nil // Gap in TSNs
            }
            expectedTSN = expectedTSN &+ 1
        }

        // Assemble data with pre-allocation
        let totalSize = sorted.reduce(0) { $0 + $1.data.count }
        var data = [UInt8]()
        data.reserveCapacity(totalSize)
        for fragment in sorted {
            data.append(contentsOf: fragment.data)
        }

        return AssembledMessage(
            streamID: key.streamID,
            sequenceNumber: key.sequenceNumber,
            ppid: ppid,
            data: data,
            unordered: key.unordered
        )
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
    public mutating func cleanup(currentTSN: UInt32) {
        guard !pendingFragments.isEmpty else { return }

        var staleKeys: [FragmentKey] = []
        for (key, fragments) in pendingFragments {
            // Fragments are TSN-sorted, so the newest is last
            guard let newest = fragments.last else {
                staleKeys.append(key)
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
            if key.unordered {
                unorderedKeyIndex.removeValue(forKey: Self.unorderedIndexKey(
                    streamID: key.streamID,
                    sequenceNumber: key.sequenceNumber
                ))
            }
        }
    }

    /// Number of pending fragment groups
    public var pendingCount: Int {
        pendingFragments.count
    }

    /// Reset state for a stream
    public mutating func resetStream(_ streamID: UInt16) {
        expectedSequence.removeValue(forKey: streamID)
        if let removedMessages = orderedBuffer.removeValue(forKey: streamID) {
            bufferedBytes -= removedMessages.values.reduce(0) { $0 + $1.data.count }
        }
        for (key, fragments) in pendingFragments where key.streamID == streamID {
            bufferedBytes -= fragments.reduce(0) { $0 + $1.data.count }
            pendingFragments.removeValue(forKey: key)
        }
        unorderedKeyIndex = unorderedKeyIndex.filter { $0.value.streamID != streamID }
    }

    // MARK: - Private helpers

    private static func unorderedIndexKey(streamID: UInt16, sequenceNumber: UInt16) -> UInt32 {
        UInt32(streamID) << 16 | UInt32(sequenceNumber)
    }

    /// RFC 1982 serial-number comparison for the 16-bit Stream Sequence Number.
    /// Returns `true` iff `a` precedes `b` in serial order, correctly handling
    /// the 0xFFFF→0x0000 wrap. Mirrors `TSNTracker.isLessThan` for the 32-bit TSN.
    static func ssnIsLessThan(_ a: UInt16, _ b: UInt16) -> Bool {
        Int16(bitPattern: a &- b) < 0
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
