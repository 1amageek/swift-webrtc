/// Fragment Assembler (RFC 4960 Section 6.9)
///
/// Reassembles fragmented SCTP user messages from multiple DATA chunks.
/// Handles both ordered and unordered delivery.

import Foundation

/// Assembled message ready for delivery
public struct AssembledMessage: Sendable {
    /// Stream identifier
    public let streamID: UInt16

    /// Stream sequence number (for ordered delivery)
    public let sequenceNumber: UInt16

    /// Payload protocol identifier
    public let ppid: UInt32

    /// Complete user data
    public let data: Data

    /// Whether this was delivered unordered
    public let unordered: Bool
}

/// Fragment information for reassembly
struct Fragment: Sendable {
    let tsn: UInt32
    let data: Data
    let isBeginning: Bool
    let isEnding: Bool
}

/// Key for identifying a fragmented message
struct FragmentKey: Hashable, Sendable {
    let streamID: UInt16
    let sequenceNumber: UInt16
    let unordered: Bool
    // For unordered messages, we use TSN of first fragment as identifier
    let firstTSN: UInt32?

    init(streamID: UInt16, sequenceNumber: UInt16, unordered: Bool, firstTSN: UInt32? = nil) {
        self.streamID = streamID
        self.sequenceNumber = sequenceNumber
        self.unordered = unordered
        self.firstTSN = unordered ? firstTSN : nil
    }
}

/// Reassembles fragmented messages
public struct FragmentAssembler: Sendable {
    /// Pending fragments keyed by (streamID, sequenceNumber, unordered)
    private var pendingFragments: [FragmentKey: [Fragment]]

    /// Expected sequence number per stream (for ordered delivery)
    private var expectedSequence: [UInt16: UInt16]

    /// Buffered complete messages waiting for in-order delivery
    private var orderedBuffer: [UInt16: [UInt16: AssembledMessage]]

    /// Maximum number of pending fragments before cleanup
    private let maxPendingFragments: Int = 1000

    /// Maximum age for fragments (in terms of TSN distance)
    private let maxFragmentAge: UInt32 = 65535

    public init() {
        self.pendingFragments = [:]
        self.expectedSequence = [:]
        self.orderedBuffer = [:]
    }

    /// Process a DATA chunk and return any complete messages
    /// - Parameters:
    ///   - chunk: The DATA chunk to process
    /// - Returns: Array of assembled messages ready for delivery
    public mutating func process(chunk: SCTPDataChunk) -> [AssembledMessage] {
        let isBeginning = chunk.flags & 0x02 != 0
        let isEnding = chunk.flags & 0x01 != 0
        let isUnordered = chunk.flags & 0x04 != 0

        let fragment = Fragment(
            tsn: chunk.tsn,
            data: chunk.userData,
            isBeginning: isBeginning,
            isEnding: isEnding
        )

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
                return deliverOrdered(message: message)
            }
        }

        // Multi-chunk message - find or create fragment group
        let key: FragmentKey
        if isUnordered {
            // For unordered, find existing group or create new
            if isBeginning {
                key = FragmentKey(
                    streamID: chunk.streamIdentifier,
                    sequenceNumber: chunk.streamSequenceNumber,
                    unordered: true,
                    firstTSN: chunk.tsn
                )
            } else {
                // Find existing group by matching stream and sequence
                if let existingKey = findUnorderedKey(
                    streamID: chunk.streamIdentifier,
                    sequenceNumber: chunk.streamSequenceNumber
                ) {
                    key = existingKey
                } else {
                    // No beginning fragment yet - create placeholder
                    key = FragmentKey(
                        streamID: chunk.streamIdentifier,
                        sequenceNumber: chunk.streamSequenceNumber,
                        unordered: true,
                        firstTSN: chunk.tsn
                    )
                }
            }
        } else {
            key = FragmentKey(
                streamID: chunk.streamIdentifier,
                sequenceNumber: chunk.streamSequenceNumber,
                unordered: false
            )
        }

        // Add fragment to group
        var fragments = pendingFragments[key] ?? []
        fragments.append(fragment)
        pendingFragments[key] = fragments

        // Try to assemble
        if let assembled = tryAssemble(key: key, ppid: chunk.payloadProtocolIdentifier) {
            pendingFragments.removeValue(forKey: key)

            if isUnordered {
                return [assembled]
            } else {
                return deliverOrdered(message: assembled)
            }
        }

        return []
    }

    /// Try to assemble fragments into a complete message
    private func tryAssemble(key: FragmentKey, ppid: UInt32) -> AssembledMessage? {
        guard let fragments = pendingFragments[key] else { return nil }

        // Sort fragments by TSN
        let sorted = fragments.sorted { TSNTracker.isLessThan($0.tsn, $1.tsn) }

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

        // Assemble data
        var data = Data()
        for fragment in sorted {
            data.append(fragment.data)
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
    private mutating func deliverOrdered(message: AssembledMessage) -> [AssembledMessage] {
        let streamID = message.streamID
        let seqNum = message.sequenceNumber

        let expected = expectedSequence[streamID] ?? 0

        if seqNum == expected {
            // In order - deliver immediately and check buffer
            var delivered = [message]
            expectedSequence[streamID] = seqNum &+ 1

            // Deliver any buffered messages that are now in order
            while let buffered = orderedBuffer[streamID]?.removeValue(forKey: expectedSequence[streamID] ?? 0) {
                delivered.append(buffered)
                expectedSequence[streamID] = (expectedSequence[streamID] ?? 0) &+ 1
            }

            return delivered
        } else if seqNum > expected || (expected > 0xF000 && seqNum < 0x1000) {
            // Out of order - buffer for later
            var streamBuffer = orderedBuffer[streamID] ?? [:]
            streamBuffer[seqNum] = message
            orderedBuffer[streamID] = streamBuffer
            return []
        } else {
            // Old/duplicate message - discard
            return []
        }
    }

    /// Find unordered fragment key by stream and sequence
    private func findUnorderedKey(streamID: UInt16, sequenceNumber: UInt16) -> FragmentKey? {
        for key in pendingFragments.keys {
            if key.streamID == streamID &&
               key.sequenceNumber == sequenceNumber &&
               key.unordered {
                return key
            }
        }
        return nil
    }

    /// Clean up stale fragments
    /// - Parameter currentTSN: Current cumulative TSN for age calculation
    public mutating func cleanup(currentTSN: UInt32) {
        // Remove fragment groups where all fragments are too old
        pendingFragments = pendingFragments.filter { _, fragments in
            guard let newest = fragments.max(by: { TSNTracker.isLessThan($0.tsn, $1.tsn) }) else {
                return false
            }
            let age = currentTSN &- newest.tsn
            return age < maxFragmentAge
        }

        // Limit total pending fragments
        if pendingFragments.count > maxPendingFragments {
            // Remove oldest groups first
            let sortedKeys = pendingFragments.keys.sorted { a, b in
                let aOldest = pendingFragments[a]?.min(by: { TSNTracker.isLessThan($0.tsn, $1.tsn) })?.tsn ?? 0
                let bOldest = pendingFragments[b]?.min(by: { TSNTracker.isLessThan($0.tsn, $1.tsn) })?.tsn ?? 0
                return TSNTracker.isLessThan(aOldest, bOldest)
            }

            let removeCount = pendingFragments.count - maxPendingFragments
            for key in sortedKeys.prefix(removeCount) {
                pendingFragments.removeValue(forKey: key)
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
        orderedBuffer.removeValue(forKey: streamID)
        pendingFragments = pendingFragments.filter { $0.key.streamID != streamID }
    }
}
