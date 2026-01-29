/// TSN Tracker (RFC 4960 Section 6.2)
///
/// Tracks received TSNs for SACK generation and duplicate detection.
/// Maintains cumulative TSN acknowledgment and gap blocks.

import Foundation

/// Tracks received TSNs for selective acknowledgment
public struct TSNTracker: Sendable {
    /// Initial TSN value (first expected TSN - 1)
    private let initialTSN: UInt32

    /// Cumulative TSN acknowledgment (highest contiguous TSN received)
    private(set) public var cumulativeTSN: UInt32

    /// TSNs received above cumulative (for gap blocks)
    private var receivedAboveCumulative: Set<UInt32>

    /// Recently received duplicate TSNs
    private var duplicates: [UInt32]

    /// Maximum number of duplicates to report
    private let maxDuplicates: Int = 16

    /// Maximum gap tracking window size
    private let windowSize: UInt32 = 65535

    /// Initialize with the peer's initial TSN
    /// - Parameter initialTSN: The initial TSN from INIT/INIT-ACK (first expected TSN)
    public init(initialTSN: UInt32) {
        self.initialTSN = initialTSN
        // Cumulative starts at initialTSN - 1 (nothing received yet)
        self.cumulativeTSN = initialTSN &- 1
        self.receivedAboveCumulative = []
        self.duplicates = []
    }

    /// Receive a TSN
    /// - Parameter tsn: The TSN to receive
    /// - Returns: True if this is a new TSN, false if duplicate
    public mutating func receive(tsn: UInt32) -> Bool {
        // Check if this TSN is within acceptable window
        let distance = tsn &- cumulativeTSN
        guard distance > 0 && distance <= windowSize else {
            // TSN is behind cumulative or too far ahead
            if distance == 0 || (distance > windowSize && tsn != cumulativeTSN &+ 1) {
                // This is a duplicate of an already-ACKed TSN
                addDuplicate(tsn)
                return false
            }
            return false
        }

        // Check if already received above cumulative
        if receivedAboveCumulative.contains(tsn) {
            addDuplicate(tsn)
            return false
        }

        // Is this the next expected TSN?
        if tsn == cumulativeTSN &+ 1 {
            // Advance cumulative
            cumulativeTSN = tsn

            // Check if we can advance further with buffered TSNs
            while receivedAboveCumulative.contains(cumulativeTSN &+ 1) {
                receivedAboveCumulative.remove(cumulativeTSN &+ 1)
                cumulativeTSN = cumulativeTSN &+ 1
            }
        } else {
            // Out of order - buffer it
            receivedAboveCumulative.insert(tsn)
        }

        return true
    }

    /// Get gap ack blocks for SACK
    /// Gap blocks are offsets from cumulative TSN
    public var gapBlocks: [(start: UInt16, end: UInt16)] {
        guard !receivedAboveCumulative.isEmpty else { return [] }

        // Sort received TSNs
        let sorted = receivedAboveCumulative.sorted { a, b in
            // Use signed comparison for TSN wrap-around
            let diffA = Int32(bitPattern: a &- cumulativeTSN)
            let diffB = Int32(bitPattern: b &- cumulativeTSN)
            return diffA < diffB
        }

        var blocks: [(start: UInt16, end: UInt16)] = []
        var currentStart: UInt32?
        var currentEnd: UInt32?

        for tsn in sorted {
            let offset = tsn &- cumulativeTSN
            guard offset > 0 && offset <= UInt32(UInt16.max) else { continue }

            if let end = currentEnd {
                if tsn == end &+ 1 {
                    // Extend current block
                    currentEnd = tsn
                } else {
                    // Finish current block, start new
                    if let start = currentStart {
                        let startOffset = start &- cumulativeTSN
                        let endOffset = end &- cumulativeTSN
                        blocks.append((UInt16(startOffset), UInt16(endOffset)))
                    }
                    currentStart = tsn
                    currentEnd = tsn
                }
            } else {
                // Start first block
                currentStart = tsn
                currentEnd = tsn
            }
        }

        // Add final block
        if let start = currentStart, let end = currentEnd {
            let startOffset = start &- cumulativeTSN
            let endOffset = end &- cumulativeTSN
            if startOffset <= UInt32(UInt16.max) && endOffset <= UInt32(UInt16.max) {
                blocks.append((UInt16(startOffset), UInt16(endOffset)))
            }
        }

        return blocks
    }

    /// Get and clear duplicate TSNs for SACK
    public mutating func takeDuplicates() -> [UInt32] {
        let dups = duplicates
        duplicates.removeAll()
        return dups
    }

    /// Check if we have any gaps (useful for detecting missing packets)
    public var hasGaps: Bool {
        !receivedAboveCumulative.isEmpty
    }

    /// Number of TSNs received above cumulative (gap size)
    public var gapSize: Int {
        receivedAboveCumulative.count
    }

    // MARK: - Private

    private mutating func addDuplicate(_ tsn: UInt32) {
        guard duplicates.count < maxDuplicates else { return }
        if !duplicates.contains(tsn) {
            duplicates.append(tsn)
        }
    }
}

// MARK: - TSN Comparison Utilities

extension TSNTracker {
    /// Compare two TSNs with wrap-around handling
    /// Returns true if a < b considering wrap-around
    public static func isLessThan(_ a: UInt32, _ b: UInt32) -> Bool {
        // Using serial number arithmetic (RFC 1982)
        let diff = Int32(bitPattern: a &- b)
        return diff < 0
    }

    /// Compare two TSNs with wrap-around handling
    /// Returns true if a <= b considering wrap-around
    public static func isLessThanOrEqual(_ a: UInt32, _ b: UInt32) -> Bool {
        a == b || isLessThan(a, b)
    }

    /// Check if a TSN is within range [start, end] with wrap-around
    public static func isInRange(_ tsn: UInt32, start: UInt32, end: UInt32) -> Bool {
        if start <= end {
            return tsn >= start && tsn <= end
        } else {
            // Wrap-around case
            return tsn >= start || tsn <= end
        }
    }
}
