/// TSN Tracker (RFC 4960 Section 6.2)
///
/// Tracks received TSNs for SACK generation and duplicate detection.
/// Maintains cumulative TSN acknowledgment and gap blocks.
///
/// ## Caller-locked value type
///
/// This is a pure value `struct` with `mutating` methods. It holds no
/// `Synchronization.Mutex` / actor and no `ContinuousClock` / `Date` — the caller
/// (`SCTPAssociation`) owns synchronization and drives
/// these methods under its own lock. The structure carries no notion of time, so
/// no `nowMillis` is needed here.

/// Tracks received TSNs for selective acknowledgment
struct TSNTracker: Sendable {
    /// Initial TSN value (first expected TSN - 1)
    private let initialTSN: UInt32

    /// Cumulative TSN acknowledgment (highest contiguous TSN received)
    private(set) public var cumulativeTSN: UInt32

    /// TSNs received above cumulative, kept sorted in serial-number order
    /// relative to `cumulativeTSN`. Maintaining sorted insertion order avoids
    /// re-sorting the whole structure on every SACK and bounds the work per
    /// SACK to a single linear scan of the (capped) entries.
    private var receivedAboveCumulative: [UInt32]

    /// Recently received duplicate TSNs
    private var duplicates: [UInt32]

    /// Maximum number of duplicates to report
    private let maxDuplicates: Int = 16

    /// Maximum gap tracking window size
    private let windowSize: UInt32 = 65535

    /// Hard cap on sparse out-of-order TSNs held above the cumulative ack.
    /// RFC 4960 places no protocol limit here, but an unbounded set lets a peer
    /// that withholds one TSN force us to retain tens of thousands of entries.
    /// Beyond the cap we stop admitting new out-of-order TSNs (they will be
    /// retransmitted by the peer once the gap is filled).
    private let maxOutOfOrderTSNs: Int = 512

    /// Initialize with the peer's initial TSN
    /// - Parameter initialTSN: The initial TSN from INIT/INIT-ACK (first expected TSN)
    init(initialTSN: UInt32) {
        self.initialTSN = initialTSN
        // Cumulative starts at initialTSN - 1 (nothing received yet)
        self.cumulativeTSN = initialTSN &- 1
        self.receivedAboveCumulative = []
        self.duplicates = []
    }

    /// Receive a TSN
    /// - Parameter tsn: The TSN to receive
    /// - Returns: True if this is a new TSN, false if duplicate
    mutating func receive(tsn: UInt32) -> Bool {
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
        if let pos = sortedIndex(of: tsn), pos.found {
            addDuplicate(tsn)
            return false
        }

        // Is this the next expected TSN?
        if tsn == cumulativeTSN &+ 1 {
            // Advance cumulative
            cumulativeTSN = tsn

            // Check if we can advance further with the buffered TSNs at the
            // front of the sorted array (they start just above cumulative).
            while let next = receivedAboveCumulative.first, next == cumulativeTSN &+ 1 {
                receivedAboveCumulative.removeFirst()
                cumulativeTSN = cumulativeTSN &+ 1
            }
        } else {
            // Out of order — buffer it, subject to the cap. Surfacing an error
            // here would be wrong (a gap is normal), so we drop the new entry;
            // the peer retransmits it once the gap is filled.
            guard receivedAboveCumulative.count < maxOutOfOrderTSNs else {
                return false
            }
            guard let pos = sortedIndex(of: tsn) else {
                return false
            }
            receivedAboveCumulative.insert(tsn, at: pos.index)
        }

        return true
    }

    /// Advance the cumulative acknowledgment over DATA abandoned by the peer.
    ///
    /// RFC 3758 permits a FORWARD-TSN to skip missing TSNs. Already received
    /// higher TSNs remain useful and can advance the cumulative point further
    /// once the skipped gap is removed.
    /// - Returns: `true` only when the cumulative TSN advanced.
    mutating func advanceCumulativeTSN(to newCumulativeTSN: UInt32) -> Bool {
        guard Self.relation(newCumulativeTSN, to: cumulativeTSN) == .after else {
            return false
        }

        let forwardedDistance = newCumulativeTSN &- cumulativeTSN
        var firstRetainedIndex = receivedAboveCumulative.startIndex
        while firstRetainedIndex < receivedAboveCumulative.endIndex {
            let distance = receivedAboveCumulative[firstRetainedIndex] &- cumulativeTSN
            guard distance <= forwardedDistance else { break }
            firstRetainedIndex += 1
        }
        if firstRetainedIndex > receivedAboveCumulative.startIndex {
            receivedAboveCumulative.removeFirst(
                firstRetainedIndex - receivedAboveCumulative.startIndex
            )
        }

        cumulativeTSN = newCumulativeTSN
        var contiguousCount = 0
        while contiguousCount < receivedAboveCumulative.count,
              receivedAboveCumulative[contiguousCount] == cumulativeTSN &+ 1 {
            cumulativeTSN &+= 1
            contiguousCount += 1
        }
        if contiguousCount > 0 {
            receivedAboveCumulative.removeFirst(contiguousCount)
        }
        return true
    }

    /// Get gap ack blocks for SACK.
    /// Gap blocks are offsets from cumulative TSN.
    ///
    /// Computed on demand from the already-sorted out-of-order list, so no
    /// per-SACK re-sort is needed. SACKs are generated once per received
    /// packet, and any new TSN changes the gap structure, so caching across
    /// calls can never hit.
    var gapBlocks: [(start: UInt16, end: UInt16)] {
        gapBlocks(maximumCount: Int.max)
    }

    /// Get the lowest gap blocks that fit the caller's wire budget.
    ///
    /// RFC 9260 requires an oversized SACK to keep the lowest TSNs and leave
    /// higher blocks unacknowledged. Bounding during the scan avoids building a
    /// larger intermediate array only to truncate it at the packet boundary.
    func gapBlocks(
        maximumCount: Int
    ) -> [(start: UInt16, end: UInt16)] {
        computeGapBlocks(maximumCount: max(0, maximumCount))
    }

    /// Compute gap blocks from the maintained sorted list (no re-sort).
    private func computeGapBlocks(
        maximumCount: Int
    ) -> [(start: UInt16, end: UInt16)] {
        guard maximumCount > 0, !receivedAboveCumulative.isEmpty else { return [] }

        var blocks: [(start: UInt16, end: UInt16)] = []
        blocks.reserveCapacity(min(maximumCount, receivedAboveCumulative.count))
        var currentStart: UInt32?
        var currentEnd: UInt32?

        for tsn in receivedAboveCumulative {
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
                        if blocks.count == maximumCount {
                            return blocks
                        }
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

    /// Binary-search `receivedAboveCumulative` for `tsn` using serial-number
    /// ordering relative to `cumulativeTSN`.
    /// - Returns: the insertion index and whether an exact match was found,
    ///   or nil if `tsn` is not above the cumulative ack (caller treats this
    ///   as out of window).
    private func sortedIndex(of tsn: UInt32) -> (index: Int, found: Bool)? {
        let target = tsn &- cumulativeTSN
        guard target > 0 else { return nil }

        var low = 0
        var high = receivedAboveCumulative.count
        while low < high {
            let mid = (low + high) / 2
            let midOffset = receivedAboveCumulative[mid] &- cumulativeTSN
            if midOffset == target {
                return (mid, true)
            } else if midOffset < target {
                low = mid + 1
            } else {
                high = mid
            }
        }
        return (low, false)
    }

    /// Get and clear duplicate TSNs for SACK
    mutating func takeDuplicates() -> [UInt32] {
        let dups = duplicates
        duplicates.removeAll()
        return dups
    }

    /// Check if we have any gaps (useful for detecting missing packets)
    var hasGaps: Bool {
        !receivedAboveCumulative.isEmpty
    }

    /// Number of TSNs received above cumulative (gap size)
    var gapSize: Int {
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
    /// Compare two 32-bit serial numbers without assigning an order to the
    /// exact half-range distance forbidden by RFC 1982.
    static func relation(
        _ candidate: UInt32,
        to reference: UInt32
    ) -> SCTPSerialNumberRelation {
        let distance = candidate &- reference
        if distance == 0 {
            return .equal
        }
        if distance == 0x8000_0000 {
            return .ambiguous
        }
        return distance < 0x8000_0000 ? .after : .before
    }

    /// Compare two TSNs with wrap-around handling
    /// Returns true if a < b considering wrap-around
    static func isLessThan(_ a: UInt32, _ b: UInt32) -> Bool {
        relation(a, to: b) == .before
    }

    /// Compare two TSNs with wrap-around handling
    /// Returns true if a <= b considering wrap-around
    static func isLessThanOrEqual(_ a: UInt32, _ b: UInt32) -> Bool {
        a == b || isLessThan(a, b)
    }

    /// Check if a TSN is within range [start, end] with wrap-around
    static func isInRange(_ tsn: UInt32, start: UInt32, end: UInt32) -> Bool {
        if start <= end {
            return tsn >= start && tsn <= end
        } else {
            // Wrap-around case
            return tsn >= start || tsn <= end
        }
    }
}
