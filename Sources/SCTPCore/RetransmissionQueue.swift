/// Retransmission Queue (RFC 4960 Section 6.3)
///
/// Manages unacknowledged DATA chunks for retransmission.
/// Implements T3-rtx timer logic and exponential backoff.

import Foundation

/// Pending chunk awaiting acknowledgment
public struct PendingChunk: Sendable {
    /// The DATA chunk
    public let dataChunk: SCTPDataChunk

    /// When the chunk was first sent
    public let firstSentTime: ContinuousClock.Instant

    /// When the chunk was last sent
    public var lastSentTime: ContinuousClock.Instant

    /// Number of retransmissions
    public var retransmitCount: Int

    /// Whether this chunk has been marked for retransmission
    public var markedForRetransmit: Bool

    public init(dataChunk: SCTPDataChunk, sentTime: ContinuousClock.Instant) {
        self.dataChunk = dataChunk
        self.firstSentTime = sentTime
        self.lastSentTime = sentTime
        self.retransmitCount = 0
        self.markedForRetransmit = false
    }
}

/// Retransmission queue for reliable delivery
public struct RetransmissionQueue: Sendable {
    /// Pending chunks keyed by TSN
    private var pending: [UInt32: PendingChunk]

    /// Retransmission timeout (RTO) in milliseconds
    private var rto: Duration

    /// Minimum RTO
    private let minRTO: Duration = .milliseconds(1000)

    /// Maximum RTO
    private let maxRTO: Duration = .milliseconds(60000)

    /// Maximum retransmissions before failure
    private let maxRetransmit: Int = 10

    /// Smoothed round-trip time
    private var srtt: Duration?

    /// RTT variation
    private var rttvar: Duration?

    /// Highest TSN sent
    private(set) public var highestSentTSN: UInt32?

    /// Number of bytes in flight
    private(set) public var bytesInFlight: Int

    /// Congestion window (simplified)
    private(set) public var cwnd: Int

    /// Slow start threshold
    private var ssthresh: Int

    public init() {
        self.pending = [:]
        self.rto = .milliseconds(3000) // Initial RTO per RFC 4960
        self.bytesInFlight = 0
        self.cwnd = 4380 // Initial cwnd (3 * MTU, assuming 1460 MTU)
        self.ssthresh = 65535
    }

    /// Add a chunk to the retransmission queue
    /// - Parameters:
    ///   - chunk: The DATA chunk to track
    ///   - sentTime: When the chunk was sent
    public mutating func enqueue(_ chunk: SCTPDataChunk, sentTime: ContinuousClock.Instant = .now) {
        let pendingChunk = PendingChunk(dataChunk: chunk, sentTime: sentTime)
        pending[chunk.tsn] = pendingChunk
        bytesInFlight += chunk.userData.count

        if let highest = highestSentTSN {
            if TSNTracker.isLessThan(highest, chunk.tsn) {
                highestSentTSN = chunk.tsn
            }
        } else {
            highestSentTSN = chunk.tsn
        }
    }

    /// Process a SACK acknowledgment
    /// - Parameters:
    ///   - cumulativeTSN: Cumulative TSN acknowledged
    ///   - gapBlocks: Gap ack blocks
    ///   - receivedTime: When the SACK was received
    /// - Returns: True if any new data was acknowledged
    public mutating func acknowledge(
        cumulativeTSN: UInt32,
        gapBlocks: [(start: UInt16, end: UInt16)],
        receivedTime: ContinuousClock.Instant = .now
    ) -> Bool {
        var acknowledged = false

        // Remove chunks up to cumulative TSN
        let toRemove = pending.keys.filter { tsn in
            TSNTracker.isLessThanOrEqual(tsn, cumulativeTSN)
        }

        for tsn in toRemove {
            if let chunk = pending.removeValue(forKey: tsn) {
                bytesInFlight -= chunk.dataChunk.userData.count
                acknowledged = true

                // Update RTT if this was the first transmission
                if chunk.retransmitCount == 0 {
                    updateRTT(sentTime: chunk.lastSentTime, receivedTime: receivedTime)
                }
            }
        }

        // Mark gap-acknowledged chunks (don't remove, but note they're received)
        for (start, end) in gapBlocks {
            let gapStart = cumulativeTSN &+ UInt32(start)
            let gapEnd = cumulativeTSN &+ UInt32(end)

            for tsn in pending.keys {
                if TSNTracker.isInRange(tsn, start: gapStart, end: gapEnd) {
                    // This chunk was selectively acknowledged
                    // We could remove it, but keep for fast retransmit logic
                }
            }
        }

        // Update congestion window on acknowledgment
        if acknowledged {
            if bytesInFlight < ssthresh {
                // Slow start
                cwnd = min(cwnd + 1460, 65535)
            } else {
                // Congestion avoidance
                cwnd = min(cwnd + 1460 * 1460 / cwnd, 65535)
            }
        }

        return acknowledged
    }

    /// Get chunks that need retransmission
    /// - Parameter now: Current time
    /// - Returns: Chunks to retransmit, or nil if max retransmits exceeded
    public mutating func pendingRetransmissions(now: ContinuousClock.Instant = .now) -> Result<[SCTPDataChunk], RetransmissionError> {
        var toRetransmit: [SCTPDataChunk] = []

        for (tsn, var chunk) in pending {
            let elapsed = now - chunk.lastSentTime

            // Check if RTO expired or marked for fast retransmit
            if elapsed >= rto || chunk.markedForRetransmit {
                if chunk.retransmitCount >= maxRetransmit {
                    return .failure(.maxRetransmitsExceeded(tsn: tsn))
                }

                chunk.retransmitCount += 1
                chunk.lastSentTime = now
                chunk.markedForRetransmit = false
                pending[tsn] = chunk

                toRetransmit.append(chunk.dataChunk)

                // Exponential backoff
                rto = min(rto * 2, maxRTO)

                // Congestion control: reduce cwnd and ssthresh
                ssthresh = max(cwnd / 2, 4 * 1460)
                cwnd = 1460
            }
        }

        // Sort by TSN for proper ordering
        toRetransmit.sort { TSNTracker.isLessThan($0.tsn, $1.tsn) }

        return .success(toRetransmit)
    }

    /// Mark a chunk for fast retransmit (3 duplicate SACKs)
    /// - Parameter tsn: TSN to mark
    public mutating func markForFastRetransmit(tsn: UInt32) {
        pending[tsn]?.markedForRetransmit = true
    }

    /// Check if queue is empty
    public var isEmpty: Bool {
        pending.isEmpty
    }

    /// Number of pending chunks
    public var count: Int {
        pending.count
    }

    /// Check if we can send more data (congestion window check)
    public var canSend: Bool {
        bytesInFlight < cwnd
    }

    /// Current RTO value
    public var currentRTO: Duration {
        rto
    }

    // MARK: - Private

    private mutating func updateRTT(sentTime: ContinuousClock.Instant, receivedTime: ContinuousClock.Instant) {
        let rtt = receivedTime - sentTime

        if let currentSRTT = srtt, let currentRTTVar = rttvar {
            // RFC 4960 Section 6.3.1
            let alpha = 0.125
            let beta = 0.25

            let rttSeconds = Double(rtt.components.seconds) + Double(rtt.components.attoseconds) / 1e18
            let srttSeconds = Double(currentSRTT.components.seconds) + Double(currentSRTT.components.attoseconds) / 1e18
            let rttvarSeconds = Double(currentRTTVar.components.seconds) + Double(currentRTTVar.components.attoseconds) / 1e18

            let newRTTVar = (1 - beta) * rttvarSeconds + beta * abs(srttSeconds - rttSeconds)
            let newSRTT = (1 - alpha) * srttSeconds + alpha * rttSeconds

            rttvar = .seconds(newRTTVar)
            srtt = .seconds(newSRTT)

            // RTO = SRTT + 4 * RTTVAR
            let newRTO = newSRTT + 4 * newRTTVar
            rto = Duration.seconds(max(min(newRTO, 60), 1))
        } else {
            // First RTT measurement
            srtt = rtt
            rttvar = Duration.seconds(Double(rtt.components.seconds) / 2 + Double(rtt.components.attoseconds) / 2e18)
            let srttSeconds = Double(rtt.components.seconds) + Double(rtt.components.attoseconds) / 1e18
            let rttvarSeconds = srttSeconds / 2
            rto = Duration.seconds(max(min(srttSeconds + 4 * rttvarSeconds, 60), 1))
        }
    }
}

/// Retransmission errors
public enum RetransmissionError: Error, Sendable {
    case maxRetransmitsExceeded(tsn: UInt32)
}
