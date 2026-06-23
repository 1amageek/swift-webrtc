/// Retransmission Queue (RFC 4960 Section 6.3)
///
/// Manages unacknowledged DATA chunks for retransmission.
/// Implements T3-rtx timer logic and exponential backoff.
///
/// ## Caller-locked value type + injected time
///
/// This is a pure value `struct` with `mutating` methods. It holds no
/// `Synchronization.Mutex` / actor and no `ContinuousClock` / `Date`. Every method
/// that needs "now" takes a monotonic millisecond timestamp PARAMETER
/// (`nowMillis: UInt64`) supplied by the caller, and all RTO / RTT / SRTT / RTTVAR
/// quantities are kept in milliseconds as plain integers/doubles. The `SCTPCore`
/// adapter holds the queue behind its `Mutex`, reads `ContinuousClock` (epoch-
/// relative millis), and injects the value, so observable behavior is identical to
/// the previous `ContinuousClock`/`Duration`-backed implementation.

/// Pending chunk awaiting acknowledgment
public struct PendingChunk: Sendable {
    /// The DATA chunk
    public let dataChunk: SCTPDataChunk

    /// When the chunk was first sent (monotonic millis)
    public let firstSentMillis: UInt64

    /// When the chunk was last sent (monotonic millis)
    public var lastSentMillis: UInt64

    /// Number of retransmissions
    public var retransmitCount: Int

    /// Whether this chunk has been marked for retransmission
    public var markedForRetransmit: Bool

    /// Miss indications from SACK gap reports (RFC 4960 §7.2.4)
    public var missIndications: Int

    public init(dataChunk: SCTPDataChunk, sentMillis: UInt64) {
        self.dataChunk = dataChunk
        self.firstSentMillis = sentMillis
        self.lastSentMillis = sentMillis
        self.retransmitCount = 0
        self.markedForRetransmit = false
        self.missIndications = 0
    }
}

/// Retransmission queue state for reliable delivery.
///
/// The `SCTPCore` adapter wraps this in a `RetransmissionQueue` that restores the
/// historical `ContinuousClock`/`Duration` surface (epoch-relative millis
/// conversion); this value type does all the accounting in plain millis.
public struct RetransmissionState: Sendable {
    /// Pending chunks keyed by TSN
    private var pending: [UInt32: PendingChunk]

    /// Retransmission timeout (RTO) in milliseconds
    private var rtoMillis: UInt64

    /// Minimum RTO (milliseconds)
    private let minRTOMillis: UInt64 = 1000

    /// Maximum RTO (milliseconds)
    private let maxRTOMillis: UInt64 = 60000

    /// Maximum retransmissions before failure
    private let maxRetransmit: Int = 10

    /// Hard ceiling on bytes held in the retransmission queue. Sends are
    /// refused (typed backpressure) once this is reached so a peer that never
    /// SACKs cannot make the queue grow without bound.
    private let maxBytesInFlight: Int = 1 * 1024 * 1024 // 1 MiB

    /// Smoothed round-trip time (milliseconds), nil until first measurement
    private var srttMillis: Double?

    /// RTT variation (milliseconds), nil until first measurement
    private var rttvarMillis: Double?

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
        self.rtoMillis = 3000 // Initial RTO per RFC 4960
        self.bytesInFlight = 0
        self.cwnd = 4380 // Initial cwnd (3 * MTU, assuming 1460 MTU)
        self.ssthresh = 65535
    }

    /// Add a chunk to the retransmission queue, enforcing the send-window cap.
    /// - Parameters:
    ///   - chunk: The DATA chunk to track
    ///   - sentMillis: When the chunk was sent (monotonic millis)
    /// - Throws: `SCTPStateError.sendQueueFull` when admitting this chunk would
    ///   push the bytes-in-flight past `maxBytesInFlight` (backpressure). A chunk
    ///   already present (same TSN) is treated as a re-send and never rejected.
    public mutating func enqueue(_ chunk: SCTPDataChunk, sentMillis: UInt64) throws(SCTPStateError) {
        // Re-enqueueing an already-tracked TSN must not double-count bytes.
        if pending[chunk.tsn] != nil {
            pending[chunk.tsn] = PendingChunk(dataChunk: chunk, sentMillis: sentMillis)
            return
        }

        let (projected, overflow) = bytesInFlight.addingReportingOverflow(chunk.userData.count)
        guard !overflow, projected <= maxBytesInFlight else {
            throw .sendQueueFull(bytesInFlight: bytesInFlight, limit: maxBytesInFlight)
        }

        let pendingChunk = PendingChunk(dataChunk: chunk, sentMillis: sentMillis)
        pending[chunk.tsn] = pendingChunk
        bytesInFlight = projected

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
    ///   - receivedMillis: When the SACK was received (monotonic millis)
    /// - Returns: True if any new data was acknowledged
    public mutating func acknowledge(
        cumulativeTSN: UInt32,
        gapBlocks: [(start: UInt16, end: UInt16)],
        receivedMillis: UInt64
    ) -> Bool {
        var acknowledged = false

        // Remove chunks up to cumulative TSN
        let toRemove = pending.keys.filter { tsn in
            TSNTracker.isLessThanOrEqual(tsn, cumulativeTSN)
        }

        for tsn in toRemove {
            if let chunk = pending.removeValue(forKey: tsn) {
                // Guard against underflow: only ever subtract bytes we are
                // certain are still counted. removeValue guarantees each chunk
                // is accounted once, but clamp defensively so a logic error or
                // crafted SACK can never wrap bytesInFlight to a huge value.
                let (remaining, overflow) = bytesInFlight.subtractingReportingOverflow(chunk.dataChunk.userData.count)
                bytesInFlight = overflow ? 0 : max(0, remaining)
                acknowledged = true

                // Update RTT if this was the first transmission
                if chunk.retransmitCount == 0 {
                    updateRTT(sentMillis: chunk.lastSentMillis, receivedMillis: receivedMillis)
                }
            }
        }

        // Fast retransmit (RFC 4960 §7.2.4): chunks below the highest TSN
        // covered by a gap block that were NOT gap-acknowledged accumulate
        // miss indications; after 3 reports they are marked for fast
        // retransmission.
        if !gapBlocks.isEmpty {
            var highestGapOffset: UInt32 = 0
            for (start, end) in gapBlocks where start <= end {
                if UInt32(end) > highestGapOffset {
                    highestGapOffset = UInt32(end)
                }
            }
            let highestGapAcked = cumulativeTSN &+ highestGapOffset

            for (tsn, var chunk) in pending {
                let offset = tsn &- cumulativeTSN
                // Only TSNs after the cumulative ack and below the highest
                // gap-acked TSN can be reported missing.
                guard offset > 0, TSNTracker.isLessThan(tsn, highestGapAcked) else { continue }

                let isGapAcked = gapBlocks.contains { block in
                    block.start <= block.end &&
                    offset >= UInt32(block.start) && offset <= UInt32(block.end)
                }
                if !isGapAcked {
                    chunk.missIndications += 1
                    if chunk.missIndications >= 3 {
                        chunk.markedForRetransmit = true
                    }
                    pending[tsn] = chunk
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
    /// - Parameter nowMillis: Current monotonic time in milliseconds
    /// - Returns: Chunks to retransmit, or failure if max retransmits exceeded
    public mutating func pendingRetransmissions(nowMillis: UInt64) -> Result<[SCTPDataChunk], RetransmissionError> {
        // 1. Identify candidates (RTO expired or fast-retransmit marked)
        //    without mutating yet. If any candidate has already hit the
        //    retransmit ceiling, the association must abort (RFC 4960 §8.2).
        var candidateTSNs: [UInt32] = []
        var timerExpired = false
        var fastRetransmit = false

        for (tsn, chunk) in pending {
            // Elapsed since last send, guarding against non-monotonic skew.
            let elapsed = nowMillis >= chunk.lastSentMillis ? nowMillis - chunk.lastSentMillis : 0
            let rtoExpired = elapsed >= rtoMillis

            if rtoExpired || chunk.markedForRetransmit {
                if chunk.retransmitCount >= maxRetransmit {
                    return .failure(.maxRetransmitsExceeded(tsn: tsn))
                }
                if rtoExpired {
                    timerExpired = true
                } else {
                    fastRetransmit = true
                }
                candidateTSNs.append(tsn)
            }
        }

        // 2. Apply backoff and congestion response once per event, not once per
        //    expired chunk (RFC 4960 §6.3.3 E2, §7.2.3, §7.2.4). This runs
        //    before burst selection so the (possibly collapsed) cwnd bounds it.
        if timerExpired {
            rtoMillis = min(rtoMillis * 2, maxRTOMillis)
            ssthresh = max(cwnd / 2, 4 * 1460)
            cwnd = 1460
        } else if fastRetransmit {
            ssthresh = max(cwnd / 2, 4 * 1460)
            cwnd = ssthresh
        }

        guard !candidateTSNs.isEmpty else { return .success([]) }

        // Retransmit in TSN order (oldest first)
        candidateTSNs.sort { TSNTracker.isLessThan($0, $1) }

        // 3. Select up to cwnd bytes (always at least one chunk so the lowest
        //    outstanding TSN makes forward progress even when cwnd < chunk
        //    size), and mutate ONLY the chunks actually retransmitted. Chunks
        //    deferred for budget reasons keep their old lastSentMillis so the
        //    next tick re-selects them immediately rather than after a full RTO.
        var burst: [SCTPDataChunk] = []
        var budget = 0
        for tsn in candidateTSNs {
            guard var chunk = pending[tsn] else { continue }
            let size = chunk.dataChunk.userData.count
            if !burst.isEmpty {
                let (next, overflow) = budget.addingReportingOverflow(size)
                if overflow || next > cwnd { break }
                budget = next
            } else {
                budget = size
            }

            chunk.retransmitCount += 1
            chunk.lastSentMillis = nowMillis
            chunk.markedForRetransmit = false
            chunk.missIndications = 0
            pending[tsn] = chunk
            burst.append(chunk.dataChunk)
        }

        return .success(burst)
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

    /// Current RTO value in milliseconds
    public var currentRTOMillis: UInt64 {
        rtoMillis
    }

    // MARK: - Private

    private mutating func updateRTT(sentMillis: UInt64, receivedMillis: UInt64) {
        // RTT in milliseconds (guard against non-monotonic skew).
        let rttMillis = Double(receivedMillis >= sentMillis ? receivedMillis - sentMillis : 0)

        if let currentSRTT = srttMillis, let currentRTTVar = rttvarMillis {
            // RFC 4960 Section 6.3.1
            let alpha = 0.125
            let beta = 0.25

            let newRTTVar = (1 - beta) * currentRTTVar + beta * abs(currentSRTT - rttMillis)
            let newSRTT = (1 - alpha) * currentSRTT + alpha * rttMillis

            rttvarMillis = newRTTVar
            srttMillis = newSRTT

            // RTO = SRTT + 4 * RTTVAR, clamped to [minRTO, maxRTO]
            let newRTO = newSRTT + 4 * newRTTVar
            rtoMillis = Self.clampRTO(newRTO, minMillis: minRTOMillis, maxMillis: maxRTOMillis)
        } else {
            // First RTT measurement
            srttMillis = rttMillis
            rttvarMillis = rttMillis / 2
            let newRTO = rttMillis + 4 * (rttMillis / 2)
            rtoMillis = Self.clampRTO(newRTO, minMillis: minRTOMillis, maxMillis: maxRTOMillis)
        }
    }

    /// Clamp a millisecond RTO (as a Double) into `[minMillis, maxMillis]` and
    /// round to an integer millisecond, matching the historical seconds-based
    /// `max(min(rto, 60), 1)` clamp.
    private static func clampRTO(_ rtoMillis: Double, minMillis: UInt64, maxMillis: UInt64) -> UInt64 {
        let clamped = max(min(rtoMillis, Double(maxMillis)), Double(minMillis))
        return UInt64(clamped)
    }
}
