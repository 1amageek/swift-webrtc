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
/// quantities are kept in milliseconds as plain integers/doubles.
/// `SCTPAssociation` holds the engine behind its `Mutex` and injects monotonic
/// milliseconds through the clock seam on every target.

/// Pending chunk awaiting acknowledgment
struct PendingChunk: Sendable {
    /// The DATA chunk
    let dataChunk: SCTPDataChunk

    /// Complete user-message identity. RFC 3758 requires every fragment in a
    /// message to be abandoned atomically when any one fragment expires.
    let assignedMessage: SCTPAssignedMessage

    /// When the chunk was first sent (monotonic millis)
    var firstSentMillis: UInt64

    /// When the chunk was last sent (monotonic millis)
    var lastSentMillis: UInt64

    /// Number of retransmissions
    var retransmitCount: Int

    /// Whether this chunk has been marked for retransmission
    var transmissionState: PendingTransmissionState

    /// Miss indications from SACK gap reports (RFC 4960 §7.2.4)
    var missIndications: Int

    /// Whether this first transmission may still produce one RTT sample.
    /// Retransmitting an earlier-or-equal TSN invalidates later measurements
    /// that were already in flight (RFC 9260 §6.3.1 C5 / Karn's algorithm).
    var rttMeasurementEligible: Bool

    init(
        dataChunk: SCTPDataChunk,
        sentMillis: UInt64,
        assignedMessage: SCTPAssignedMessage? = nil
    ) {
        self.dataChunk = dataChunk
        self.assignedMessage = assignedMessage ?? SCTPAssignedMessage(
            firstTSN: dataChunk.tsn,
            lastTSN: dataChunk.tsn,
            reliability: .reliable
        )
        self.firstSentMillis = sentMillis
        self.lastSentMillis = sentMillis
        self.retransmitCount = 0
        self.transmissionState = .inFlight
        self.missIndications = 0
        self.rttMeasurementEligible = true
    }

    package init(
        dataChunk: SCTPDataChunk,
        admittedMillis: UInt64,
        transmissionState: PendingTransmissionState,
        assignedMessage: SCTPAssignedMessage? = nil
    ) {
        self.dataChunk = dataChunk
        self.assignedMessage = assignedMessage ?? SCTPAssignedMessage(
            firstTSN: dataChunk.tsn,
            lastTSN: dataChunk.tsn,
            reliability: .reliable
        )
        self.firstSentMillis = admittedMillis
        self.lastSentMillis = admittedMillis
        self.retransmitCount = 0
        self.transmissionState = transmissionState
        self.missIndications = 0
        self.rttMeasurementEligible = transmissionState == .inFlight
    }

    /// Whether this chunk contributes to congestion/receiver flight size.
    var countsTowardBytesInFlight: Bool {
        switch transmissionState {
        case .inFlight:
            true
        case .queued, .gapAcknowledged, .markedForRetransmission:
            false
        }
    }
}

/// Retransmission queue state for reliable delivery.
///
/// `SCTPAssociationEngine` owns this value and performs all accounting in plain
/// monotonic milliseconds supplied by its caller.
struct RetransmissionState: Sendable {
    /// Pending chunks keyed by TSN
    private var pending: [UInt32: PendingChunk]

    /// TSNs treated as finally acknowledged locally but not yet cumulatively
    /// acknowledged by the peer. Entries retain only scalar stream metadata,
    /// never payload owners.
    private var abandoned: [UInt32: SCTPAbandonedChunk]

    /// RFC 3758 C5 retransmission deadline for an outstanding FORWARD-TSN.
    private var forwardTSNDeadlineMillis: UInt64?
    private var lastForwardTSNCumulativeTSN: UInt32?
    private var forwardTSNRetransmitCount: Int

    /// Admission-order scalar queue. Payload owners live only in `pending`, so
    /// queueing does not retain a second copy of message storage.
    private var queuedTSNs: [UInt32]
    private var queuedHeadIndex: Int

    /// At most one DATA chunk is used as an exponentially backed-off receiver
    /// window probe. The TSN continues to be owned by `pending`.
    private var zeroWindowProbeTSN: UInt32?
    private var zeroWindowProbeDeadlineMillis: UInt64?
    private var zeroWindowProbeIntervalMillis: UInt64

    /// One frozen path-level T3-rtx deadline. This implementation currently
    /// has one SCTP path (DTLS transport), so a scalar exactly models RFC 9260
    /// §6.3.2. Per-chunk timestamps are retained only for RTT and diagnostics.
    private var t3DeadlineMillis: UInt64?

    /// After T3 expiry, no more than one SCTP DATA packet may remain in flight
    /// until that recovery probe is acknowledged (RFC 9260 §7.2.3).
    private var timeoutRecoveryProbeTSN: UInt32?

    /// Retransmission timeout (RTO) in milliseconds
    private var rtoMillis: UInt64

    /// Minimum RTO (milliseconds)
    private let minRTOMillis: UInt64 = 1000

    /// Maximum RTO (milliseconds)
    private let maxRTOMillis: UInt64 = 60000

    /// Maximum retransmissions before failure
    private let maxRetransmit: Int = 10

    /// Hard ceiling on bytes retained by the retransmission queue. Sends are
    /// refused (typed backpressure) once this is reached so a peer that never
    /// SACKs cannot make the queue grow without bound.
    private let retainedPayloadByteLimit: Int = 1 * 1024 * 1024 // 1 MiB

    /// Byte limits alone do not bound dictionary/fragment metadata for empty or
    /// tiny DATA chunks.
    private let retainedChunkLimit: Int = 4096

    /// Smoothed round-trip time (milliseconds), nil until first measurement
    private var srttMillis: Double?

    /// RTT variation (milliseconds), nil until first measurement
    private var rttvarMillis: Double?

    /// Highest TSN sent
    private(set) public var highestSentTSN: UInt32?

    /// Latest cumulative acknowledgment committed from a valid SACK.
    private var cumulativeTSNAckPoint: UInt32?

    /// Total payload owner bytes retained until cumulative acknowledgment.
    private(set) public var retainedPayloadByteCount: Int

    /// Number of bytes in flight
    private(set) public var bytesInFlight: Int

    /// Last peer-advertised receive window and the effective remaining window
    /// after currently outstanding bytes.
    private(set) public var peerAdvertisedReceiverWindow: UInt32
    private(set) public var peerReceiverWindow: UInt64

    /// Congestion window (simplified)
    private(set) public var cwnd: Int

    /// Slow start threshold
    private var ssthresh: Int

    init(
        initialTSN: UInt32? = nil,
        peerAdvertisedReceiverWindow: UInt32 = 65_535
    ) {
        self.pending = [:]
        self.abandoned = [:]
        self.forwardTSNDeadlineMillis = nil
        self.lastForwardTSNCumulativeTSN = nil
        self.forwardTSNRetransmitCount = 0
        self.queuedTSNs = []
        self.queuedHeadIndex = 0
        self.zeroWindowProbeTSN = nil
        self.zeroWindowProbeDeadlineMillis = nil
        self.zeroWindowProbeIntervalMillis = 3000
        self.t3DeadlineMillis = nil
        self.timeoutRecoveryProbeTSN = nil
        self.rtoMillis = 3000 // Initial RTO per RFC 4960
        self.cumulativeTSNAckPoint = initialTSN.map { $0 &- 1 }
        self.retainedPayloadByteCount = 0
        self.bytesInFlight = 0
        self.peerAdvertisedReceiverWindow = peerAdvertisedReceiverWindow
        self.peerReceiverWindow = UInt64(peerAdvertisedReceiverWindow)
        self.cwnd = 4380 // Initial cwnd (3 * MTU, assuming 1460 MTU)
        self.ssthresh = 65535
    }

    /// Validate send-window capacity without constructing DATA fragments.
    ///
    /// Callers use this before allocating fragment descriptors or encoded
    /// packets for a new user message. The mutating enqueue paths repeat the
    /// same check at commit time so admission remains atomic if the state has
    /// changed between planning and commit.
    package func validateAdditionalByteCount(
        _ additionalByteCount: Int,
        additionalChunkCount: Int = 0
    ) throws(SCTPStateError) {
        let (projected, overflow) = retainedPayloadByteCount.addingReportingOverflow(
            additionalByteCount
        )
        guard additionalByteCount >= 0,
              !overflow,
              projected <= retainedPayloadByteLimit else {
            throw .sendQueueFull(
                bytesInFlight: retainedPayloadByteCount,
                limit: retainedPayloadByteLimit
            )
        }
        let (projectedCount, countOverflow) = pending.count.addingReportingOverflow(
            additionalChunkCount
        )
        guard additionalChunkCount >= 0,
              !countOverflow,
              projectedCount <= retainedChunkLimit else {
            throw .sendChunkLimitReached(
                retainedChunkCount: pending.count,
                limit: retainedChunkLimit
            )
        }
    }

    /// Add a chunk to the retransmission queue, enforcing the retained-owner cap.
    /// - Parameters:
    ///   - chunk: The DATA chunk to track
    ///   - sentMillis: When the chunk was sent (monotonic millis)
    /// - Throws: `SCTPStateError.sendQueueFull` when admitting this chunk would
    ///   push retained payload owners past the association limit. A chunk
    ///   already present (same TSN) is treated as a re-send and never rejected.
    mutating func enqueue(_ chunk: SCTPDataChunk, sentMillis: UInt64) throws(SCTPStateError) {
        // Re-enqueueing an already-tracked TSN must not double-count bytes.
        if pending[chunk.tsn] != nil {
            return
        }

        try validateAdditionalByteCount(
            chunk.userDataByteCount,
            additionalChunkCount: 1
        )
        let projectedRetained = retainedPayloadByteCount + chunk.userDataByteCount
        let projectedFlight = bytesInFlight + chunk.userDataByteCount

        let pendingChunk = PendingChunk(dataChunk: chunk, sentMillis: sentMillis)
        pending[chunk.tsn] = pendingChunk
        retainedPayloadByteCount = projectedRetained
        bytesInFlight = projectedFlight
        if cumulativeTSNAckPoint == nil {
            cumulativeTSNAckPoint = chunk.tsn &- 1
        }

        if let highest = highestSentTSN {
            if TSNTracker.isLessThan(highest, chunk.tsn) {
                highestSentTSN = chunk.tsn
            }
        } else {
            highestSentTSN = chunk.tsn
        }
        startT3IfStopped(nowMillis: sentMillis)
        updatePeerReceiverWindow()
    }

    /// Atomically admit every fragment of one SCTP user message as queued DATA.
    ///
    /// Admission retains one immutable payload owner plus scalar TSNs, but does
    /// not make any fragment outstanding. A later outbound opportunity performs
    /// the `.queued` to `.inFlight` transition under cwnd and rwnd constraints.
    package mutating func admit(
        contentsOf chunks: [SCTPDataChunk],
        at admittedMillis: UInt64,
        reliability: SCTPAssignedMessageReliability = .reliable
    ) throws(SCTPStateError) {
        var additionalByteCount = 0
        for chunk in chunks where pending[chunk.tsn] == nil {
            let (next, overflow) = additionalByteCount.addingReportingOverflow(
                chunk.userDataByteCount
            )
            guard !overflow else {
                throw .sendQueueFull(
                    bytesInFlight: retainedPayloadByteCount,
                    limit: retainedPayloadByteLimit
                )
            }
            additionalByteCount = next
        }

        let additionalChunkCount = chunks.reduce(into: 0) { count, chunk in
            if pending[chunk.tsn] == nil {
                count += 1
            }
        }
        try validateAdditionalByteCount(
            additionalByteCount,
            additionalChunkCount: additionalChunkCount
        )
        let projectedRetained = retainedPayloadByteCount + additionalByteCount

        guard let firstChunk = chunks.first, let lastChunk = chunks.last else {
            return
        }
        let assignedMessage = SCTPAssignedMessage(
            firstTSN: firstChunk.tsn,
            lastTSN: lastChunk.tsn,
            reliability: reliability
        )

        for chunk in chunks {
            guard pending[chunk.tsn] == nil else {
                continue
            }
            pending[chunk.tsn] = PendingChunk(
                dataChunk: chunk,
                admittedMillis: admittedMillis,
                transmissionState: .queued,
                assignedMessage: assignedMessage
            )
            queuedTSNs.append(chunk.tsn)
            if cumulativeTSNAckPoint == nil {
                cumulativeTSNAckPoint = chunk.tsn &- 1
            }
        }
        retainedPayloadByteCount = projectedRetained
    }

    /// Select DATA for one sender opportunity, always prioritizing marked
    /// retransmissions before newly admitted fragments.
    package mutating func outboundChunks(
        nowMillis: UInt64,
        trigger: SCTPOutboundTrigger,
        maximumBurstPacketCount: Int = 4
    ) -> Result<[SCTPDataChunk], RetransmissionError> {
        // Let an expired path timer perform the normal RFC 9260 timeout
        // response before RFC 3758 discards timed messages. At every other
        // sender opportunity TR4 is evaluated before transmission.
        let t3IsExpired = trigger == .timer
            && t3DeadlineMillis.map { nowMillis >= $0 } == true
        if !t3IsExpired {
            switch abandonExpiredMessages(nowMillis: nowMillis) {
            case .success:
                break
            case .failure(let error):
                return .failure(error)
            }
        }
        let burstLimit = max(1, maximumBurstPacketCount)
        let retransmissions: [SCTPDataChunk]
        switch pendingRetransmissions(
            nowMillis: nowMillis,
            includeExpired: trigger == .timer,
            maximumChunkCount: burstLimit
        ) {
        case .success(let chunks):
            retransmissions = chunks
        case .failure(let error):
            return .failure(error)
        }

        var outbound = retransmissions
        let remainingBurst = max(0, burstLimit - outbound.count)
        if remainingBurst > 0, timeoutRecoveryProbeTSN == nil {
            outbound.append(contentsOf: transmitQueuedChunks(
                nowMillis: nowMillis,
                maximumChunkCount: remainingBurst
            ))
        }

        scheduleZeroWindowProbeIfNeeded(nowMillis: nowMillis)
        if trigger == .timer,
           outbound.isEmpty,
           let probe = zeroWindowProbeIfDue(nowMillis: nowMillis) {
            outbound.append(probe)
        }
        return .success(outbound)
    }

    /// Build the latest RFC 3758 FORWARD-TSN that can fit in one packet.
    ///
    /// The cumulative point advances only across consecutive abandoned TSNs.
    /// Ordered streams appear once with their highest skipped SSN; unordered
    /// messages never produce stream entries. Sending commits only scalar timer
    /// state and extends the highest point a peer may validly acknowledge.
    package mutating func pendingForwardTSN(
        nowMillis: UInt64,
        force: Bool,
        maximumPacketByteCount: Int = 1_200
    ) -> Result<SCTPForwardTSNChunk?, RetransmissionError> {
        guard let cumulativeTSNAckPoint,
              maximumPacketByteCount >= 20 else {
            return .success(nil)
        }
        let shouldSend = force
            || forwardTSNDeadlineMillis == nil
            || nowMillis >= (forwardTSNDeadlineMillis ?? UInt64.max)
        guard shouldSend else { return .success(nil) }

        let maximumStreamEntryCount = (maximumPacketByteCount - 20) / 4
        var skippedByStream: [UInt16: UInt16] = [:]
        var candidate = cumulativeTSNAckPoint &+ 1
        var newCumulativeTSN: UInt32?
        var visitedCount = 0
        while visitedCount < abandoned.count,
              let descriptor = abandoned[candidate] {
            if !descriptor.unordered {
                if let existing = skippedByStream[descriptor.streamIdentifier] {
                    if Self.isLaterSSN(
                        descriptor.streamSequenceNumber,
                        than: existing
                    ) {
                        skippedByStream[descriptor.streamIdentifier] =
                            descriptor.streamSequenceNumber
                    }
                } else {
                    guard skippedByStream.count < maximumStreamEntryCount else {
                        break
                    }
                    skippedByStream[descriptor.streamIdentifier] =
                        descriptor.streamSequenceNumber
                }
            }
            newCumulativeTSN = candidate
            candidate &+= 1
            visitedCount += 1
        }
        guard let newCumulativeTSN else { return .success(nil) }

        let advancesPreviousForward = lastForwardTSNCumulativeTSN.map {
            TSNTracker.isLessThan($0, newCumulativeTSN)
        } ?? true
        if advancesPreviousForward {
            forwardTSNRetransmitCount = 0
        } else if !force, forwardTSNDeadlineMillis != nil {
            guard forwardTSNRetransmitCount < maxRetransmit else {
                return .failure(.maxRetransmitsExceeded(tsn: newCumulativeTSN))
            }
            forwardTSNRetransmitCount += 1

            // RFC 3758 C5/F5: the retransmission timer covering FORWARD-TSN
            // also carries the congestion response for transmitted DATA that
            // was released at abandonment and would otherwise time out.
            let needsTimeoutResponse = abandoned.values.contains {
                $0.wasTransmitted && !$0.congestionResponseApplied
            }
            if needsTimeoutResponse {
                let (doubledRTO, overflow) = rtoMillis
                    .multipliedReportingOverflow(by: 2)
                rtoMillis = min(
                    overflow ? maxRTOMillis : doubledRTO,
                    maxRTOMillis
                )
                ssthresh = max(cwnd / 2, 4 * 1460)
                cwnd = 1460
                for tsn in abandoned.keys {
                    guard var descriptor = abandoned[tsn],
                          descriptor.wasTransmitted else {
                        continue
                    }
                    descriptor.congestionResponseApplied = true
                    abandoned[tsn] = descriptor
                }
            }
        }

        let skippedStreams = skippedByStream.keys.sorted().map { streamID in
            SCTPForwardTSNSkippedStream(
                streamIdentifier: streamID,
                streamSequenceNumber: skippedByStream[streamID] ?? 0
            )
        }
        if let highestSentTSN {
            if TSNTracker.isLessThan(highestSentTSN, newCumulativeTSN) {
                self.highestSentTSN = newCumulativeTSN
            }
        } else {
            highestSentTSN = newCumulativeTSN
        }
        forwardTSNDeadlineMillis = Self.saturatingAdd(nowMillis, rtoMillis)
        lastForwardTSNCumulativeTSN = newCumulativeTSN
        return .success(SCTPForwardTSNChunk(
            newCumulativeTSN: newCumulativeTSN,
            skippedStreams: skippedStreams
        ))
    }

    /// Release every retained payload owner and sender timer during terminal
    /// association teardown.
    package mutating func removeAll() {
        pending.removeAll(keepingCapacity: false)
        abandoned.removeAll(keepingCapacity: false)
        forwardTSNDeadlineMillis = nil
        lastForwardTSNCumulativeTSN = nil
        forwardTSNRetransmitCount = 0
        queuedTSNs.removeAll(keepingCapacity: false)
        queuedHeadIndex = 0
        highestSentTSN = nil
        retainedPayloadByteCount = 0
        bytesInFlight = 0
        zeroWindowProbeTSN = nil
        zeroWindowProbeDeadlineMillis = nil
        zeroWindowProbeIntervalMillis = rtoMillis
        t3DeadlineMillis = nil
        timeoutRecoveryProbeTSN = nil
        updatePeerReceiverWindow()
    }

    /// Validate and atomically apply one SACK acknowledgment.
    ///
    /// Gap-acknowledged payload owners remain retained until a cumulative SACK
    /// releases them because SCTP permits receiver reneging. No mutation is
    /// committed when the SACK acknowledges unsent data or contains malformed
    /// gap blocks.
    mutating func acknowledge(
        cumulativeTSN: UInt32,
        gapBlocks: [(start: UInt16, end: UInt16)],
        advertisedReceiverWindowCredit: UInt32 = 65_535,
        receivedMillis: UInt64
    ) -> SCTPSackOutcome {
        applyAcknowledgment(
            cumulativeTSN: cumulativeTSN,
            gapBlocks: gapBlocks,
            advertisedReceiverWindowCredit: advertisedReceiverWindowCredit,
            receivedMillis: receivedMillis,
            preserveExistingGapAcknowledgments: false
        )
    }

    /// Apply the cumulative acknowledgment carried by SHUTDOWN.
    ///
    /// RFC 9260 §3.3.8 states that SHUTDOWN does not carry Gap Ack Blocks. Their
    /// absence therefore cannot revoke a prior SACK gap acknowledgment. Payload
    /// owners above the cumulative point stay retained exactly as they were
    /// until a later cumulative acknowledgment releases them.
    package mutating func acknowledgeShutdown(
        cumulativeTSN: UInt32,
        receivedMillis: UInt64
    ) -> SCTPSackOutcome {
        applyAcknowledgment(
            cumulativeTSN: cumulativeTSN,
            gapBlocks: [],
            advertisedReceiverWindowCredit: peerAdvertisedReceiverWindow,
            receivedMillis: receivedMillis,
            preserveExistingGapAcknowledgments: true
        )
    }

    private mutating func applyAcknowledgment(
        cumulativeTSN: UInt32,
        gapBlocks: [(start: UInt16, end: UInt16)],
        advertisedReceiverWindowCredit: UInt32,
        receivedMillis: UInt64,
        preserveExistingGapAcknowledgments: Bool
    ) -> SCTPSackOutcome {
        let previousCumulative = cumulativeTSNAckPoint
        let t3AnchorBeforeSack = earliestTimerOutstandingTSN()

        if let previousCumulative {
            switch TSNTracker.relation(cumulativeTSN, to: previousCumulative) {
            case .before:
                return .stale(cumulativeTSN: cumulativeTSN)
            case .ambiguous:
                return .protocolViolation(.ambiguousSerialNumber(
                    reference: previousCumulative,
                    candidate: cumulativeTSN
                ))
            case .equal, .after:
                break
            }
        }

        if let highestSentTSN {
            switch TSNTracker.relation(cumulativeTSN, to: highestSentTSN) {
            case .after:
                return .protocolViolation(.cumulativeAcknowledgesUnsentTSN(
                    cumulativeTSN: cumulativeTSN,
                    highestSentTSN: highestSentTSN
                ))
            case .ambiguous:
                return .protocolViolation(.ambiguousSerialNumber(
                    reference: highestSentTSN,
                    candidate: cumulativeTSN
                ))
            case .before, .equal:
                break
            }
        } else if previousCumulative != cumulativeTSN {
            return .protocolViolation(.cumulativeAcknowledgesUnsentTSN(
                cumulativeTSN: cumulativeTSN,
                highestSentTSN: nil
            ))
        }

        var previousGapEnd: UInt16?
        for (index, block) in gapBlocks.enumerated() {
            guard block.start > 0,
                  block.start <= block.end,
                  previousGapEnd.map({ block.start > $0 }) ?? true else {
                return .protocolViolation(.invalidGapBlock(
                    index: index,
                    start: block.start,
                    end: block.end
                ))
            }
            previousGapEnd = block.end

            let highestAcknowledgedTSN = cumulativeTSN &+ UInt32(block.end)
            guard let highestSentTSN else {
                return .protocolViolation(.gapAcknowledgesUnsentTSN(
                    blockIndex: index,
                    highestAcknowledgedTSN: highestAcknowledgedTSN,
                    highestSentTSN: nil
                ))
            }
            switch TSNTracker.relation(highestAcknowledgedTSN, to: highestSentTSN) {
            case .after:
                return .protocolViolation(.gapAcknowledgesUnsentTSN(
                    blockIndex: index,
                    highestAcknowledgedTSN: highestAcknowledgedTSN,
                    highestSentTSN: highestSentTSN
                ))
            case .ambiguous:
                return .protocolViolation(.ambiguousSerialNumber(
                    reference: highestSentTSN,
                    candidate: highestAcknowledgedTSN
                ))
            case .before, .equal:
                break
            }
        }

        var cumulativeRemovals: [UInt32] = []
        var abandonedRemovals: [UInt32] = []
        var cumulativeRemovalSet = Set<UInt32>()
        var currentGapAcknowledgments = Set<UInt32>()
        var renegedTSNs: [UInt32] = []
        var newlyCumulativeBytes = 0
        var newlyGapBytes = 0
        var newlyGapAcknowledgedChunkCount = 0
        var renegedBytes = 0
        var removedFlightBytes = 0
        var newlyGapFlightBytes = 0
        var newlyMarkedBytes = 0
        var highestNewlyAcknowledgedTSN: UInt32?
        var rttSample: PendingChunk?
        var abandonedUpdates: [UInt32: SCTPAbandonedChunk] = [:]
        var applyAbandonedFastRetransmitResponse = false

        func laterTSN(_ lhs: UInt32?, _ rhs: UInt32) -> UInt32? {
            guard let lhs else { return rhs }
            switch TSNTracker.relation(rhs, to: lhs) {
            case .after:
                return rhs
            case .before, .equal:
                return lhs
            case .ambiguous:
                return nil
            }
        }

        func considerRTTSample(_ chunk: PendingChunk) {
            guard chunk.retransmitCount == 0,
                  chunk.rttMeasurementEligible else {
                return
            }
            if let existing = rttSample {
                if TSNTracker.relation(
                    chunk.dataChunk.tsn,
                    to: existing.dataChunk.tsn
                ) == .after {
                    rttSample = chunk
                }
            } else {
                rttSample = chunk
            }
        }

        for tsn in abandoned.keys {
            let relation = TSNTracker.relation(tsn, to: cumulativeTSN)
            switch relation {
            case .before, .equal:
                abandonedRemovals.append(tsn)
            case .after:
                break
            case .ambiguous:
                return .protocolViolation(.ambiguousSerialNumber(
                    reference: cumulativeTSN,
                    candidate: tsn
                ))
            }
        }

        for (tsn, chunk) in pending {
            let relation = TSNTracker.relation(tsn, to: cumulativeTSN)
            if relation == .ambiguous {
                return .protocolViolation(.ambiguousSerialNumber(
                    reference: cumulativeTSN,
                    candidate: tsn
                ))
            }

            if relation == .before || relation == .equal {
                cumulativeRemovals.append(tsn)
                cumulativeRemovalSet.insert(tsn)
                guard let nextBytes = Self.checkedAdd(
                    newlyCumulativeBytes,
                    chunk.dataChunk.userDataByteCount
                ) else {
                    return .protocolViolation(.accountingOverflow)
                }
                newlyCumulativeBytes = nextBytes
                if chunk.countsTowardBytesInFlight {
                    guard let nextFlight = Self.checkedAdd(
                        removedFlightBytes,
                        chunk.dataChunk.userDataByteCount
                    ) else {
                        return .protocolViolation(.accountingOverflow)
                    }
                    removedFlightBytes = nextFlight
                }
                guard let highest = laterTSN(highestNewlyAcknowledgedTSN, tsn) else {
                    return .protocolViolation(.ambiguousSerialNumber(
                        reference: highestNewlyAcknowledgedTSN ?? tsn,
                        candidate: tsn
                    ))
                }
                highestNewlyAcknowledgedTSN = highest
                considerRTTSample(chunk)
                continue
            }

            let offset = tsn &- cumulativeTSN
            let isGapAcknowledged = (
                preserveExistingGapAcknowledgments
                    && chunk.transmissionState == .gapAcknowledged
            ) || (
                offset <= UInt32(UInt16.max)
                    && Self.containsGapOffset(offset, in: gapBlocks)
            )
            if isGapAcknowledged {
                currentGapAcknowledgments.insert(tsn)
                if chunk.transmissionState != .gapAcknowledged {
                    newlyGapAcknowledgedChunkCount += 1
                    guard let nextBytes = Self.checkedAdd(
                        newlyGapBytes,
                        chunk.dataChunk.userDataByteCount
                    ) else {
                        return .protocolViolation(.accountingOverflow)
                    }
                    newlyGapBytes = nextBytes
                    if chunk.countsTowardBytesInFlight {
                        guard let nextFlight = Self.checkedAdd(
                            newlyGapFlightBytes,
                            chunk.dataChunk.userDataByteCount
                        ) else {
                            return .protocolViolation(.accountingOverflow)
                        }
                        newlyGapFlightBytes = nextFlight
                    }
                    guard let highest = laterTSN(highestNewlyAcknowledgedTSN, tsn) else {
                        return .protocolViolation(.ambiguousSerialNumber(
                            reference: highestNewlyAcknowledgedTSN ?? tsn,
                            candidate: tsn
                        ))
                    }
                    highestNewlyAcknowledgedTSN = highest
                    considerRTTSample(chunk)
                }
            } else if chunk.transmissionState == .gapAcknowledged {
                renegedTSNs.append(tsn)
                guard let nextBytes = Self.checkedAdd(
                    renegedBytes,
                    chunk.dataChunk.userDataByteCount
                ) else {
                    return .protocolViolation(.accountingOverflow)
                }
                renegedBytes = nextBytes
            }
        }

        let cumulativeAdvanced: Bool
        if let previousCumulative {
            cumulativeAdvanced = TSNTracker.relation(
                cumulativeTSN,
                to: previousCumulative
            ) == .after
        } else {
            cumulativeAdvanced = true
        }
        if cumulativeAdvanced {
            guard let highest = laterTSN(
                highestNewlyAcknowledgedTSN,
                cumulativeTSN
            ) else {
                return .protocolViolation(.ambiguousSerialNumber(
                    reference: highestNewlyAcknowledgedTSN ?? cumulativeTSN,
                    candidate: cumulativeTSN
                ))
            }
            highestNewlyAcknowledgedTSN = highest
        }

        // RFC 3758 F5 still requires normal loss accounting after payload
        // ownership has been released. Track miss indications using only the
        // scalar abandoned descriptor, and apply the fast-retransmit response
        // once when a transmitted skipped TSN reaches the normal threshold.
        if let highestNewlyAcknowledged = highestNewlyAcknowledgedTSN {
            let abandonedRemovalSet = Set(abandonedRemovals)
            for (tsn, descriptor) in abandoned {
                guard !abandonedRemovalSet.contains(tsn) else { continue }
                let offset = tsn &- cumulativeTSN
                let isGapAcknowledged = offset <= UInt32(UInt16.max)
                    && Self.containsGapOffset(offset, in: gapBlocks)
                var updated = descriptor
                if isGapAcknowledged {
                    updated.missIndications = 0
                } else {
                    switch TSNTracker.relation(tsn, to: highestNewlyAcknowledged) {
                    case .before:
                        if updated.missIndications < 3 {
                            updated.missIndications += 1
                        }
                        if updated.wasTransmitted,
                           updated.missIndications >= 3,
                           !updated.congestionResponseApplied {
                            updated.congestionResponseApplied = true
                            applyAbandonedFastRetransmitResponse = true
                        }
                    case .equal, .after:
                        break
                    case .ambiguous:
                        return .protocolViolation(.ambiguousSerialNumber(
                            reference: highestNewlyAcknowledged,
                            candidate: tsn
                        ))
                    }
                }
                if updated != descriptor {
                    abandonedUpdates[tsn] = updated
                }
            }
        }

        guard let retainedAfterCumulative = Self.checkedSubtract(
            retainedPayloadByteCount,
            newlyCumulativeBytes
        ), let flightAfterCumulative = Self.checkedSubtract(
            bytesInFlight,
            removedFlightBytes
        ), let flightAfterGap = Self.checkedSubtract(
            flightAfterCumulative,
            newlyGapFlightBytes
        ), let flightAfterReneging = Self.checkedAdd(
            flightAfterGap,
            renegedBytes
        ) else {
            return .protocolViolation(.accountingOverflow)
        }

        let renegedTSNSet = Set(renegedTSNs)
        let highestNewlyAcknowledged = highestNewlyAcknowledgedTSN
        var missIndicationTSNs: [UInt32] = []
        if let highestNewlyAcknowledged {
            for (tsn, chunk) in pending {
                guard !cumulativeRemovalSet.contains(tsn),
                      !currentGapAcknowledgments.contains(tsn),
                      !renegedTSNSet.contains(tsn),
                      chunk.transmissionState != .queued else {
                    continue
                }
                switch TSNTracker.relation(tsn, to: highestNewlyAcknowledged) {
                case .before:
                    missIndicationTSNs.append(tsn)
                case .equal, .after:
                    break
                case .ambiguous:
                    return .protocolViolation(.ambiguousSerialNumber(
                        reference: highestNewlyAcknowledged,
                        candidate: tsn
                    ))
                }
            }
        }

        for tsn in renegedTSNs {
            guard let chunk = pending[tsn],
                  chunk.missIndications < 3,
                  chunk.missIndications + 1 >= 3 else {
                continue
            }
            guard let next = Self.checkedAdd(
                newlyMarkedBytes,
                chunk.dataChunk.userDataByteCount
            ) else {
                return .protocolViolation(.accountingOverflow)
            }
            newlyMarkedBytes = next
        }
        for tsn in missIndicationTSNs {
            guard let chunk = pending[tsn],
                  chunk.countsTowardBytesInFlight,
                  chunk.missIndications < 3,
                  chunk.missIndications + 1 >= 3 else {
                continue
            }
            guard let next = Self.checkedAdd(
                newlyMarkedBytes,
                chunk.dataChunk.userDataByteCount
            ) else {
                return .protocolViolation(.accountingOverflow)
            }
            newlyMarkedBytes = next
        }
        guard let committedFlight = Self.checkedSubtract(
            flightAfterReneging,
            newlyMarkedBytes
        ) else {
            return .protocolViolation(.accountingOverflow)
        }

        for tsn in cumulativeRemovals {
            pending.removeValue(forKey: tsn)
        }
        for tsn in abandonedRemovals {
            abandoned.removeValue(forKey: tsn)
        }
        for (tsn, descriptor) in abandonedUpdates where abandoned[tsn] != nil {
            abandoned[tsn] = descriptor
        }
        if abandoned.isEmpty {
            forwardTSNDeadlineMillis = nil
            lastForwardTSNCumulativeTSN = nil
            forwardTSNRetransmitCount = 0
        }
        for tsn in currentGapAcknowledgments {
            guard var chunk = pending[tsn] else { continue }
            chunk.transmissionState = .gapAcknowledged
            chunk.missIndications = 0
            // A gap acknowledgment is already the acknowledgment event for
            // RTT purposes. Retaining the owner for reneging must not sample
            // this same transmission again at cumulative release.
            chunk.rttMeasurementEligible = false
            pending[tsn] = chunk
        }
        for tsn in renegedTSNs {
            guard var chunk = pending[tsn] else { continue }
            if chunk.missIndications < 3 {
                chunk.missIndications += 1
            }
            chunk.transmissionState = chunk.missIndications >= 3
                ? .markedForRetransmission
                : .inFlight
            pending[tsn] = chunk
        }
        for tsn in missIndicationTSNs {
            guard var chunk = pending[tsn] else { continue }
            if chunk.missIndications < 3 {
                chunk.missIndications += 1
            }
            if chunk.missIndications >= 3 {
                chunk.transmissionState = .markedForRetransmission
            }
            pending[tsn] = chunk
        }

        if let probeTSN = zeroWindowProbeTSN,
           cumulativeRemovalSet.contains(probeTSN)
                || currentGapAcknowledgments.contains(probeTSN) {
            clearZeroWindowProbe()
        }
        if let recoveryTSN = timeoutRecoveryProbeTSN,
           cumulativeRemovalSet.contains(recoveryTSN)
                || currentGapAcknowledgments.contains(recoveryTSN) {
            timeoutRecoveryProbeTSN = nil
        }

        retainedPayloadByteCount = retainedAfterCumulative
        bytesInFlight = committedFlight
        cumulativeTSNAckPoint = cumulativeTSN
        peerAdvertisedReceiverWindow = advertisedReceiverWindowCredit
        updatePeerReceiverWindow()

        if let rttSample {
            updateRTT(
                sentMillis: rttSample.lastSentMillis,
                receivedMillis: receivedMillis
            )
        }

        let t3AnchorWasAcknowledged = t3AnchorBeforeSack.map {
            cumulativeRemovalSet.contains($0)
                || currentGapAcknowledgments.contains($0)
        } ?? false
        if t3AnchorWasAcknowledged {
            if earliestTimerOutstandingTSN() == nil {
                stopT3()
            } else {
                restartT3(nowMillis: receivedMillis)
            }
        } else if t3DeadlineMillis == nil,
                  earliestTimerOutstandingTSN() != nil,
                  zeroWindowProbeTSN == nil {
            // RFC 9260 §6.3.2 R4: reneging can recreate outstanding DATA
            // while the path timer is stopped.
            startT3IfStopped(nowMillis: receivedMillis)
        }

        // RFC 3758 A2: a peer acknowledging a FORWARD-TSN releases abandoned
        // scalar metadata but must not grow cwnd. Credit only SACKed DATA that
        // still existed in the normal retransmission queue.
        if !cumulativeRemovals.isEmpty || newlyGapAcknowledgedChunkCount > 0 {
            if bytesInFlight < ssthresh {
                cwnd = min(cwnd + 1460, 65535)
            } else {
                cwnd = min(cwnd + 1460 * 1460 / cwnd, 65535)
            }
        }
        if applyAbandonedFastRetransmitResponse {
            ssthresh = max(cwnd / 2, 4 * 1460)
            cwnd = ssthresh
        }

        return .applied(SCTPSackUpdate(
            cumulativeAdvanced: cumulativeAdvanced,
            newlyCumulativelyAcknowledgedByteCount: newlyCumulativeBytes,
            newlyGapAcknowledgedByteCount: newlyGapBytes,
            renegedByteCount: renegedBytes,
            highestNewlyAcknowledgedTSN: highestNewlyAcknowledgedTSN,
            bytesInFlight: bytesInFlight,
            retainedPayloadByteCount: retainedPayloadByteCount,
            peerReceiverWindow: peerReceiverWindow
        ))
    }

    /// Select retransmissions using the single path-level T3-rtx timer.
    ///
    /// `lastSentMillis` is deliberately not used as a deadline. RFC 9260
    /// §6.3.2 defines one T3 timer per destination transport address; this
    /// implementation has one DTLS path, so `t3DeadlineMillis` is authoritative.
    mutating func pendingRetransmissions(
        nowMillis: UInt64,
        includeExpired: Bool = true,
        maximumChunkCount: Int = .max
    ) -> Result<[SCTPDataChunk], RetransmissionError> {
        guard maximumChunkCount > 0 else { return .success([]) }

        if includeExpired,
           let deadline = t3DeadlineMillis,
           nowMillis >= deadline {
            return retransmitAfterT3Expiry(nowMillis: nowMillis)
        }

        // RFC 9260 §7.2.3 permits only one physical SCTP packet in flight after
        // a T3 expiry until that packet is acknowledged.
        guard timeoutRecoveryProbeTSN == nil else { return .success([]) }

        var candidateTSNs: [UInt32] = []
        for (tsn, chunk) in pending {
            if chunk.transmissionState == .markedForRetransmission {
                candidateTSNs.append(tsn)
            }
        }
        var messagesToAbandon: [UInt32: SCTPAssignedMessage] = [:]
        for tsn in candidateTSNs {
            guard let chunk = pending[tsn],
                  Self.shouldAbandonBeforeRetransmission(
                    chunk,
                    nowMillis: nowMillis
                  ) else {
                continue
            }
            messagesToAbandon[chunk.assignedMessage.firstTSN] =
                chunk.assignedMessage
        }
        if !messagesToAbandon.isEmpty {
            for message in messagesToAbandon.values {
                switch abandonMessage(
                    message,
                    congestionResponseApplied: true
                ) {
                case .success:
                    break
                case .failure(let error):
                    return .failure(error)
                }
            }
            // RFC 3758 F5: abandoning DATA that fast retransmit would have sent
            // performs the same congestion reduction without crediting ACKed
            // bytes or growing cwnd.
            ssthresh = max(cwnd / 2, 4 * 1460)
            cwnd = ssthresh
            candidateTSNs.removeAll(keepingCapacity: true)
            for (tsn, chunk) in pending
            where chunk.transmissionState == .markedForRetransmission {
                candidateTSNs.append(tsn)
            }
        }
        guard !candidateTSNs.isEmpty else { return .success([]) }
        candidateTSNs.sort { TSNTracker.isLessThan($0, $1) }

        let earliestBeforeRetransmission = earliestTimerOutstandingTSN()
        let entersFastRecovery = candidateTSNs.first == earliestBeforeRetransmission
        let congestionWindow = entersFastRecovery
            ? max(cwnd / 2, 4 * 1460)
            : cwnd
        var selectedTSNs: [UInt32] = []
        selectedTSNs.reserveCapacity(min(candidateTSNs.count, maximumChunkCount))
        var budget = 0
        for tsn in candidateTSNs {
            guard selectedTSNs.count < maximumChunkCount,
                  let chunk = pending[tsn] else {
                break
            }
            let size = chunk.dataChunk.userDataByteCount
            if !selectedTSNs.isEmpty {
                let (next, overflow) = budget.addingReportingOverflow(size)
                if overflow || next > congestionWindow { break }
                budget = next
            } else {
                budget = size
            }
            guard chunk.retransmitCount < maxRetransmit else {
                return .failure(.maxRetransmitsExceeded(tsn: tsn))
            }
            selectedTSNs.append(tsn)
        }

        if entersFastRecovery {
            ssthresh = congestionWindow
            cwnd = congestionWindow
        }

        var burst: [SCTPDataChunk] = []
        burst.reserveCapacity(selectedTSNs.count)
        for tsn in selectedTSNs {
            invalidateRTTMeasurements(atOrAfter: tsn)
            guard var chunk = pending[tsn] else { continue }
            chunk.retransmitCount += 1
            chunk.lastSentMillis = nowMillis
            bytesInFlight += chunk.dataChunk.userDataByteCount
            chunk.transmissionState = .inFlight
            chunk.missIndications = 0
            pending[tsn] = chunk
            burst.append(chunk.dataChunk)
        }

        if let earliestBeforeRetransmission,
           selectedTSNs.contains(earliestBeforeRetransmission) {
            restartT3(nowMillis: nowMillis)
        } else if !burst.isEmpty {
            startT3IfStopped(nowMillis: nowMillis)
        }
        updatePeerReceiverWindow()
        return .success(burst)
    }

    /// Mark a chunk for fast retransmit (3 duplicate SACKs)
    /// - Parameter tsn: TSN to mark
    mutating func markForFastRetransmit(tsn: UInt32) {
        guard var chunk = pending[tsn],
              chunk.transmissionState == .inFlight else {
            return
        }
        bytesInFlight -= chunk.dataChunk.userDataByteCount
        chunk.transmissionState = .markedForRetransmission
        pending[tsn] = chunk
        updatePeerReceiverWindow()
    }

    /// Check if queue is empty
    var isEmpty: Bool {
        pending.isEmpty && abandoned.isEmpty
    }

    /// Number of pending chunks
    var count: Int {
        pending.count
    }

    /// Number of retained DATA chunks that have not reached the wire yet.
    package var queuedChunkCount: Int {
        pending.values.reduce(into: 0) { count, chunk in
            if chunk.transmissionState == .queued {
                count += 1
            }
        }
    }

    /// Check if we can send more data (congestion window check)
    var canSend: Bool {
        availableNewDataByteCount > 0
    }

    /// Current allowance for new DATA after congestion and peer receive-window
    /// constraints. Retransmissions are not blocked by peer window exhaustion.
    var availableNewDataByteCount: UInt64 {
        let congestionAllowance = cwnd > bytesInFlight
            ? UInt64(cwnd - bytesInFlight)
            : 0
        return min(congestionAllowance, peerReceiverWindow)
    }

    /// Whether the legacy one-packet API can admit and immediately return this
    /// exact DATA chunk without overtaking queued or retransmitted DATA.
    package func canImmediatelyTransmitNewDataChunk(byteCount: Int) -> Bool {
        guard byteCount >= 0,
              queuedChunkCount == 0,
              !pending.values.contains(where: {
                  $0.transmissionState == .markedForRetransmission
              }),
              bytesInFlight < cwnd else {
            return false
        }
        return peerReceiverWindow >= UInt64(byteCount)
    }

    /// Update the peer's receive-window credit learned during INIT/INIT-ACK.
    mutating func setPeerAdvertisedReceiverWindow(_ value: UInt32) {
        peerAdvertisedReceiverWindow = value
        updatePeerReceiverWindow()
    }

    /// Current RTO value in milliseconds
    var currentRTOMillis: UInt64 {
        rtoMillis
    }

    // MARK: - Private

    /// Apply RFC 3758 TR4 at existing sender opportunity boundaries. No
    /// per-message timer is needed: application sends, SACK processing, and the
    /// caller's timer poll all pass through this selector.
    private mutating func abandonExpiredMessages(
        nowMillis: UInt64
    ) -> Result<Bool, RetransmissionError> {
        var messages: [UInt32: SCTPAssignedMessage] = [:]
        for chunk in pending.values
        where chunk.assignedMessage.reliability.isExpired(at: nowMillis) {
            messages[chunk.assignedMessage.firstTSN] = chunk.assignedMessage
        }
        guard !messages.isEmpty else { return .success(false) }

        let previousTimerAnchor = earliestTimerOutstandingTSN()
        var fastResponseMessageTSNs = Set<UInt32>()
        for message in messages.values {
            let isMarked = pending.values.contains { chunk in
                chunk.assignedMessage.firstTSN == message.firstTSN
                    && chunk.transmissionState == .markedForRetransmission
            }
            if isMarked {
                fastResponseMessageTSNs.insert(message.firstTSN)
            }
        }
        if !fastResponseMessageTSNs.isEmpty {
            // The normal SACK path already established that these chunks would
            // enter fast retransmit. Apply the RFC 3758 F5 response even though
            // TR4 releases their payload instead of retransmitting it.
            ssthresh = max(cwnd / 2, 4 * 1460)
            cwnd = ssthresh
        }
        for message in messages.values {
            switch abandonMessage(
                message,
                congestionResponseApplied: fastResponseMessageTSNs.contains(
                    message.firstTSN
                )
            ) {
            case .success:
                break
            case .failure(let error):
                return .failure(error)
            }
        }
        if previousTimerAnchor != earliestTimerOutstandingTSN() {
            if earliestTimerOutstandingTSN() == nil {
                stopT3()
            } else {
                restartT3(nowMillis: nowMillis)
            }
        }
        return .success(true)
    }

    /// Treat every retained fragment in one user message as finally
    /// acknowledged locally while preserving the scalar metadata required for
    /// a later FORWARD-TSN. Payload owners are released exactly once here.
    private mutating func abandonMessage(
        _ message: SCTPAssignedMessage,
        congestionResponseApplied: Bool = false
    ) -> Result<Bool, RetransmissionError> {
        let selectedTSNs = pending.compactMap { tsn, chunk in
            chunk.assignedMessage.firstTSN == message.firstTSN ? tsn : nil
        }
        guard !selectedTSNs.isEmpty else { return .success(false) }

        var removedPayloadByteCount = 0
        var removedFlightByteCount = 0
        for tsn in selectedTSNs {
            guard let chunk = pending[tsn],
                  let nextPayload = Self.checkedAdd(
                    removedPayloadByteCount,
                    chunk.dataChunk.userDataByteCount
                  ) else {
                return .failure(.accountingInvariantViolation)
            }
            removedPayloadByteCount = nextPayload
            if chunk.countsTowardBytesInFlight {
                guard let nextFlight = Self.checkedAdd(
                    removedFlightByteCount,
                    chunk.dataChunk.userDataByteCount
                ) else {
                    return .failure(.accountingInvariantViolation)
                }
                removedFlightByteCount = nextFlight
            }
        }
        guard let retainedAfter = Self.checkedSubtract(
            retainedPayloadByteCount,
            removedPayloadByteCount
        ), let flightAfter = Self.checkedSubtract(
            bytesInFlight,
            removedFlightByteCount
        ) else {
            return .failure(.accountingInvariantViolation)
        }

        for tsn in selectedTSNs {
            guard let chunk = pending.removeValue(forKey: tsn) else { continue }
            abandoned[tsn] = SCTPAbandonedChunk(
                streamIdentifier: chunk.dataChunk.streamIdentifier,
                streamSequenceNumber: chunk.dataChunk.streamSequenceNumber,
                unordered: chunk.dataChunk.unordered,
                wasTransmitted: chunk.transmissionState != .queued,
                missIndications: chunk.missIndications,
                congestionResponseApplied: congestionResponseApplied
            )
        }
        if let probeTSN = zeroWindowProbeTSN,
           selectedTSNs.contains(probeTSN) {
            clearZeroWindowProbe()
        }
        if let recoveryTSN = timeoutRecoveryProbeTSN,
           selectedTSNs.contains(recoveryTSN) {
            timeoutRecoveryProbeTSN = nil
        }
        retainedPayloadByteCount = retainedAfter
        bytesInFlight = flightAfter
        updatePeerReceiverWindow()
        return .success(true)
    }

    private static func shouldAbandonBeforeRetransmission(
        _ chunk: PendingChunk,
        nowMillis: UInt64
    ) -> Bool {
        switch chunk.assignedMessage.reliability {
        case .reliable:
            return false
        case .maximumRetransmissions(let maximum):
            return UInt64(chunk.retransmitCount) >= UInt64(maximum)
        case .expiresAtMillis(let deadline):
            return nowMillis >= deadline
        }
    }

    private static func isLaterSSN(
        _ candidate: UInt16,
        than reference: UInt16
    ) -> Bool {
        let distance = candidate &- reference
        return distance != 0 && distance < (UInt16.max / 2) + 1
    }

    private mutating func transmitQueuedChunks(
        nowMillis: UInt64,
        maximumChunkCount: Int
    ) -> [SCTPDataChunk] {
        guard maximumChunkCount > 0 else { return [] }
        var chunks: [SCTPDataChunk] = []
        chunks.reserveCapacity(maximumChunkCount)

        while chunks.count < maximumChunkCount,
              let tsn = nextQueuedTSN(),
              let pendingChunk = pending[tsn] {
            let byteCount = pendingChunk.dataChunk.userDataByteCount
            guard bytesInFlight < cwnd,
                  peerReceiverWindow >= UInt64(byteCount) else {
                break
            }
            guard let emitted = emitQueuedChunk(tsn: tsn, nowMillis: nowMillis) else {
                continue
            }
            chunks.append(emitted)
        }
        return chunks
    }

    private mutating func emitQueuedChunk(
        tsn: UInt32,
        nowMillis: UInt64,
        startsT3: Bool = true
    ) -> SCTPDataChunk? {
        guard var chunk = pending[tsn],
              chunk.transmissionState == .queued else {
            return nil
        }
        chunk.firstSentMillis = nowMillis
        chunk.lastSentMillis = nowMillis
        chunk.transmissionState = .inFlight
        chunk.rttMeasurementEligible = true
        pending[tsn] = chunk
        bytesInFlight += chunk.dataChunk.userDataByteCount

        if let highestSentTSN {
            if TSNTracker.isLessThan(highestSentTSN, tsn) {
                self.highestSentTSN = tsn
            }
        } else {
            highestSentTSN = tsn
        }

        if queuedHeadIndex < queuedTSNs.count,
           queuedTSNs[queuedHeadIndex] == tsn {
            queuedHeadIndex += 1
            compactQueuedTSNsIfNeeded()
        }
        if startsT3 {
            startT3IfStopped(nowMillis: nowMillis)
        }
        updatePeerReceiverWindow()
        return chunk.dataChunk
    }

    private mutating func nextQueuedTSN() -> UInt32? {
        while queuedHeadIndex < queuedTSNs.count {
            let tsn = queuedTSNs[queuedHeadIndex]
            if pending[tsn]?.transmissionState == .queued {
                return tsn
            }
            queuedHeadIndex += 1
        }
        compactQueuedTSNsIfNeeded()
        return nil
    }

    private mutating func compactQueuedTSNsIfNeeded() {
        guard queuedHeadIndex > 0,
              queuedHeadIndex == queuedTSNs.count
                || (queuedHeadIndex >= 1_024
                    && queuedHeadIndex >= queuedTSNs.count / 2) else {
            return
        }
        queuedTSNs.removeFirst(queuedHeadIndex)
        queuedHeadIndex = 0
    }

    private mutating func scheduleZeroWindowProbeIfNeeded(nowMillis: UInt64) {
        if let probeTSN = zeroWindowProbeTSN {
            guard let probe = pending[probeTSN] else {
                clearZeroWindowProbe()
                return
            }
            if UInt64(peerAdvertisedReceiverWindow)
                >= UInt64(probe.dataChunk.userDataByteCount) {
                clearZeroWindowProbe()
                if probe.transmissionState == .inFlight {
                    startT3IfStopped(nowMillis: nowMillis)
                }
            }
            return
        }

        guard let tsn = nextQueuedTSN(),
              let chunk = pending[tsn] else {
            zeroWindowProbeDeadlineMillis = nil
            zeroWindowProbeIntervalMillis = rtoMillis
            return
        }
        guard peerReceiverWindow < UInt64(chunk.dataChunk.userDataByteCount) else {
            zeroWindowProbeDeadlineMillis = nil
            zeroWindowProbeIntervalMillis = rtoMillis
            return
        }
        if zeroWindowProbeDeadlineMillis == nil {
            zeroWindowProbeIntervalMillis = rtoMillis
            zeroWindowProbeDeadlineMillis = Self.saturatingAdd(
                nowMillis,
                rtoMillis
            )
        }
    }

    private mutating func zeroWindowProbeIfDue(
        nowMillis: UInt64
    ) -> SCTPDataChunk? {
        guard let deadline = zeroWindowProbeDeadlineMillis,
              nowMillis >= deadline else {
            return nil
        }

        if let probeTSN = zeroWindowProbeTSN {
            guard var probe = pending[probeTSN] else {
                clearZeroWindowProbe()
                return nil
            }
            guard UInt64(peerAdvertisedReceiverWindow)
                    < UInt64(probe.dataChunk.userDataByteCount) else {
                clearZeroWindowProbe()
                return nil
            }
            probe.lastSentMillis = nowMillis
            probe.rttMeasurementEligible = false
            pending[probeTSN] = probe
            scheduleNextZeroWindowProbe(after: nowMillis)
            return probe.dataChunk
        }

        guard bytesInFlight == 0,
              bytesInFlight < cwnd,
              let tsn = nextQueuedTSN(),
              let chunk = pending[tsn],
              peerReceiverWindow < UInt64(chunk.dataChunk.userDataByteCount),
              let emitted = emitQueuedChunk(
                  tsn: tsn,
                  nowMillis: nowMillis,
                  startsT3: false
              ) else {
            return nil
        }
        zeroWindowProbeTSN = tsn
        scheduleNextZeroWindowProbe(after: nowMillis)
        return emitted
    }

    private mutating func scheduleNextZeroWindowProbe(after nowMillis: UInt64) {
        let (doubled, overflow) = zeroWindowProbeIntervalMillis
            .multipliedReportingOverflow(by: 2)
        zeroWindowProbeIntervalMillis = min(
            overflow ? maxRTOMillis : doubled,
            maxRTOMillis
        )
        zeroWindowProbeDeadlineMillis = Self.saturatingAdd(
            nowMillis,
            zeroWindowProbeIntervalMillis
        )
    }

    private mutating func clearZeroWindowProbe() {
        zeroWindowProbeTSN = nil
        zeroWindowProbeDeadlineMillis = nil
        zeroWindowProbeIntervalMillis = rtoMillis
    }

    private mutating func retransmitAfterT3Expiry(
        nowMillis: UInt64
    ) -> Result<[SCTPDataChunk], RetransmissionError> {
        var outstandingTSNs: [UInt32] = []
        var flightByteCount = 0
        for (tsn, chunk) in pending {
            guard tsn != zeroWindowProbeTSN else { continue }
            switch chunk.transmissionState {
            case .inFlight:
                guard let nextFlight = Self.checkedAdd(
                    flightByteCount,
                    chunk.dataChunk.userDataByteCount
                ) else {
                    return .failure(.accountingInvariantViolation)
                }
                flightByteCount = nextFlight
                outstandingTSNs.append(tsn)
            case .markedForRetransmission:
                outstandingTSNs.append(tsn)
            case .queued, .gapAcknowledged:
                continue
            }
        }

        guard !outstandingTSNs.isEmpty else {
            stopT3()
            timeoutRecoveryProbeTSN = nil
            return .success([])
        }
        guard bytesInFlight >= flightByteCount else {
            return .failure(.accountingInvariantViolation)
        }

        // RFC 9260 §6.3.3 E1-E4 and §7.2.3: stop the expired timer,
        // back off once, mark every outstanding DATA chunk, and put only the
        // earliest one-packet recovery probe back on the wire.
        stopT3()
        let (doubledRTO, rtoOverflow) = rtoMillis.multipliedReportingOverflow(by: 2)
        rtoMillis = min(rtoOverflow ? maxRTOMillis : doubledRTO, maxRTOMillis)
        ssthresh = max(cwnd / 2, 4 * 1460)
        cwnd = 1460

        for tsn in outstandingTSNs {
            guard var chunk = pending[tsn] else { continue }
            if chunk.transmissionState == .inFlight {
                chunk.transmissionState = .markedForRetransmission
                pending[tsn] = chunk
            }
        }
        bytesInFlight -= flightByteCount

        var messagesToAbandon: [UInt32: SCTPAssignedMessage] = [:]
        for tsn in outstandingTSNs {
            guard let chunk = pending[tsn],
                  Self.shouldAbandonBeforeRetransmission(
                    chunk,
                    nowMillis: nowMillis
                  ) else {
                continue
            }
            messagesToAbandon[chunk.assignedMessage.firstTSN] =
                chunk.assignedMessage
        }
        for message in messagesToAbandon.values {
            switch abandonMessage(
                message,
                congestionResponseApplied: true
            ) {
            case .success:
                break
            case .failure(let error):
                return .failure(error)
            }
        }

        outstandingTSNs.removeAll(keepingCapacity: true)
        for (tsn, chunk) in pending
        where chunk.transmissionState == .markedForRetransmission {
            outstandingTSNs.append(tsn)
        }
        guard !outstandingTSNs.isEmpty else {
            timeoutRecoveryProbeTSN = nil
            updatePeerReceiverWindow()
            return .success([])
        }
        outstandingTSNs.sort { TSNTracker.isLessThan($0, $1) }
        guard let retransmittedTSN = outstandingTSNs.first,
              var retransmitted = pending[retransmittedTSN] else {
            return .failure(.accountingInvariantViolation)
        }
        guard retransmitted.retransmitCount < maxRetransmit else {
            return .failure(.maxRetransmitsExceeded(tsn: retransmittedTSN))
        }

        invalidateRTTMeasurements(atOrAfter: retransmittedTSN)
        retransmitted = pending[retransmittedTSN] ?? retransmitted
        retransmitted.retransmitCount += 1
        retransmitted.lastSentMillis = nowMillis
        retransmitted.transmissionState = .inFlight
        retransmitted.missIndications = 0
        pending[retransmittedTSN] = retransmitted
        bytesInFlight += retransmitted.dataChunk.userDataByteCount
        timeoutRecoveryProbeTSN = retransmittedTSN
        restartT3(nowMillis: nowMillis)
        updatePeerReceiverWindow()
        return .success([retransmitted.dataChunk])
    }

    private func earliestTimerOutstandingTSN() -> UInt32? {
        var earliest: UInt32?
        for (tsn, chunk) in pending {
            guard tsn != zeroWindowProbeTSN else { continue }
            switch chunk.transmissionState {
            case .inFlight, .markedForRetransmission:
                if let current = earliest {
                    if TSNTracker.isLessThan(tsn, current) {
                        earliest = tsn
                    }
                } else {
                    earliest = tsn
                }
            case .queued, .gapAcknowledged:
                continue
            }
        }
        return earliest
    }

    private mutating func startT3IfStopped(nowMillis: UInt64) {
        guard t3DeadlineMillis == nil,
              earliestTimerOutstandingTSN() != nil else {
            return
        }
        t3DeadlineMillis = Self.saturatingAdd(nowMillis, rtoMillis)
    }

    private mutating func restartT3(nowMillis: UInt64) {
        t3DeadlineMillis = Self.saturatingAdd(nowMillis, rtoMillis)
    }

    private mutating func stopT3() {
        t3DeadlineMillis = nil
    }

    private mutating func invalidateRTTMeasurements(atOrAfter tsn: UInt32) {
        for candidateTSN in pending.keys {
            guard var chunk = pending[candidateTSN],
                  chunk.transmissionState != .queued else {
                continue
            }
            switch TSNTracker.relation(candidateTSN, to: tsn) {
            case .equal, .after:
                chunk.rttMeasurementEligible = false
                pending[candidateTSN] = chunk
            case .before:
                continue
            case .ambiguous:
                // The retained-chunk limit is far below the serial half-range;
                // an ambiguous relation cannot arise for one valid send window.
                continue
            }
        }
    }

    private static func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
        let (value, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? UInt64.max : value
    }

    private static func containsGapOffset(
        _ offset: UInt32,
        in gapBlocks: [(start: UInt16, end: UInt16)]
    ) -> Bool {
        var low = 0
        var high = gapBlocks.count
        while low < high {
            let middle = (low + high) / 2
            let block = gapBlocks[middle]
            if offset < UInt32(block.start) {
                high = middle
            } else if offset > UInt32(block.end) {
                low = middle + 1
            } else {
                return true
            }
        }
        return false
    }

    private static func checkedAdd(_ lhs: Int, _ rhs: Int) -> Int? {
        let (value, overflow) = lhs.addingReportingOverflow(rhs)
        guard !overflow, value >= 0 else { return nil }
        return value
    }

    private static func checkedSubtract(_ lhs: Int, _ rhs: Int) -> Int? {
        let (value, overflow) = lhs.subtractingReportingOverflow(rhs)
        guard !overflow, value >= 0 else { return nil }
        return value
    }

    private mutating func updatePeerReceiverWindow() {
        let advertised = UInt64(peerAdvertisedReceiverWindow)
        let outstanding = UInt64(bytesInFlight)
        peerReceiverWindow = advertised >= outstanding
            ? advertised - outstanding
            : 0
    }

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
