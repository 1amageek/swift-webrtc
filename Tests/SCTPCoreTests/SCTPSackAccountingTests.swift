import Foundation
import Testing
@testable import WebRTC
@Suite("SCTP SACK Accounting Tests")
struct SCTPSackAccountingTests {
    private let payloadByteCount = 100

    private func makeChunk(tsn: UInt32, size: Int? = nil) -> SCTPDataChunk {
        SCTPDataChunk(
            tsn: tsn,
            streamIdentifier: 0,
            streamSequenceNumber: UInt16(truncatingIfNeeded: tsn),
            payloadProtocolIdentifier: 53,
            userData: Data(repeating: 0x5A, count: size ?? payloadByteCount)
        )
    }

    private func retransmissionTSNs(
        _ queue: inout RetransmissionQueue,
        now: ContinuousClock.Instant
    ) -> [UInt32] {
        switch queue.pendingRetransmissions(now: now) {
        case .success(let chunks):
            return chunks.map(\.tsn)
        case .failure(let error):
            Issue.record("Unexpected retransmission failure: \(error)")
            return []
        }
    }

    @Test("Equal cumulative SACK applies a new gap acknowledgment")
    func equalCumulativeAppliesNewGap() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now
        try queue.enqueue(makeChunk(tsn: 10), sentTime: sentTime)
        try queue.enqueue(makeChunk(tsn: 11), sentTime: sentTime)

        let outcome = queue.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 2, end: 2)],
            advertisedReceiverWindowCredit: 1_000,
            receivedTime: sentTime + .milliseconds(10)
        )

        guard case .applied(let update) = outcome else {
            Issue.record("Expected an applied SACK, got \(outcome)")
            return
        }
        #expect(!update.cumulativeAdvanced)
        #expect(update.newlyGapAcknowledgedByteCount == payloadByteCount)
        #expect(update.highestNewlyAcknowledgedTSN == 11)
        #expect(queue.bytesInFlight == payloadByteCount)
        #expect(queue.retainedPayloadByteCount == payloadByteCount * 2)
        #expect(queue.peerReceiverWindow == 900)
    }

    @Test("Stale SACK discards every field without mutation")
    func staleSackIsAtomic() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now
        try queue.enqueue(makeChunk(tsn: 10), sentTime: sentTime)
        try queue.enqueue(makeChunk(tsn: 11), sentTime: sentTime)
        _ = queue.acknowledge(
            cumulativeTSN: 10,
            gapBlocks: [],
            advertisedReceiverWindowCredit: 1_000,
            receivedTime: sentTime + .milliseconds(10)
        )

        let before = QueueSnapshot(queue)
        let outcome = queue.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 2, end: 2)],
            advertisedReceiverWindowCredit: 60_000,
            receivedTime: sentTime + .milliseconds(20)
        )

        #expect(outcome == .stale(cumulativeTSN: 9))
        #expect(QueueSnapshot(queue) == before)
    }

    @Test("Forged cumulative acknowledgment fails atomically")
    func forgedCumulativeFailsAtomically() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now
        try queue.enqueue(makeChunk(tsn: 10), sentTime: sentTime)
        try queue.enqueue(makeChunk(tsn: 11), sentTime: sentTime)
        let before = QueueSnapshot(queue)

        let outcome = queue.acknowledge(
            cumulativeTSN: 12,
            gapBlocks: [],
            advertisedReceiverWindowCredit: 0,
            receivedTime: sentTime + .milliseconds(10)
        )

        #expect(outcome == .protocolViolation(
            .cumulativeAcknowledgesUnsentTSN(
                cumulativeTSN: 12,
                highestSentTSN: 11
            )
        ))
        #expect(QueueSnapshot(queue) == before)
    }

    @Test("Forged gap acknowledgment fails atomically")
    func forgedGapFailsAtomically() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now
        try queue.enqueue(makeChunk(tsn: 10), sentTime: sentTime)
        try queue.enqueue(makeChunk(tsn: 11), sentTime: sentTime)
        let before = QueueSnapshot(queue)

        let outcome = queue.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 3, end: 3)],
            advertisedReceiverWindowCredit: 0,
            receivedTime: sentTime + .milliseconds(10)
        )

        #expect(outcome == .protocolViolation(
            .gapAcknowledgesUnsentTSN(
                blockIndex: 0,
                highestAcknowledgedTSN: 12,
                highestSentTSN: 11
            )
        ))
        #expect(QueueSnapshot(queue) == before)
    }

    @Test("Exact half-range TSN is an ambiguous typed violation")
    func halfRangeIsAmbiguous() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now
        try queue.enqueue(makeChunk(tsn: 0), sentTime: sentTime)
        let before = QueueSnapshot(queue)

        let outcome = queue.acknowledge(
            cumulativeTSN: 0x7FFF_FFFF,
            gapBlocks: [],
            receivedTime: sentTime + .milliseconds(10)
        )

        #expect(outcome == .protocolViolation(
            .ambiguousSerialNumber(
                reference: UInt32.max,
                candidate: 0x7FFF_FFFF
            )
        ))
        #expect(QueueSnapshot(queue) == before)
    }

    @Test("Cumulative acknowledgment advances across UInt32 wrap")
    func cumulativeAcknowledgmentWraps() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now
        try queue.enqueue(makeChunk(tsn: UInt32.max), sentTime: sentTime)
        try queue.enqueue(makeChunk(tsn: 0), sentTime: sentTime)

        let first = queue.acknowledge(
            cumulativeTSN: UInt32.max,
            gapBlocks: [],
            receivedTime: sentTime + .milliseconds(10)
        )
        guard case .applied(let firstUpdate) = first else {
            Issue.record("Expected the pre-wrap cumulative SACK to apply")
            return
        }
        #expect(firstUpdate.cumulativeAdvanced)
        #expect(queue.retainedPayloadByteCount == payloadByteCount)

        let second = queue.acknowledge(
            cumulativeTSN: 0,
            gapBlocks: [],
            receivedTime: sentTime + .milliseconds(20)
        )
        guard case .applied(let secondUpdate) = second else {
            Issue.record("Expected the post-wrap cumulative SACK to apply")
            return
        }
        #expect(secondUpdate.cumulativeAdvanced)
        #expect(queue.bytesInFlight == 0)
        #expect(queue.retainedPayloadByteCount == 0)
    }

    @Test("Gap acknowledgment suppresses RTO while retaining its payload owner")
    func gapAcknowledgmentSuppressesRTO() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now
        try queue.enqueue(makeChunk(tsn: 10), sentTime: sentTime)
        try queue.enqueue(makeChunk(tsn: 11), sentTime: sentTime)
        let initialRTO = queue.currentRTO

        _ = queue.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 2, end: 2)],
            receivedTime: sentTime + .milliseconds(10)
        )
        #expect(queue.bytesInFlight == payloadByteCount)
        #expect(queue.retainedPayloadByteCount == payloadByteCount * 2)

        let retransmissions = retransmissionTSNs(
            &queue,
            now: sentTime + initialRTO + .milliseconds(1)
        )
        #expect(retransmissions == [10])

        _ = queue.acknowledge(
            cumulativeTSN: 11,
            gapBlocks: [],
            receivedTime: sentTime + .milliseconds(20)
        )
        #expect(queue.retainedPayloadByteCount == 0)
    }

    @Test("Reneging restores flight accounting and retransmission eligibility")
    func renegingRestoresFlightAccounting() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now
        for tsn: UInt32 in 10...12 {
            try queue.enqueue(makeChunk(tsn: tsn), sentTime: sentTime)
        }
        let initialRTO = queue.currentRTO

        _ = queue.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 2, end: 2)],
            receivedTime: sentTime + .milliseconds(10)
        )
        let outcome = queue.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 3, end: 3)],
            receivedTime: sentTime + .milliseconds(20)
        )

        guard case .applied(let update) = outcome else {
            Issue.record("Expected reneging SACK to apply")
            return
        }
        #expect(update.renegedByteCount == payloadByteCount)
        #expect(queue.bytesInFlight == payloadByteCount * 2)
        #expect(queue.retainedPayloadByteCount == payloadByteCount * 3)

        let retransmissions = retransmissionTSNs(
            &queue,
            now: sentTime + initialRTO + .milliseconds(1)
        )
        #expect(retransmissions == [10])
    }

    @Test("A standalone reneging SACK contributes one miss indication")
    func standaloneRenegingContributesOneMiss() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now
        for tsn: UInt32 in 10...13 {
            try queue.enqueue(makeChunk(tsn: tsn), sentTime: sentTime)
        }

        _ = queue.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 2, end: 2)],
            receivedTime: sentTime + .milliseconds(10)
        )
        _ = queue.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [],
            receivedTime: sentTime + .milliseconds(20)
        )
        _ = queue.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 3, end: 3)],
            receivedTime: sentTime + .milliseconds(30)
        )
        _ = queue.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 3, end: 4)],
            receivedTime: sentTime + .milliseconds(40)
        )

        let retransmissions = retransmissionTSNs(
            &queue,
            now: sentTime + .milliseconds(100)
        )
        #expect(retransmissions.contains(11))
    }

    @Test("Repeated identical SACK does not manufacture miss indications")
    func repeatedSackDoesNotIncreaseMisses() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now
        try queue.enqueue(makeChunk(tsn: 10), sentTime: sentTime)
        try queue.enqueue(makeChunk(tsn: 11), sentTime: sentTime)

        for _ in 0..<3 {
            _ = queue.acknowledge(
                cumulativeTSN: 9,
                gapBlocks: [(start: 2, end: 2)],
                receivedTime: sentTime + .milliseconds(10)
            )
        }

        let retransmissions = retransmissionTSNs(
            &queue,
            now: sentTime + .milliseconds(100)
        )
        #expect(retransmissions.isEmpty)
    }

    @Test("Retained byte limit survives gap acknowledgments until cumulative release")
    func retainedLimitSurvivesGapAcknowledgment() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now
        try queue.enqueue(
            makeChunk(tsn: 1, size: 1 * 1_024 * 1_024),
            sentTime: sentTime
        )
        _ = queue.acknowledge(
            cumulativeTSN: 0,
            gapBlocks: [(start: 1, end: 1)],
            receivedTime: sentTime + .milliseconds(10)
        )

        #expect(queue.bytesInFlight == 0)
        #expect(queue.retainedPayloadByteCount == 1 * 1_024 * 1_024)
        do {
            try queue.enqueue(makeChunk(tsn: 2, size: 1), sentTime: sentTime)
            Issue.record("Expected retained-owner backpressure")
        } catch let error as SCTPError {
            guard case .sendQueueFull = error else {
                Issue.record("Unexpected backpressure error: \(error)")
                return
            }
        }

        _ = queue.acknowledge(
            cumulativeTSN: 1,
            gapBlocks: [],
            receivedTime: sentTime + .milliseconds(20)
        )
        try queue.enqueue(makeChunk(tsn: 2, size: 1), sentTime: sentTime)
        #expect(queue.retainedPayloadByteCount == 1)
    }

    @Test("Advertised receive window is effective and stale updates are ignored")
    func advertisedReceiveWindowAccounting() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now
        try queue.enqueue(makeChunk(tsn: 1, size: 400), sentTime: sentTime)
        try queue.enqueue(makeChunk(tsn: 2, size: 400), sentTime: sentTime)

        _ = queue.acknowledge(
            cumulativeTSN: 1,
            gapBlocks: [],
            advertisedReceiverWindowCredit: 1_000,
            receivedTime: sentTime + .milliseconds(10)
        )
        #expect(queue.peerReceiverWindow == 600)

        let stale = queue.acknowledge(
            cumulativeTSN: 0,
            gapBlocks: [],
            advertisedReceiverWindowCredit: 60_000,
            receivedTime: sentTime + .milliseconds(20)
        )
        #expect(stale == .stale(cumulativeTSN: 0))
        #expect(queue.peerReceiverWindow == 600)

        _ = queue.acknowledge(
            cumulativeTSN: 1,
            gapBlocks: [],
            advertisedReceiverWindowCredit: 0,
            receivedTime: sentTime + .milliseconds(30)
        )
        #expect(queue.peerReceiverWindow == 0)
        #expect(!queue.canSend)
    }

    @Test("Malformed and overlapping gap blocks fail atomically")
    func invalidGapBlocksFailAtomically() throws {
        let invalidBlocks: [[(start: UInt16, end: UInt16)]] = [
            [(start: 3, end: 2)],
            [(start: 2, end: 3), (start: 3, end: 4)],
            [(start: 0, end: 1)],
        ]

        for blocks in invalidBlocks {
            var queue = RetransmissionQueue()
            let sentTime = ContinuousClock.now
            for tsn: UInt32 in 10...14 {
                try queue.enqueue(makeChunk(tsn: tsn), sentTime: sentTime)
            }
            let before = QueueSnapshot(queue)

            let outcome = queue.acknowledge(
                cumulativeTSN: 9,
                gapBlocks: blocks,
                advertisedReceiverWindowCredit: 0,
                receivedTime: sentTime + .milliseconds(10)
            )

            guard case .protocolViolation(.invalidGapBlock) = outcome else {
                Issue.record("Expected invalid gap-block violation, got \(outcome)")
                continue
            }
            #expect(QueueSnapshot(queue) == before)
        }
    }

    @Test("Retained chunk metadata has a typed hard limit")
    func retainedChunkLimitIsBounded() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now
        for tsn: UInt32 in 0..<4_096 {
            try queue.enqueue(makeChunk(tsn: tsn, size: 0), sentTime: sentTime)
        }

        do {
            try queue.enqueue(makeChunk(tsn: 4_096, size: 0), sentTime: sentTime)
            Issue.record("Expected retained chunk metadata backpressure")
        } catch let error as SCTPError {
            guard case .sendChunkLimitReached(
                let retainedChunkCount,
                let limit
            ) = error else {
                Issue.record("Unexpected metadata-limit error: \(error)")
                return
            }
            #expect(retainedChunkCount == 4_096)
            #expect(limit == 4_096)
        }
    }
}

private struct QueueSnapshot: Equatable {
    let count: Int
    let highestSentTSN: UInt32?
    let bytesInFlight: Int
    let retainedPayloadByteCount: Int
    let peerReceiverWindow: UInt64
    let cwnd: Int
    let rto: Duration

    init(_ queue: RetransmissionQueue) {
        self.count = queue.count
        self.highestSentTSN = queue.highestSentTSN
        self.bytesInFlight = queue.bytesInFlight
        self.retainedPayloadByteCount = queue.retainedPayloadByteCount
        self.peerReceiverWindow = queue.peerReceiverWindow
        self.cwnd = queue.cwnd
        self.rto = queue.currentRTO
    }
}
