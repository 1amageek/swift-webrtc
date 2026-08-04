import Testing
@testable import WebRTC
@Suite("SCTP T3-rtx Timer Tests")
struct SCTPT3TimerTests {
    private func chunk(tsn: UInt32, byteCount: Int = 100) -> SCTPDataChunk {
        SCTPDataChunk(
            tsn: tsn,
            streamIdentifier: 0,
            streamSequenceNumber: UInt16(truncatingIfNeeded: tsn),
            payloadProtocolIdentifier: 53,
            userData: [UInt8](repeating: UInt8(truncatingIfNeeded: tsn), count: byteCount)
        )
    }

    private func retransmissions(
        _ state: inout RetransmissionState,
        at nowMillis: UInt64,
        includeExpired: Bool = true
    ) throws -> [UInt32] {
        try state.pendingRetransmissions(
            nowMillis: nowMillis,
            includeExpired: includeExpired
        ).get().map(\.tsn)
    }

    @Test("Later DATA does not move the running T3 deadline")
    func laterSendDoesNotRestartT3() throws {
        var state = RetransmissionState(initialTSN: 10)
        try state.enqueue(chunk(tsn: 10), sentMillis: 0)
        try state.enqueue(chunk(tsn: 11), sentMillis: 1_000)

        #expect(try retransmissions(&state, at: 2_999).isEmpty)
        #expect(try retransmissions(&state, at: 3_000) == [10])
    }

    @Test("Acknowledging the earliest outstanding DATA restarts T3")
    func earliestAcknowledgmentRestartsT3() throws {
        var state = RetransmissionState(initialTSN: 10)
        try state.enqueue(chunk(tsn: 10), sentMillis: 0)
        try state.enqueue(chunk(tsn: 11), sentMillis: 500)

        _ = state.acknowledge(
            cumulativeTSN: 10,
            gapBlocks: [],
            receivedMillis: 1_000
        )

        #expect(state.currentRTOMillis == 3_000)
        #expect(try retransmissions(&state, at: 3_500).isEmpty)
        #expect(try retransmissions(&state, at: 4_000) == [11])
    }

    @Test("Gap ACK of later DATA preserves the frozen T3 deadline")
    func laterGapAcknowledgmentDoesNotRestartT3() throws {
        var state = RetransmissionState(initialTSN: 10)
        try state.enqueue(chunk(tsn: 10), sentMillis: 0)
        try state.enqueue(chunk(tsn: 11), sentMillis: 0)

        _ = state.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 2, end: 2)],
            receivedMillis: 100
        )

        #expect(state.currentRTOMillis == 1_000)
        #expect(try retransmissions(&state, at: 1_000).isEmpty)
        #expect(try retransmissions(&state, at: 2_999).isEmpty)
        #expect(try retransmissions(&state, at: 3_000) == [10])
    }

    @Test("T3 stops with no outstanding DATA and starts on the next send")
    func t3StopsAndStartsAgain() throws {
        var state = RetransmissionState(initialTSN: 10)
        try state.enqueue(chunk(tsn: 10), sentMillis: 0)
        _ = state.acknowledge(
            cumulativeTSN: 10,
            gapBlocks: [],
            receivedMillis: 100
        )

        #expect(try retransmissions(&state, at: 10_000).isEmpty)
        try state.enqueue(chunk(tsn: 11), sentMillis: 10_000)
        #expect(try retransmissions(&state, at: 10_999).isEmpty)
        #expect(try retransmissions(&state, at: 11_000) == [11])
    }

    @Test("T3 expiry emits one packet and ACK releases the next marked DATA")
    func timeoutRecoveryIsOnePacketUntilAcknowledged() throws {
        var state = RetransmissionState(initialTSN: 10)
        try state.enqueue(chunk(tsn: 10), sentMillis: 0)
        try state.enqueue(chunk(tsn: 11), sentMillis: 0)

        #expect(try retransmissions(&state, at: 3_000) == [10])
        #expect(state.bytesInFlight == 100)
        #expect(try retransmissions(
            &state,
            at: 3_001,
            includeExpired: false
        ).isEmpty)

        _ = state.acknowledge(
            cumulativeTSN: 10,
            gapBlocks: [],
            receivedMillis: 3_100
        )
        #expect(try retransmissions(
            &state,
            at: 3_100,
            includeExpired: false
        ) == [11])
    }

    @Test("Each T3 expiration backs off once and freezes the next deadline")
    func timeoutBackoffFreezesDeadline() throws {
        var state = RetransmissionState(initialTSN: 10)
        try state.enqueue(chunk(tsn: 10), sentMillis: 0)

        #expect(try retransmissions(&state, at: 3_000) == [10])
        #expect(state.currentRTOMillis == 6_000)
        #expect(try retransmissions(&state, at: 8_999).isEmpty)
        #expect(try retransmissions(&state, at: 9_000) == [10])
        #expect(state.currentRTOMillis == 12_000)
    }

    @Test("Reneging starts T3 after all DATA had been gap acknowledged")
    func renegingRestartsStoppedT3() throws {
        var state = RetransmissionState(initialTSN: 10)
        try state.enqueue(chunk(tsn: 10), sentMillis: 0)
        try state.enqueue(chunk(tsn: 11), sentMillis: 0)
        _ = state.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 1, end: 2)],
            receivedMillis: 100
        )
        #expect(try retransmissions(&state, at: 10_000).isEmpty)

        _ = state.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 2, end: 2)],
            receivedMillis: 10_000
        )
        #expect(try retransmissions(&state, at: 10_999).isEmpty)
        #expect(try retransmissions(&state, at: 11_000) == [10])
    }

    @Test("Only fast retransmitting the earliest outstanding TSN restarts T3")
    func fastRetransmitRestartRule() throws {
        var nonEarliest = RetransmissionState(initialTSN: 10)
        try nonEarliest.enqueue(chunk(tsn: 10), sentMillis: 0)
        try nonEarliest.enqueue(chunk(tsn: 11), sentMillis: 0)
        nonEarliest.markForFastRetransmit(tsn: 11)
        #expect(try retransmissions(
            &nonEarliest,
            at: 100,
            includeExpired: false
        ) == [11])
        #expect(try retransmissions(&nonEarliest, at: 3_000) == [10])

        var earliest = RetransmissionState(initialTSN: 10)
        try earliest.enqueue(chunk(tsn: 10), sentMillis: 0)
        try earliest.enqueue(chunk(tsn: 11), sentMillis: 0)
        earliest.markForFastRetransmit(tsn: 10)
        #expect(try retransmissions(
            &earliest,
            at: 100,
            includeExpired: false
        ) == [10])
        #expect(try retransmissions(&earliest, at: 3_000).isEmpty)
        #expect(try retransmissions(&earliest, at: 3_100) == [10])
    }

    @Test("Retransmitting an earlier TSN invalidates later RTT samples")
    func retransmissionInvalidatesLaterRTTSample() throws {
        var state = RetransmissionState(initialTSN: 10)
        try state.enqueue(chunk(tsn: 10), sentMillis: 0)
        try state.enqueue(chunk(tsn: 11), sentMillis: 0)
        state.markForFastRetransmit(tsn: 10)
        #expect(try retransmissions(
            &state,
            at: 100,
            includeExpired: false
        ) == [10])

        _ = state.acknowledge(
            cumulativeTSN: 11,
            gapBlocks: [],
            receivedMillis: 1_000
        )
        #expect(state.currentRTOMillis == 3_000)
    }

    @Test("Opening a zero window hands the probe to normal T3 ownership")
    func zeroWindowProbeHandsOffToT3() throws {
        var state = RetransmissionState(
            initialTSN: 10,
            peerAdvertisedReceiverWindow: 0
        )
        try state.admit(contentsOf: [chunk(tsn: 10)], at: 0)
        #expect(try state.outboundChunks(
            nowMillis: 0,
            trigger: .application
        ).get().isEmpty)
        #expect(try state.outboundChunks(
            nowMillis: 3_000,
            trigger: .timer
        ).get().map(\.tsn) == [10])

        _ = state.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [],
            advertisedReceiverWindowCredit: 1_000,
            receivedMillis: 4_000
        )
        #expect(try state.outboundChunks(
            nowMillis: 4_000,
            trigger: .acknowledgment
        ).get().isEmpty)
        #expect(try retransmissions(&state, at: 6_999).isEmpty)
        #expect(try retransmissions(&state, at: 7_000) == [10])
    }

    @Test("T3 selects the serially earliest DATA across TSN wrap")
    func timeoutSelectionWraps() throws {
        let first = UInt32.max &- 1
        var state = RetransmissionState(initialTSN: first)
        try state.enqueue(chunk(tsn: first), sentMillis: 0)
        try state.enqueue(chunk(tsn: UInt32.max), sentMillis: 0)
        try state.enqueue(chunk(tsn: 0), sentMillis: 0)

        #expect(try retransmissions(&state, at: 3_000) == [first])
    }

    @Test("Teardown releases T3 and retained payload ownership")
    func teardownStopsTimerAndReleasesOwners() throws {
        var state = RetransmissionState(initialTSN: 10)
        try state.enqueue(chunk(tsn: 10), sentMillis: 0)
        state.removeAll()

        #expect(state.isEmpty)
        #expect(state.bytesInFlight == 0)
        #expect(state.retainedPayloadByteCount == 0)
        #expect(try retransmissions(&state, at: UInt64.max).isEmpty)
    }
}
