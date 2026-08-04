import Testing
@testable import WebRTC

@Suite("SCTP Flow Control Tests")
struct SCTPFlowControlTests {
    private typealias Engine = SCTPAssociationEngine

    private func chunk(tsn: UInt32, byteCount: Int = 1_172) -> SCTPDataChunk {
        SCTPDataChunk(
            tsn: tsn,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53,
            userData: [UInt8](repeating: UInt8(truncatingIfNeeded: tsn), count: byteCount)
        )
    }

    private func makeEngine(
        initiateTag: UInt32,
        initialTSN: UInt32
    ) -> Engine {
        Engine(
            localPort: 5000,
            remotePort: 5000,
            maxInboundStreams: 32,
            maxOutboundStreams: 32,
            initiateTag: initiateTag,
            initialTSN: initialTSN,
            cookieSecretKey: [UInt8](
                repeating: UInt8(truncatingIfNeeded: initiateTag),
                count: 32
            ),
            cookieCrypto: makeSCTPCookieCryptoContext()
        )
    }

    private func establishPair() throws -> (client: Engine, server: Engine) {
        var client = makeEngine(initiateTag: 0x1111_1111, initialTSN: 100)
        var server = makeEngine(initiateTag: 0x2222_2222, initialTSN: 200)
        let initPacket = client.generateInit()
        let initAck = try #require(server.processPacketWithEvents(
            initPacket,
            nowMillis: 1
        ).responses.first)
        let cookieEcho = try #require(client.processPacketWithEvents(
            initAck,
            nowMillis: 2
        ).responses.first)
        let cookieAck = try #require(server.processPacketWithEvents(
            cookieEcho,
            nowMillis: 3
        ).responses.first)
        _ = try client.processPacketWithEvents(cookieAck, nowMillis: 4)
        return (client, server)
    }

    private func dataTSNs(_ packets: [SCTPPacket]) throws -> [UInt32] {
        try packets.compactMap { packet in
            guard let wireChunk = packet.chunks.first,
                  wireChunk.chunkType == SCTPChunkType.data.rawValue else {
                return nil
            }
            return try wireChunk.decodedDataChunk().tsn
        }
    }

    @Test("INIT and INIT-ACK advertise the bounded reassembly capacity")
    func handshakeAdvertisesReassemblyCapacity() throws {
        var client = makeEngine(
            initiateTag: 0x1111_1111,
            initialTSN: 100
        )
        var server = makeEngine(
            initiateTag: 0x2222_2222,
            initialTSN: 200
        )

        let initPacket = client.generateInit()
        let initWireChunk = try #require(initPacket.chunks.first)
        let initChunk = try SCTPInitChunk.decode(
            from: initWireChunk.value
        )
        #expect(
            initChunk.advertisedReceiverWindowCredit
                == UInt32(FragmentReassembler.defaultMaxBufferedBytes)
        )

        let initAckPacket = try #require(server.processPacketWithEvents(
            initPacket,
            nowMillis: 1
        ).responses.first)
        let initAckWireChunk = try #require(initAckPacket.chunks.first)
        let initAckChunk = try SCTPInitChunk.decode(
            from: initAckWireChunk.value
        )
        #expect(
            initAckChunk.advertisedReceiverWindowCredit
                == UInt32(FragmentReassembler.defaultMaxBufferedBytes)
        )
    }

    @Test("Production sender admits a message but emits only the initial cwnd burst")
    func engineAdmissionIsWindowBounded() throws {
        var pair = try establishPair()
        let packets = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [UInt8](repeating: 0xA5, count: 20_000),
            unordered: false,
            nowMillis: 10
        )

        #expect(packets.count == 4)
        #expect(try dataTSNs(packets) == [100, 101, 102, 103])
        #expect(pair.client.hasUnacknowledgedData)
    }

    @Test("A cumulative SACK drains the next FIFO burst")
    func sackDrainsQueuedData() throws {
        var pair = try establishPair()
        let initial = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [UInt8](repeating: 0x5A, count: 20_000),
            unordered: false,
            nowMillis: 10
        )

        var finalSack: SCTPPacket?
        for (index, packet) in initial.enumerated() {
            finalSack = try pair.server.processPacketWithEvents(
                packet,
                nowMillis: 20 + UInt64(index)
            ).responses.first
        }
        let sack = try #require(finalSack)
        let drained = try pair.client.processPacketWithEvents(
            sack,
            nowMillis: 30
        ).responses

        #expect(try dataTSNs(drained) == [104, 105, 106, 107])
    }

    @Test("A queued TSN cannot be acknowledged before it reaches the wire")
    func queuedTSNCannotBeAcknowledged() throws {
        var state = RetransmissionState(initialTSN: 100)
        let chunks = (100..<110).map { chunk(tsn: UInt32($0)) }
        try state.admit(contentsOf: chunks, at: 0)
        _ = try state.outboundChunks(
            nowMillis: 0,
            trigger: .application
        ).get()

        let outcome = state.acknowledge(
            cumulativeTSN: 104,
            gapBlocks: [],
            receivedMillis: 10
        )
        #expect(outcome == .protocolViolation(
            .cumulativeAcknowledgesUnsentTSN(
                cumulativeTSN: 104,
                highestSentTSN: 103
            )
        ))
    }

    @Test("Retransmission is selected before queued new DATA")
    func retransmissionPrecedesQueuedData() throws {
        var state = RetransmissionState(initialTSN: 100)
        try state.enqueue(chunk(tsn: 100, byteCount: 100), sentMillis: 0)
        try state.admit(contentsOf: [chunk(tsn: 101, byteCount: 100)], at: 1)
        state.markForFastRetransmit(tsn: 100)

        let outbound = try state.outboundChunks(
            nowMillis: 2,
            trigger: .application
        ).get()
        #expect(outbound.map(\.tsn) == [100, 101])
    }

    @Test("Zero receiver window blocks DATA and probes with exponential backoff")
    func zeroWindowProbeRecoversWithoutRetransmitFailure() throws {
        var state = RetransmissionState(
            initialTSN: 100,
            peerAdvertisedReceiverWindow: 0
        )
        try state.admit(contentsOf: [chunk(tsn: 100, byteCount: 100)], at: 0)

        #expect(try state.outboundChunks(
            nowMillis: 0,
            trigger: .application
        ).get().isEmpty)
        #expect(try state.outboundChunks(
            nowMillis: 2_999,
            trigger: .timer
        ).get().isEmpty)
        #expect(try state.outboundChunks(
            nowMillis: 3_000,
            trigger: .timer
        ).get().map(\.tsn) == [100])

        var deadline: UInt64 = 9_000
        var interval: UInt64 = 6_000
        for _ in 0..<12 {
            let sack = state.acknowledge(
                cumulativeTSN: 99,
                gapBlocks: [],
                advertisedReceiverWindowCredit: 0,
                receivedMillis: deadline - 1
            )
            guard case .applied = sack else {
                Issue.record("Expected the zero-window SACK to remain valid")
                return
            }
            let probe = try state.outboundChunks(
                nowMillis: deadline,
                trigger: .timer
            ).get()
            #expect(probe.map(\.tsn) == [100])
            interval = min(interval * 2, 60_000)
            deadline += interval
        }

        _ = state.acknowledge(
            cumulativeTSN: 100,
            gapBlocks: [],
            advertisedReceiverWindowCredit: 65_535,
            receivedMillis: deadline
        )
        #expect(state.isEmpty)
    }
}
