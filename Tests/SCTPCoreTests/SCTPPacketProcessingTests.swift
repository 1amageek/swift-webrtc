import Testing
@testable import WebRTC

@Suite("SCTP Packet Processing Tests")
struct SCTPPacketProcessingTests {
    private typealias Engine = SCTPAssociationEngine

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
            cookieSecretKey: Array(
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

    private func emptyChunk(_ type: SCTPChunkType) throws -> SCTPChunk {
        try SCTPChunk(chunkType: type.rawValue, value: [])
    }

    private func bytes(_ value: UInt32) -> [UInt8] {
        [
            UInt8(value >> 24),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF),
        ]
    }

    @Test("OOTB ABORT wins over bundled INIT and SACK without mutation")
    func abortHasPacketWidePriority() throws {
        var endpoint = makeEngine(initiateTag: 0x2222_2222, initialTSN: 200)
        var peer = makeEngine(initiateTag: 0x1111_1111, initialTSN: 100)
        let initPacket = peer.generateInit()
        let packet = SCTPPacket(
            sourcePort: initPacket.sourcePort,
            destinationPort: initPacket.destinationPort,
            verificationTag: initPacket.verificationTag,
            chunks: initPacket.chunks + [
                try emptyChunk(.abort),
                try emptyChunk(.sack),
            ]
        )

        let result = try endpoint.processPacketWithEvents(packet, nowMillis: 1)

        #expect(result.responses.isEmpty)
        #expect(result.deliveries.isEmpty)
        #expect(endpoint.state == .closed)
    }

    @Test("INIT bundled with SACK is silently discarded")
    func initBundleIsDiscarded() throws {
        var endpoint = makeEngine(initiateTag: 0x2222_2222, initialTSN: 200)
        var peer = makeEngine(initiateTag: 0x1111_1111, initialTSN: 100)
        let initPacket = peer.generateInit()
        let packet = SCTPPacket(
            sourcePort: initPacket.sourcePort,
            destinationPort: initPacket.destinationPort,
            verificationTag: initPacket.verificationTag,
            chunks: initPacket.chunks + [try emptyChunk(.sack)]
        )

        let result = try endpoint.processPacketWithEvents(packet, nowMillis: 1)

        #expect(result.responses.isEmpty)
        #expect(endpoint.state == .closed)
    }

    @Test("OOTB ABORT bundled after COOKIE-ECHO cannot consume the cookie")
    func abortPreventsCookieMutation() throws {
        var client = makeEngine(initiateTag: 0x1111_1111, initialTSN: 100)
        var server = makeEngine(initiateTag: 0x2222_2222, initialTSN: 200)
        let initAck = try #require(server.processPacketWithEvents(
            client.generateInit(),
            nowMillis: 1
        ).responses.first)
        let cookieEcho = try #require(client.processPacketWithEvents(
            initAck,
            nowMillis: 2
        ).responses.first)
        let attack = SCTPPacket(
            sourcePort: cookieEcho.sourcePort,
            destinationPort: cookieEcho.destinationPort,
            verificationTag: cookieEcho.verificationTag,
            chunks: cookieEcho.chunks + [
                try emptyChunk(.abort),
                try emptyChunk(.sack),
            ]
        )

        let discarded = try server.processPacketWithEvents(attack, nowMillis: 3)
        #expect(discarded.responses.isEmpty)
        #expect(server.state == .closed)

        let accepted = try server.processPacketWithEvents(cookieEcho, nowMillis: 4)
        #expect(accepted.responses.first?.chunks.first?.chunkType == SCTPChunkType.cookieAck.rawValue)
        #expect(server.state == .established)
    }

    @Test("Misplaced COOKIE-ECHO cannot establish an OOTB association")
    func misplacedCookieEchoDoesNotEstablish() throws {
        var client = makeEngine(initiateTag: 0x1111_1111, initialTSN: 100)
        var server = makeEngine(initiateTag: 0x2222_2222, initialTSN: 200)
        let initAck = try #require(server.processPacketWithEvents(
            client.generateInit(),
            nowMillis: 1
        ).responses.first)
        let cookieEcho = try #require(client.processPacketWithEvents(
            initAck,
            nowMillis: 2
        ).responses.first)
        let misplaced = SCTPPacket(
            sourcePort: cookieEcho.sourcePort,
            destinationPort: cookieEcho.destinationPort,
            verificationTag: cookieEcho.verificationTag,
            chunks: [try emptyChunk(.sack)] + cookieEcho.chunks
        )

        let result = try server.processPacketWithEvents(misplaced, nowMillis: 3)
        #expect(result.responses.first?.chunks.first?.chunkType == SCTPChunkType.abort.rawValue)
        #expect(server.state == .closed)
    }

    @Test("OOTB SHUTDOWN-ACK takes priority and returns reflected SHUTDOWN-COMPLETE")
    func shutdownAckGetsShutdownComplete() throws {
        var endpoint = makeEngine(initiateTag: 0x2222_2222, initialTSN: 200)
        let reflectedTag: UInt32 = 0xDEAD_BEEF
        let packet = SCTPPacket(
            sourcePort: 6000,
            destinationPort: 5000,
            verificationTag: reflectedTag,
            chunks: [
                try emptyChunk(.sack),
                try emptyChunk(.shutdownAck),
            ]
        )

        let result = try endpoint.processPacketWithEvents(packet, nowMillis: 1)
        let response = try #require(result.responses.first)
        let complete = try #require(response.chunks.first)
        #expect(result.responses.count == 1)
        #expect(response.verificationTag == reflectedTag)
        #expect(complete.chunkType == SCTPChunkType.shutdownComplete.rawValue)
        #expect(complete.flags & 0x01 == 0x01)
    }

    @Test("OOTB COOKIE-ACK packet is silently discarded")
    func cookieAckIsDiscarded() throws {
        var endpoint = makeEngine(initiateTag: 0x2222_2222, initialTSN: 200)
        let packet = SCTPPacket(
            sourcePort: 6000,
            destinationPort: 5000,
            verificationTag: 0xDEAD_BEEF,
            chunks: [
                try emptyChunk(.sack),
                try emptyChunk(.cookieAck),
            ]
        )

        let result = try endpoint.processPacketWithEvents(packet, nowMillis: 1)
        #expect(result.responses.isEmpty)
        #expect(endpoint.state == .closed)
    }

    @Test("Multiple HEARTBEAT responses are coalesced into one packet")
    func heartbeatResponsesAreCoalesced() throws {
        var pair = try establishPair()
        let header = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x01],
            unordered: false,
            nowMillis: 5
        )[0]
        let packet = SCTPPacket(
            sourcePort: header.sourcePort,
            destinationPort: header.destinationPort,
            verificationTag: header.verificationTag,
            chunks: [
                try SCTPChunk(chunkType: SCTPChunkType.heartbeat.rawValue, value: [1]),
                try SCTPChunk(chunkType: SCTPChunkType.heartbeat.rawValue, value: [2]),
            ]
        )

        let result = try pair.server.processPacketWithEvents(packet, nowMillis: 6)
        let response = try #require(result.responses.first)
        #expect(result.responses.count == 1)
        #expect(response.chunks.count == 2)
        #expect(response.chunks.allSatisfy {
            $0.chunkType == SCTPChunkType.heartbeatAck.rawValue
        })
    }

    @Test("Control responses spill into ordered PMTU-bounded packets without loss")
    func controlResponsesSpillWithoutLoss() throws {
        var pair = try establishPair()
        let header = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x01],
            unordered: false,
            nowMillis: 5
        )[0]
        let packet = SCTPPacket(
            sourcePort: header.sourcePort,
            destinationPort: header.destinationPort,
            verificationTag: header.verificationTag,
            chunks: [
                try SCTPChunk(
                    chunkType: SCTPChunkType.heartbeat.rawValue,
                    value: Array(repeating: 0x11, count: 600)
                ),
                try SCTPChunk(
                    chunkType: SCTPChunkType.heartbeat.rawValue,
                    value: Array(repeating: 0x22, count: 600)
                ),
            ]
        )

        let result = try pair.server.processPacketWithEvents(packet, nowMillis: 6)

        #expect(result.responses.count == 2)
        #expect(result.responses.allSatisfy {
            $0.encodedByteCount <= Engine.defaultMaximumPacketByteCount
        })
        #expect(result.responses.flatMap(\.chunks).map(\.value) == [
            Array(repeating: 0x11, count: 600),
            Array(repeating: 0x22, count: 600),
        ])
    }

    @Test("DATA bundled with an oversized control response terminates without retained mutation")
    func oversizedControlResponseFails() throws {
        var pair = try establishPair()
        let header = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x01],
            unordered: false,
            nowMillis: 5
        )[0]
        let packet = SCTPPacket(
            sourcePort: header.sourcePort,
            destinationPort: header.destinationPort,
            verificationTag: header.verificationTag,
            chunks: header.chunks + [try SCTPChunk(
                chunkType: SCTPChunkType.heartbeat.rawValue,
                value: Array(repeating: 0x33, count: 1_190)
            )]
        )

        let outcome = try pair.server.processPacketOutcome(packet, nowMillis: 6)
        guard case .terminal(
            let result,
            .packetSizeExceeded(let actual, let limit)
        ) = outcome else {
            Issue.record("Expected a terminal packetSizeExceeded outcome")
            return
        }

        #expect(actual == 1_208)
        #expect(limit == 1_200)
        #expect(result.deliveries.isEmpty)
        #expect(result.responses.first?.chunks.first?.chunkType
            == SCTPChunkType.abort.rawValue)
        #expect(pair.server.state == .closed)
        #expect(pair.server.retainedUserDataByteCount == 0)
    }

    @Test("Bundled SHUTDOWN COMPLETE is discarded before any chunk mutation")
    func bundledShutdownCompleteIsDiscarded() throws {
        var pair = try establishPair()
        let headerPackets = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x01],
            unordered: false,
            nowMillis: 5
        )
        let header = try #require(headerPackets.first)
        let packet = SCTPPacket(
            sourcePort: header.sourcePort,
            destinationPort: header.destinationPort,
            verificationTag: header.verificationTag,
            chunks: [
                try SCTPChunk(
                    chunkType: SCTPChunkType.heartbeat.rawValue,
                    value: [0x01]
                ),
                try SCTPChunk(
                    chunkType: SCTPChunkType.shutdownComplete.rawValue,
                    value: []
                ),
            ]
        )

        let result = try pair.server.processPacketWithEvents(packet, nowMillis: 6)

        #expect(result.responses.isEmpty)
        #expect(result.deliveries.isEmpty)
        #expect(pair.server.state == .established)
    }

    @Test("SACK keeps the lowest gap blocks within one PMTU")
    func sackTruncatesHighestGapBlocks() throws {
        var pair = try establishPair()
        let header = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x01],
            unordered: false,
            nowMillis: 5
        )[0]
        var chunks: [SCTPChunk] = []
        chunks.reserveCapacity(512)
        for index in 0..<512 {
            chunks.append(try SCTPDataChunk(
                tsn: 101 &+ UInt32(index * 2),
                streamIdentifier: 0,
                streamSequenceNumber: UInt16(truncatingIfNeeded: index),
                payloadProtocolIdentifier: 53,
                userData: [0x01],
                unordered: true
            ).toChunk())
        }
        let packet = SCTPPacket(
            sourcePort: header.sourcePort,
            destinationPort: header.destinationPort,
            verificationTag: header.verificationTag,
            chunks: chunks
        )

        let result = try pair.server.processPacketWithEvents(packet, nowMillis: 6)
        let response = try #require(result.responses.first)
        let sackChunk = try #require(response.chunks.first)
        let sack = try SCTPSackChunk.decode(from: sackChunk.value)

        #expect(result.responses.count == 1)
        #expect(response.encodedByteCount == Engine.defaultMaximumPacketByteCount)
        #expect(sack.gapAckBlocks.count == 293)
        #expect(sack.gapAckBlocks.first?.start == 2)
        #expect(sack.gapAckBlocks.last?.end == 586)
    }

    @Test("SHUTDOWN followed by SACK processes the SACK before SHUTDOWN-ACK")
    func shutdownAndSackBundleDrainsOutstandingData() throws {
        var pair = try establishPair()
        _ = try pair.server.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x01],
            unordered: false,
            nowMillis: 5
        )
        _ = try pair.server.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x02],
            unordered: false,
            nowMillis: 6
        )
        #expect(pair.server.hasUnacknowledgedData)

        let header = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x03],
            unordered: false,
            nowMillis: 7
        )[0]
        let shutdown = try SCTPChunk(
            chunkType: SCTPChunkType.shutdown.rawValue,
            value: bytes(199)
        )
        let sack = try SCTPSackChunk(cumulativeTSNAck: 201).toChunk()
        let packet = SCTPPacket(
            sourcePort: header.sourcePort,
            destinationPort: header.destinationPort,
            verificationTag: header.verificationTag,
            chunks: [shutdown, sack]
        )

        let result = try pair.server.processPacketWithEvents(packet, nowMillis: 8)
        #expect(!pair.server.hasUnacknowledgedData)
        #expect(pair.server.state == .shutdownAckSent)
        #expect(result.responses.first?.chunks.contains {
            $0.chunkType == SCTPChunkType.shutdownAck.rawValue
        } == true)
    }

    @Test("Forged SACK returns wire ABORT and typed terminal failure together")
    func forgedSackProducesTerminalOutcome() throws {
        var pair = try establishPair()
        let data = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x01],
            unordered: false,
            nowMillis: 5
        )[0]
        let legitimateSackPacket = try #require(pair.server.processPacketWithEvents(
            data,
            nowMillis: 6
        ).responses.first)
        let legitimateSackChunk = try #require(legitimateSackPacket.chunks.first)
        let legitimateSack = try SCTPSackChunk.decode(from: legitimateSackChunk.value)
        let forged = SCTPPacket(
            sourcePort: legitimateSackPacket.sourcePort,
            destinationPort: legitimateSackPacket.destinationPort,
            verificationTag: legitimateSackPacket.verificationTag,
            chunks: [try SCTPSackChunk(
                cumulativeTSNAck: legitimateSack.cumulativeTSNAck &+ 1
            ).toChunk()]
        )

        let outcome = try pair.client.processPacketOutcome(forged, nowMillis: 7)
        guard case .terminal(let result, let error) = outcome else {
            Issue.record("Expected a terminal SCTP outcome")
            return
        }
        guard case .sackProtocolViolation(
            .cumulativeAcknowledgesUnsentTSN(
                let cumulativeTSN,
                let highestSentTSN
            )
        ) = error else {
            Issue.record("Expected a typed forged-SACK violation, got \(error)")
            return
        }
        let abortPacket = try #require(result.responses.first)
        let abort = try #require(abortPacket.chunks.first)
        #expect(cumulativeTSN == 101)
        #expect(highestSentTSN == 100)
        #expect(abort.chunkType == SCTPChunkType.abort.rawValue)
        #expect(abort.flags & 0x01 == 0)
        #expect(pair.client.state == .closed)
    }
}
