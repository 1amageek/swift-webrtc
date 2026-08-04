import Testing
@testable import WebRTC

@Suite("SCTP FORWARD-TSN Tests")
struct SCTPForwardTSNTests {
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

        let initAck = try #require(server.processPacketWithEvents(
            client.generateInit(),
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

        #expect(client.state == .established)
        #expect(server.state == .established)
        #expect(client.supportsPartialReliability)
        #expect(server.supportsPartialReliability)
        return (client, server)
    }

    private func packet(
        like template: SCTPPacket,
        chunks: [SCTPChunk]
    ) -> SCTPPacket {
        SCTPPacket(
            sourcePort: template.sourcePort,
            destinationPort: template.destinationPort,
            verificationTag: template.verificationTag,
            chunks: chunks
        )
    }

    private func sack(in packets: [SCTPPacket]) throws -> SCTPSackChunk {
        let chunk = try #require(packets.lazy.flatMap(\.chunks).first {
            $0.chunkType == SCTPChunkType.sack.rawValue
        })
        return try SCTPSackChunk.decode(from: chunk.value)
    }

    private func resetResponses(
        in packets: [SCTPPacket]
    ) throws -> [SCTPReconfigurationResponse] {
        let parameters = try packets.lazy.flatMap(\.chunks).filter {
            $0.chunkType == SCTPChunkType.reConfig.rawValue
        }.flatMap { chunk in
            try SCTPReconfigurationChunk.decode(from: chunk).parameters
        }
        return parameters.compactMap { parameter in
            guard case .response(let response) = parameter else { return nil }
            return response
        }
    }

    @Test("FORWARD-TSN wire codec validates flags, alignment, and duplicate streams")
    func wireValidation() throws {
        let value = SCTPForwardTSNChunk(
            newCumulativeTSN: 0x0102_0304,
            skippedStreams: [
                .init(streamIdentifier: 3, streamSequenceNumber: 7),
                .init(streamIdentifier: 5, streamSequenceNumber: 9),
            ]
        )
        let chunk = try value.toChunk()
        #expect(chunk.value == [
            0x01, 0x02, 0x03, 0x04,
            0x00, 0x03, 0x00, 0x07,
            0x00, 0x05, 0x00, 0x09,
        ])
        #expect(try SCTPForwardTSNChunk.decode(from: chunk) == value)

        #expect(throws: SCTPWireError.self) {
            _ = try SCTPForwardTSNChunk.decode(from: SCTPChunk(
                chunkType: SCTPChunkType.forwardTSN.rawValue,
                flags: 1,
                value: [0, 0, 0, 1]
            ))
        }
        #expect(throws: SCTPWireError.self) {
            _ = try SCTPForwardTSNChunk.decode(from: SCTPChunk(
                chunkType: SCTPChunkType.forwardTSN.rawValue,
                value: [0, 0, 0, 1, 0]
            ))
        }
        #expect(throws: SCTPWireError.self) {
            _ = try SCTPForwardTSNChunk.decode(from: SCTPChunk(
                chunkType: SCTPChunkType.forwardTSN.rawValue,
                value: [
                    0, 0, 0, 1,
                    0, 3, 0, 7,
                    0, 3, 0, 8,
                ]
            ))
        }
    }

    @Test("FORWARD-TSN releases stranded ordered DATA and advances through buffered TSNs")
    func orderedGapRelease() throws {
        var pair = try establishPair()
        var packets: [SCTPPacket] = []
        for payload in UInt8(0x10)...UInt8(0x12) {
            packets.append(try #require(pair.client.sendDataPackets(
                streamID: 0,
                payloadProtocolIdentifier: 53,
                data: [payload],
                unordered: false,
                nowMillis: UInt64(payload)
            ).first))
        }

        let outOfOrder = try pair.server.processPacketWithEvents(
            packets[2],
            nowMillis: 20
        )
        #expect(outOfOrder.receivedData.isEmpty)
        #expect(try sack(in: outOfOrder.responses).cumulativeTSNAck == 99)

        let forward = try SCTPForwardTSNChunk(
            newCumulativeTSN: 101,
            skippedStreams: [
                .init(streamIdentifier: 0, streamSequenceNumber: 1),
            ]
        ).toChunk()
        let result = try pair.server.processPacketWithEvents(
            packet(like: packets[2], chunks: [forward]),
            nowMillis: 21
        )

        #expect(result.receivedData.map(\.data) == [[0x12]])
        #expect(try sack(in: result.responses).cumulativeTSNAck == 102)
        #expect(pair.server.retainedUserDataByteCount == 0)

        let stale = try SCTPForwardTSNChunk(
            newCumulativeTSN: 100,
            skippedStreams: [
                .init(streamIdentifier: 0, streamSequenceNumber: 0),
            ]
        ).toChunk()
        let staleResult = try pair.server.processPacketWithEvents(
            packet(like: packets[2], chunks: [stale]),
            nowMillis: 22
        )
        #expect(staleResult.receivedData.isEmpty)
        #expect(try sack(in: staleResult.responses).cumulativeTSNAck == 102)
    }

    @Test("FORWARD-TSN discards a partial message whose missing fragment was abandoned")
    func abandonedFragmentRelease() throws {
        var pair = try establishPair()
        let template = try #require(pair.client.sendDataPackets(
            streamID: 1,
            payloadProtocolIdentifier: 53,
            data: [0xEE],
            unordered: true,
            nowMillis: 5
        ).first)
        let beginning = SCTPDataChunk(
            tsn: 100,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53,
            userData: [0xA0],
            beginningFragment: true,
            endingFragment: false,
            unordered: false
        )
        let ending = SCTPDataChunk(
            tsn: 102,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53,
            userData: [0xA2],
            beginningFragment: false,
            endingFragment: true,
            unordered: false
        )

        _ = try pair.server.processPacketWithEvents(
            packet(like: template, chunks: [try beginning.toChunk()]),
            nowMillis: 6
        )
        _ = try pair.server.processPacketWithEvents(
            packet(like: template, chunks: [try ending.toChunk()]),
            nowMillis: 7
        )
        #expect(pair.server.retainedUserDataByteCount == 2)

        let forward = try SCTPForwardTSNChunk(
            newCumulativeTSN: 101
        ).toChunk()
        let forwarded = try pair.server.processPacketWithEvents(
            packet(like: template, chunks: [forward]),
            nowMillis: 8
        )
        #expect(forwarded.receivedData.isEmpty)
        #expect(try sack(in: forwarded.responses).cumulativeTSNAck == 102)
        #expect(pair.server.retainedUserDataByteCount == 0)

        let late = SCTPDataChunk(
            tsn: 101,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53,
            userData: [0xA1],
            beginningFragment: false,
            endingFragment: false,
            unordered: false
        )
        let lateResult = try pair.server.processPacketWithEvents(
            packet(like: template, chunks: [try late.toChunk()]),
            nowMillis: 9
        )
        #expect(lateResult.receivedData.isEmpty)
        #expect(pair.server.retainedUserDataByteCount == 0)
    }

    @Test("FORWARD-TSN completes a reset waiting on abandoned DATA")
    func forwardCompletesDeferredReset() throws {
        var pair = try establishPair()
        var dataPackets: [SCTPPacket] = []
        for payload in UInt8(0x20)...UInt8(0x22) {
            dataPackets.append(try #require(pair.client.sendDataPackets(
                streamID: 0,
                payloadProtocolIdentifier: 53,
                data: [payload],
                unordered: false,
                nowMillis: UInt64(payload)
            ).first))
        }

        let outOfOrder = try pair.server.processPacketWithEvents(
            dataPackets[2],
            nowMillis: 40
        )
        #expect(outOfOrder.receivedData.isEmpty)
        #expect(try sack(in: outOfOrder.responses).cumulativeTSNAck == 99)

        let resetRequest = try #require(try pair.client.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 41
        ))
        let pending = try pair.server.processPacketWithEvents(
            resetRequest,
            nowMillis: 42
        )
        #expect(try resetResponses(in: pending.responses).map(\.result) == [
            .inProgress,
        ])

        let forward = try SCTPForwardTSNChunk(
            newCumulativeTSN: 101,
            skippedStreams: [
                .init(streamIdentifier: 0, streamSequenceNumber: 1),
            ]
        ).toChunk()
        let completed = try pair.server.processPacketWithEvents(
            packet(like: dataPackets[2], chunks: [forward]),
            nowMillis: 43
        )

        #expect(completed.deliveries.count == 2)
        if case .message(let message) = completed.deliveries[0] {
            #expect(message.data == [0x22])
        } else {
            Issue.record("The released ordered message must precede the reset boundary")
        }
        if case .event(let event) = completed.deliveries[1] {
            #expect(event == .incomingStreamsReset(.listed([0])))
        } else {
            Issue.record("The reset boundary must follow pre-reset DATA")
        }
        #expect(try resetResponses(in: completed.responses).map(\.result) == [
            .successPerformed,
        ])
        #expect(try sack(in: completed.responses).cumulativeTSNAck == 102)
        #expect(pair.server.retainedUserDataByteCount == 0)
    }
}

@Suite("SCTP Reset-Queued DATA Tests")
struct SCTPResetQueuedDataTests {
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
        let initAck = try #require(server.processPacketWithEvents(
            client.generateInit(),
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

    private func dataChunks(in packets: [SCTPPacket]) throws -> [SCTPDataChunk] {
        try packets.flatMap(\.chunks).compactMap { chunk in
            guard chunk.chunkType == SCTPChunkType.data.rawValue else {
                return nil
            }
            return try SCTPDataChunk.decode(from: chunk.value, flags: chunk.flags)
        }
    }

    private func responsePacket(
        like template: SCTPPacket,
        sequenceNumber: UInt32,
        result: SCTPReconfigurationResult
    ) throws -> SCTPPacket {
        SCTPPacket(
            sourcePort: template.sourcePort,
            destinationPort: template.destinationPort,
            verificationTag: template.verificationTag,
            chunks: [try SCTPReconfigurationChunk(parameters: [
                .response(SCTPReconfigurationResponse(
                    responseSequenceNumber: sequenceNumber,
                    result: result
                )),
            ]).toChunk()]
        )
    }

    @Test("Reset-blocked DATA is accepted without consuming TSN and released FIFO after success")
    func successResetsSSNBeforeRelease() throws {
        var pair = try establishPair()
        let request = try #require(try pair.client.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 5
        ))

        #expect(try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xA0],
            unordered: false,
            nowMillis: 6
        ).isEmpty)
        #expect(try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xA1],
            unordered: false,
            nowMillis: 7
        ).isEmpty)
        #expect(pair.client.hasUnacknowledgedData)
        #expect(pair.client.retainedUserDataByteCount == 2)

        let unaffected = try #require(pair.client.sendDataPackets(
            streamID: 1,
            payloadProtocolIdentifier: 53,
            data: [0xB0],
            unordered: false,
            nowMillis: 8
        ).first)
        #expect(try dataChunks(in: [unaffected]).first?.tsn == 100)

        let peerResult = try pair.server.processPacketWithEvents(
            request,
            nowMillis: 9
        )
        let finalResponse = try #require(peerResult.responses.first)
        let completion = try pair.client.processPacketWithEvents(
            finalResponse,
            nowMillis: 10
        )
        let released = try dataChunks(in: completion.responses)
        #expect(released.map(\.tsn) == [101, 102])
        #expect(released.map(\.streamSequenceNumber) == [0, 1])
        #expect(released.map(\.userData) == [[0xA0], [0xA1]])
        #expect(completion.events == [.outgoingStreamsReset(.listed([0]))])
    }

    @Test("In Progress retains DATA and a denied reset continues the existing SSN")
    func inProgressThenDeniedContinuesSSN() throws {
        var pair = try establishPair()
        let initial = try #require(pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x10],
            unordered: false,
            nowMillis: 5
        ).first)
        let ack = try #require(pair.server.processPacketWithEvents(
            initial,
            nowMillis: 6
        ).responses.first)
        _ = try pair.client.processPacketWithEvents(ack, nowMillis: 7)

        let request = try #require(try pair.client.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 8
        ))
        #expect(try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x11],
            unordered: false,
            nowMillis: 9
        ).isEmpty)

        let realPeerResult = try pair.server.processPacketWithEvents(
            request,
            nowMillis: 10
        )
        let responseTemplate = try #require(realPeerResult.responses.first)
        let progress = try responsePacket(
            like: responseTemplate,
            sequenceNumber: 100,
            result: .inProgress
        )
        let progressResult = try pair.client.processPacketWithEvents(
            progress,
            nowMillis: 11
        )
        #expect(try dataChunks(in: progressResult.responses).isEmpty)
        #expect(pair.client.retainedUserDataByteCount == 1)

        let denied = try responsePacket(
            like: responseTemplate,
            sequenceNumber: 100,
            result: .denied
        )
        let deniedResult = try pair.client.processPacketWithEvents(
            denied,
            nowMillis: 12
        )
        let released = try #require(dataChunks(in: deniedResult.responses).first)
        #expect(released.tsn == 101)
        #expect(released.streamSequenceNumber == 1)
        #expect(released.userData == [0x11])
        #expect(deniedResult.events == [
            .outgoingStreamResetFailed(.listed([0]), .denied),
        ])
    }

    @Test("Shutdown releases accepted reset-blocked DATA before sending SHUTDOWN")
    func shutdownDrainsQueuedData() throws {
        var pair = try establishPair()
        _ = try #require(try pair.client.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 5
        ))
        #expect(try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xCC],
            unordered: false,
            nowMillis: 6
        ).isEmpty)

        #expect(try pair.client.requestShutdown(nowMillis: 7) == nil)
        #expect(pair.client.state == .shutdownPending)
        let outbound = try pair.client.pollOutboundPackets(nowMillis: 8).get()
        let released = try #require(dataChunks(in: outbound).first)
        #expect(released.tsn == 100)
        #expect(released.streamSequenceNumber == 0)
        #expect(released.userData == [0xCC])
    }

    @Test("Reset-blocked DATA reservations enforce the shared byte ceiling")
    func queuedByteReservationIsBounded() throws {
        var pair = try establishPair()
        _ = try #require(try pair.client.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 5
        ))
        let maximumPayload = Array(repeating: UInt8(0x5A), count: 1_048_576)
        #expect(try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: maximumPayload,
            unordered: false,
            nowMillis: 6
        ).isEmpty)
        #expect(pair.client.retainedUserDataByteCount == maximumPayload.count)

        #expect(throws: SCTPError.self) {
            _ = try pair.client.sendDataPackets(
                streamID: 0,
                payloadProtocolIdentifier: 53,
                data: [0x01],
                unordered: false,
                nowMillis: 7
            )
        }
        #expect(pair.client.retainedUserDataByteCount == maximumPayload.count)
    }

    @Test("Timed reset-blocked DATA expires before TSN and SSN assignment")
    func timedQueuedDataExpiresBeforeResetCompletion() throws {
        var pair = try establishPair()
        let request = try #require(try pair.client.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 5
        ))
        #expect(try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xDD],
            unordered: false,
            reliability: .maximumLifetimeMilliseconds(10),
            nowMillis: 6
        ).isEmpty)

        let peerResult = try pair.server.processPacketWithEvents(
            request,
            nowMillis: 20
        )
        let response = try #require(peerResult.responses.first)
        let completed = try pair.client.processPacketWithEvents(
            response,
            nowMillis: 21
        )
        #expect(try dataChunks(in: completed.responses).isEmpty)
        #expect(pair.client.retainedUserDataByteCount == 0)

        let next = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xDE],
            unordered: false,
            nowMillis: 22
        )
        let chunk = try #require(dataChunks(in: next).first)
        #expect(chunk.tsn == 100)
        #expect(chunk.streamSequenceNumber == 0)
    }
}

@Suite("SCTP Partial-Reliability Sender Tests")
struct SCTPPartialReliabilitySenderTests {
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
        let initAck = try #require(server.processPacketWithEvents(
            client.generateInit(),
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

    private func forwardTSN(
        in packets: [SCTPPacket]
    ) throws -> SCTPForwardTSNChunk {
        let chunk = try #require(packets.lazy.flatMap(\.chunks).first {
            $0.chunkType == SCTPChunkType.forwardTSN.rawValue
        })
        return try SCTPForwardTSNChunk.decode(from: chunk)
    }

    private func dataChunks(
        in packets: [SCTPPacket]
    ) throws -> [SCTPDataChunk] {
        try packets.lazy.flatMap(\.chunks).compactMap { chunk in
            guard chunk.chunkType == SCTPChunkType.data.rawValue else {
                return nil
            }
            return try SCTPDataChunk.decode(from: chunk.value, flags: chunk.flags)
        }
    }

    @Test("Zero retransmissions abandons a lost message and preserves later ordering")
    func zeroRetransmissionsForwardsAndContinues() throws {
        var pair = try establishPair()
        let first = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xA0],
            unordered: false,
            reliability: .maximumRetransmissions(0),
            nowMillis: 5
        )
        #expect(try dataChunks(in: first).map(\.tsn) == [100])

        let timedOut = try pair.client.pollOutboundPackets(
            nowMillis: 3_005
        ).get()
        #expect(try dataChunks(in: timedOut).isEmpty)
        let forward = try forwardTSN(in: timedOut)
        #expect(forward.newCumulativeTSN == 100)
        #expect(forward.skippedStreams == [
            .init(streamIdentifier: 0, streamSequenceNumber: 0),
        ])
        #expect(pair.client.retainedUserDataByteCount == 0)

        let acknowledgment = try pair.server.processPacketWithEvents(
            timedOut[0],
            nowMillis: 3_006
        )
        let sack = try #require(acknowledgment.responses.first)
        _ = try pair.client.processPacketWithEvents(sack, nowMillis: 3_007)
        #expect(!pair.client.hasUnacknowledgedData)

        let next = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xA1],
            unordered: false,
            nowMillis: 3_008
        )
        let nextChunk = try #require(dataChunks(in: next).first)
        #expect(nextChunk.tsn == 101)
        #expect(nextChunk.streamSequenceNumber == 1)
        let delivered = try pair.server.processPacketWithEvents(
            next[0],
            nowMillis: 3_009
        )
        #expect(delivered.receivedData.map(\.data) == [[0xA1]])
    }

    @Test("Abandoning one fragment abandons the complete ordered message")
    func fragmentedMessageIsAtomic() throws {
        var pair = try establishPair()
        let payload = Array(repeating: UInt8(0x5A), count: 2_000)
        let packets = try pair.client.sendDataPackets(
            streamID: 2,
            payloadProtocolIdentifier: 53,
            data: payload,
            unordered: false,
            reliability: .maximumRetransmissions(0),
            nowMillis: 5
        )
        #expect(try dataChunks(in: packets).count == 2)

        let timedOut = try pair.client.pollOutboundPackets(
            nowMillis: 3_005
        ).get()
        let forward = try forwardTSN(in: timedOut)
        #expect(forward.newCumulativeTSN == 101)
        #expect(forward.skippedStreams == [
            .init(streamIdentifier: 2, streamSequenceNumber: 0),
        ])
        #expect(try dataChunks(in: timedOut).isEmpty)
        #expect(pair.client.retainedUserDataByteCount == 0)
    }

    @Test("Timed reliability expires before T3 and retransmits FORWARD-TSN on its deadline")
    func timedExpiryAndForwardRetransmission() throws {
        var pair = try establishPair()
        _ = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xB0],
            unordered: false,
            reliability: .maximumLifetimeMilliseconds(100),
            nowMillis: 10
        )

        #expect(try pair.client.pollOutboundPackets(
            nowMillis: 109
        ).get().isEmpty)
        let expired = try pair.client.pollOutboundPackets(
            nowMillis: 110
        ).get()
        #expect(try forwardTSN(in: expired).newCumulativeTSN == 100)
        #expect(try pair.client.pollOutboundPackets(
            nowMillis: 3_109
        ).get().isEmpty)
        let retransmitted = try pair.client.pollOutboundPackets(
            nowMillis: 3_110
        ).get()
        #expect(try forwardTSN(in: retransmitted).newCumulativeTSN == 100)
    }

    @Test("Expired before TSN assignment consumes no TSN or SSN")
    func zeroLifetimeConsumesNoSequenceSpace() throws {
        var pair = try establishPair()
        #expect(try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xC0],
            unordered: false,
            reliability: .maximumLifetimeMilliseconds(0),
            nowMillis: 10
        ).isEmpty)

        let reliable = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xC1],
            unordered: false,
            nowMillis: 11
        )
        let chunk = try #require(dataChunks(in: reliable).first)
        #expect(chunk.tsn == 100)
        #expect(chunk.streamSequenceNumber == 0)
    }

    @Test("Unordered abandonment does not report stream sequence metadata")
    func unorderedForwardHasNoSkippedStream() throws {
        var pair = try establishPair()
        _ = try pair.client.sendDataPackets(
            streamID: 3,
            payloadProtocolIdentifier: 53,
            data: [0xD0],
            unordered: true,
            reliability: .maximumRetransmissions(0),
            nowMillis: 5
        )
        let timedOut = try pair.client.pollOutboundPackets(
            nowMillis: 3_005
        ).get()
        #expect(try forwardTSN(in: timedOut).skippedStreams.isEmpty)
    }

    @Test("One retransmission is emitted before the message is abandoned")
    func maximumOneRetransmission() throws {
        var pair = try establishPair()
        _ = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xE0],
            unordered: false,
            reliability: .maximumRetransmissions(1),
            nowMillis: 5
        )

        let firstTimeout = try pair.client.pollOutboundPackets(
            nowMillis: 3_005
        ).get()
        #expect(try dataChunks(in: firstTimeout).map(\.tsn) == [100])
        #expect(firstTimeout.allSatisfy { packet in
            packet.chunks.allSatisfy {
                $0.chunkType != SCTPChunkType.forwardTSN.rawValue
            }
        })

        let secondTimeout = try pair.client.pollOutboundPackets(
            nowMillis: 9_005
        ).get()
        #expect(try dataChunks(in: secondTimeout).isEmpty)
        #expect(try forwardTSN(in: secondTimeout).newCumulativeTSN == 100)
    }

    @Test("Partial reliability is rejected when the peer did not negotiate it")
    func peerNegotiationIsRequired() throws {
        var client = makeEngine(initiateTag: 0x1111_1111, initialTSN: 100)
        var server = makeEngine(initiateTag: 0x2222_2222, initialTSN: 200)
        let advertisedInit = client.generateInit()
        let originalChunk = try #require(advertisedInit.chunks.first)
        let baseInit = try SCTPInitChunk.decode(from: originalChunk.value)
        let strippedInit = SCTPPacket(
            sourcePort: advertisedInit.sourcePort,
            destinationPort: advertisedInit.destinationPort,
            verificationTag: advertisedInit.verificationTag,
            chunks: [baseInit.toChunk()]
        )
        let initAck = try #require(server.processPacketWithEvents(
            strippedInit,
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

        #expect(client.supportsPartialReliability)
        #expect(!server.supportsPartialReliability)
        do {
            _ = try server.sendDataPackets(
                streamID: 0,
                payloadProtocolIdentifier: 53,
                data: [0xE1],
                unordered: false,
                reliability: .maximumRetransmissions(0),
                nowMillis: 5
            )
            Issue.record("A peer without PR-SCTP negotiation accepted partial DATA")
        } catch let error {
            guard case .partialReliabilityNotNegotiated = error else {
                Issue.record("Unexpected partial-reliability error: \(error)")
                return
            }
        }
    }

    @Test("Abandoned DATA retains fast-retransmit congestion accounting")
    func abandonedFastRetransmitAdjustsCongestionWindow() throws {
        var state = RetransmissionState(initialTSN: 10)
        func chunk(_ tsn: UInt32) -> SCTPDataChunk {
            SCTPDataChunk(
                tsn: tsn,
                streamIdentifier: 0,
                streamSequenceNumber: UInt16(truncatingIfNeeded: tsn),
                payloadProtocolIdentifier: 53,
                userData: [UInt8(truncatingIfNeeded: tsn)]
            )
        }

        try state.admit(
            contentsOf: [chunk(10)],
            at: 0,
            reliability: .expiresAtMillis(50)
        )
        for tsn: UInt32 in 11...13 {
            try state.admit(contentsOf: [chunk(tsn)], at: 0)
        }
        _ = try state.outboundChunks(
            nowMillis: 0,
            trigger: .application
        ).get()
        _ = try state.outboundChunks(
            nowMillis: 50,
            trigger: .acknowledgment
        ).get()

        _ = state.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 2, end: 2)],
            receivedMillis: 60
        )
        _ = state.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 2, end: 3)],
            receivedMillis: 70
        )
        _ = state.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 2, end: 4)],
            receivedMillis: 80
        )

        #expect(state.cwnd == 5_840)
    }

    @Test("FORWARD-TSN timeout applies congestion response without ACK credit")
    func forwardTimeoutAdjustsCongestionWindow() throws {
        var state = RetransmissionState(initialTSN: 10)
        let chunk = SCTPDataChunk(
            tsn: 10,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53,
            userData: [0xE2]
        )
        try state.admit(
            contentsOf: [chunk],
            at: 0,
            reliability: .expiresAtMillis(100)
        )
        _ = try state.outboundChunks(
            nowMillis: 0,
            trigger: .application
        ).get()
        _ = try state.outboundChunks(
            nowMillis: 100,
            trigger: .timer
        ).get()
        #expect(state.cwnd == 4_380)
        #expect(try state.pendingForwardTSN(
            nowMillis: 100,
            force: false
        ).get() != nil)
        #expect(try state.pendingForwardTSN(
            nowMillis: 3_100,
            force: false
        ).get() != nil)
        #expect(state.cwnd == 1_460)
        #expect(state.currentRTOMillis == 6_000)

        _ = state.acknowledge(
            cumulativeTSN: 10,
            gapBlocks: [],
            receivedMillis: 3_101
        )
        #expect(state.cwnd == 1_460)
    }

    @Test("Single-packet compatibility send rolls back multi-packet protocol progress")
    func singlePacketCompatibilitySendIsTransactional() throws {
        var pair = try establishPair()
        _ = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xF0],
            unordered: false,
            reliability: .maximumLifetimeMilliseconds(100),
            nowMillis: 5
        )

        do {
            _ = try pair.client.sendData(
                streamID: 0,
                payloadProtocolIdentifier: 53,
                data: [0xF1],
                unordered: false,
                nowMillis: 105
            )
            Issue.record("Single-packet API accepted a two-packet protocol batch")
        } catch let error {
            guard case .sendRequiresPacketBatchForProtocolProgress(
                packetCount: 2
            ) = error else {
                Issue.record("Unexpected single-packet compatibility error: \(error)")
                return
            }
        }

        let canonical = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xF1],
            unordered: false,
            nowMillis: 105
        )
        #expect(canonical.count == 2)
        #expect(try forwardTSN(in: canonical).newCumulativeTSN == 100)
        let data = try #require(dataChunks(in: canonical).first)
        #expect(data.tsn == 101)
        #expect(data.streamSequenceNumber == 1)
    }
}
