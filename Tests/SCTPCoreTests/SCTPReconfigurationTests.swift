import Testing
@testable import WebRTC
@Suite("SCTP Reconfiguration Wire Tests")
struct SCTPReconfigurationWireTests {
    @Test("Odd stream list length excludes enclosing chunk padding")
    func oddStreamListLengthAndPadding() throws {
        let request = SCTPOutgoingSSNResetRequest(
            requestSequenceNumber: 0x0102_0304,
            responseSequenceNumber: 0x0506_0708,
            senderLastAssignedTSN: 0x090A_0B0C,
            streamIDs: [0x1234]
        )
        let chunk = try SCTPReconfigurationChunk(
            parameters: [.outgoingSSNReset(request)]
        ).toChunk()

        #expect(chunk.value.count == 18)
        #expect(chunk.length == 22)
        #expect(chunk.encodeBytes().count == 24)
        #expect(chunk.value[2] == 0)
        #expect(chunk.value[3] == 18)

        let flagged = try SCTPChunk(
            chunkType: chunk.chunkType,
            flags: 0xFF,
            value: chunk.value
        )
        let decoded = try SCTPReconfigurationChunk.decode(from: flagged)
        #expect(decoded.parameters == [.outgoingSSNReset(request)])
    }

    @Test("Two request parameters use only inter-parameter padding")
    func twoRequestParameterPadding() throws {
        let outgoing = SCTPOutgoingSSNResetRequest(
            requestSequenceNumber: 10,
            responseSequenceNumber: 9,
            senderLastAssignedTSN: 20,
            streamIDs: [3]
        )
        let incoming = SCTPIncomingSSNResetRequest(
            requestSequenceNumber: 11,
            streamIDs: [3]
        )
        let chunk = try SCTPReconfigurationChunk(parameters: [
            .outgoingSSNReset(outgoing),
            .incomingSSNReset(incoming),
        ]).toChunk()

        #expect(chunk.value.count == 30)
        #expect(Array(chunk.value[18..<20]) == [0, 0])
        #expect(chunk.length == 34)
        #expect(chunk.encodeBytes().count == 36)

        let decoded = try SCTPReconfigurationChunk.decode(from: chunk)
        #expect(decoded.parameters == [
            .outgoingSSNReset(outgoing),
            .incomingSSNReset(incoming),
        ])
    }

    @Test("Response parameter requires either zero or two optional TSNs")
    func responseLengths() throws {
        let short = SCTPReconfigurationResponse(
            responseSequenceNumber: 7,
            result: .successPerformed
        )
        let long = SCTPReconfigurationResponse(
            responseSequenceNumber: 8,
            result: .successNothingToDo,
            senderNextTSN: 100,
            receiverNextTSN: 200
        )

        #expect(try short.encodeParameterBytes().count == 12)
        #expect(try long.encodeParameterBytes().count == 20)
        #expect(throws: SCTPWireError.self) {
            _ = try SCTPReconfigurationResponse(
                responseSequenceNumber: 9,
                result: .successPerformed,
                senderNextTSN: 100
            ).encodeParameterBytes()
        }
    }

    @Test("Unsupported two-parameter ordering is rejected")
    func invalidCombinationRejected() {
        let request = SCTPOutgoingSSNResetRequest(
            requestSequenceNumber: 1,
            responseSequenceNumber: 0,
            senderLastAssignedTSN: 1,
            streamIDs: []
        )
        let response = SCTPReconfigurationResponse(
            responseSequenceNumber: 1,
            result: .denied
        )

        #expect(throws: SCTPWireError.self) {
            _ = try SCTPReconfigurationChunk(parameters: [
                .outgoingSSNReset(request),
                .response(response),
            ]).toChunk()
        }
    }

    @Test("Supported Extensions parameter preserves advertised chunk IDs")
    func supportedExtensionsRoundTrip() throws {
        let parameter = SCTPSupportedExtensionsParameter(chunkTypes: [130, 192])
        let bytes = try parameter.encodeParameterBytes()

        #expect(bytes == [0x80, 0x08, 0x00, 0x06, 130, 192])
        #expect(try SCTPSupportedExtensionsParameter.decode(
            from: bytes,
            offset: 0,
            length: bytes.count
        ) == parameter)
    }

    @Test("Stream selection canonicalizes all and duplicate IDs")
    func streamSelectionCanonicalization() {
        #expect(SCTPStreamSelection.listed([]) == .all)
        #expect(SCTPStreamSelection.listed([4, 2, 4]).wireStreamIDs == [2, 4])
        #expect(SCTPStreamSelection.all.contains(UInt16.max))
    }
}

@Suite("SCTP Reconfiguration State Tests")
struct SCTPReconfigurationStateTests {
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
            cookieSecretKey: Array(repeating: UInt8(truncatingIfNeeded: initiateTag), count: 32),
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

        #expect(client.state == .established)
        #expect(server.state == .established)
        #expect(client.supportsStreamReconfiguration)
        #expect(server.supportsStreamReconfiguration)
        return (client, server)
    }

    private func reconfiguration(
        in packet: SCTPPacket
    ) throws -> SCTPReconfigurationChunk {
        let chunk = try #require(packet.chunks.first {
            $0.chunkType == SCTPChunkType.reConfig.rawValue
        })
        return try SCTPReconfigurationChunk.decode(from: chunk)
    }

    private func resetRequest(
        in packet: SCTPPacket
    ) throws -> SCTPOutgoingSSNResetRequest {
        let decoded = try reconfiguration(in: packet)
        for parameter in decoded.parameters {
            if case .outgoingSSNReset(let request) = parameter {
                return request
            }
        }
        Issue.record("Packet did not contain an outgoing reset request")
        throw SCTPError.invalidFormat("Missing outgoing reset request")
    }

    private func resetResponses(
        in packet: SCTPPacket
    ) throws -> [SCTPReconfigurationResponse] {
        try reconfiguration(in: packet).parameters.compactMap { parameter in
            guard case .response(let response) = parameter else { return nil }
            return response
        }
    }

    @Test("Outgoing reset succeeds without consuming the next TSN")
    func immediateReset() throws {
        var pair = try establishPair()
        let optionalRequestPacket = try pair.client.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 10
        )
        let requestPacket = try #require(optionalRequestPacket)
        let request = try resetRequest(in: requestPacket)
        #expect(request.requestSequenceNumber == 100)
        #expect(request.senderLastAssignedTSN == 99)

        let peerResult = try pair.server.processPacketWithEvents(
            requestPacket,
            nowMillis: 11
        )
        #expect(peerResult.events == [.incomingStreamsReset(.listed([0]))])
        let responsePacket = try #require(peerResult.responses.first)
        #expect(try resetResponses(in: responsePacket).first?.result == .successPerformed)

        let localResult = try pair.client.processPacketWithEvents(
            responsePacket,
            nowMillis: 12
        )
        #expect(localResult.events == [.outgoingStreamsReset(.listed([0]))])

        let dataPacket = try pair.client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [1],
            unordered: false,
            nowMillis: 13
        )
        let data = try SCTPDataChunk.decode(
            from: dataPacket.chunks[0].value,
            flags: dataPacket.chunks[0].flags
        )
        #expect(data.tsn == 100)
        #expect(data.streamSequenceNumber == 0)
    }

    @Test("Reciprocal reset stops retransmission but awaits the explicit result")
    func reciprocalResetAcknowledgesWithoutAssumingSuccess() throws {
        var pair = try establishPair()
        let clientRequest = try #require(try pair.client.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 10
        ))

        let serverResult = try pair.server.processPacketWithEvents(
            clientRequest,
            nowMillis: 11
        )
        #expect(serverResult.events == [.incomingStreamsReset(.listed([0]))])
        let explicitResponse = try #require(serverResult.responses.first)

        // Drop the explicit Re-configuration Response and send the reciprocal
        // request required by the bidirectional WebRTC data-channel close.
        let reciprocal = try #require(try pair.server.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 12
        ))
        let reciprocalRequest = try resetRequest(in: reciprocal)
        #expect(reciprocalRequest.responseSequenceNumber == 100)
        let composite = SCTPPacket(
            sourcePort: reciprocal.sourcePort,
            destinationPort: reciprocal.destinationPort,
            verificationTag: reciprocal.verificationTag,
            chunks: [try SCTPReconfigurationChunk(parameters: [
                .response(SCTPReconfigurationResponse(
                    responseSequenceNumber: 100,
                    result: .inProgress
                )),
                .outgoingSSNReset(reciprocalRequest),
            ]).toChunk()]
        )

        let clientResult = try pair.client.processPacketWithEvents(
            composite,
            nowMillis: 13
        )
        #expect(clientResult.events == [
            .incomingStreamsReset(.listed([0])),
        ])
        #expect(try pair.client.pollOutboundPackets(nowMillis: 120_000).get().isEmpty)

        let explicitCompletion = try pair.client.processPacketWithEvents(
            explicitResponse,
            nowMillis: 13
        )
        #expect(explicitCompletion.events == [.outgoingStreamsReset(.listed([0]))])

        let reciprocalResponse = try #require(clientResult.responses.first)
        let serverCompletion = try pair.server.processPacketWithEvents(
            reciprocalResponse,
            nowMillis: 14
        )
        #expect(serverCompletion.events == [.outgoingStreamsReset(.listed([0]))])
    }

    @Test("In Progress after implicit acknowledgement restarts the response timer")
    func inProgressRestartsTimerAfterImplicitAcknowledgement() throws {
        var pair = try establishPair()
        let clientRequest = try #require(try pair.client.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 10
        ))

        let serverResult = try pair.server.processPacketWithEvents(
            clientRequest,
            nowMillis: 11
        )
        let finalResponse = try #require(serverResult.responses.first)

        let reciprocal = try #require(try pair.server.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 12
        ))
        let implicitResult = try pair.client.processPacketWithEvents(
            reciprocal,
            nowMillis: 13
        )
        #expect(implicitResult.events == [.incomingStreamsReset(.listed([0]))])
        #expect(try pair.client.pollOutboundPackets(
            nowMillis: 120_000
        ).get().isEmpty)

        let inProgressPacket = SCTPPacket(
            sourcePort: finalResponse.sourcePort,
            destinationPort: finalResponse.destinationPort,
            verificationTag: finalResponse.verificationTag,
            chunks: [try SCTPReconfigurationChunk(parameters: [
                .response(SCTPReconfigurationResponse(
                    responseSequenceNumber: 100,
                    result: .inProgress
                )),
            ]).toChunk()]
        )
        let progressResult = try pair.client.processPacketWithEvents(
            inProgressPacket,
            nowMillis: 14
        )
        #expect(progressResult.events.isEmpty)
        #expect(try pair.client.pollOutboundPackets(
            nowMillis: 120_000
        ).get().count == 1)

        let completion = try pair.client.processPacketWithEvents(
            finalResponse,
            nowMillis: 120_001
        )
        #expect(completion.events == [.outgoingStreamsReset(.listed([0]))])
    }

    @Test("Deferred composite reset advances sequence and caches both responses")
    func deferredCompositeResetCache() throws {
        var pair = try establishPair()
        let dataPacket = try pair.client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xAA],
            unordered: false,
            nowMillis: 10
        )
        let optionalResetPacket = try pair.client.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 11
        )
        let originalResetPacket = try #require(optionalResetPacket)
        let outgoing = try resetRequest(in: originalResetPacket)
        let incoming = SCTPIncomingSSNResetRequest(
            requestSequenceNumber: outgoing.requestSequenceNumber &+ 1,
            streamIDs: [0]
        )
        let compositeChunk = try SCTPReconfigurationChunk(parameters: [
            .outgoingSSNReset(outgoing),
            .incomingSSNReset(incoming),
        ]).toChunk()
        let compositePacket = SCTPPacket(
            sourcePort: originalResetPacket.sourcePort,
            destinationPort: originalResetPacket.destinationPort,
            verificationTag: originalResetPacket.verificationTag,
            chunks: [compositeChunk]
        )

        let initial = try pair.server.processPacketWithEvents(
            compositePacket,
            nowMillis: 12
        )
        let initialResponses = try resetResponses(in: #require(initial.responses.first))
        #expect(initialResponses.map(\.result) == [.inProgress, .denied])

        let optionalReciprocal = try pair.server.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 13
        )
        let reciprocal = try #require(optionalReciprocal)
        #expect(try resetRequest(in: reciprocal).responseSequenceNumber == 101)

        let completed = try pair.server.processPacketWithEvents(
            dataPacket,
            nowMillis: 14
        )
        #expect(completed.events == [.incomingStreamsReset(.listed([0]))])
        let finalPacket = try #require(completed.responses.first { packet in
            packet.chunks.contains { $0.chunkType == SCTPChunkType.reConfig.rawValue }
        })
        #expect(try resetResponses(in: finalPacket).map(\.result) == [.successPerformed])

        let duplicate = try pair.server.processPacketWithEvents(
            compositePacket,
            nowMillis: 15
        )
        #expect(duplicate.deliveries.isEmpty)
        let replayed = try #require(duplicate.responses.first)
        #expect(try resetResponses(in: replayed).map(\.result) == [
            .successPerformed,
            .denied,
        ])
    }
}
