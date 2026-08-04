import Testing
@testable import WebRTC

@Suite("SCTP DATA Fragmentation Tests")
struct SCTPFragmentationTests {
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

        #expect(client.state == .established)
        #expect(server.state == .established)
        return (client, server)
    }

    private func payload(byteCount: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        for index in bytes.indices {
            bytes[index] = UInt8(truncatingIfNeeded: index)
        }
        return bytes
    }

    private func decodedDataChunk(
        in packet: SCTPPacket
    ) throws -> SCTPDataChunk {
        let chunk = try #require(packet.chunks.first)
        #expect(chunk.chunkType == SCTPChunkType.data.rawValue)
        return try chunk.decodedDataChunk()
    }

    private func storageAddress(_ bytes: [UInt8]) -> UInt {
        bytes.withUnsafeBufferPointer { buffer in
            guard let baseAddress = buffer.baseAddress else { return 0 }
            return UInt(bitPattern: baseAddress)
        }
    }

    private func deliver(
        _ packets: [SCTPPacket],
        to server: inout Engine,
        startingAt nowMillis: UInt64
    ) throws -> [SCTPReceivedMessage] {
        var messages: [SCTPReceivedMessage] = []
        messages.reserveCapacity(1)
        for (index, packet) in packets.enumerated() {
            let encoded = packet.encodeBytes()
            #expect(encoded.count == packet.encodedByteCount)
            #expect(encoded.count <= Engine.defaultMaximumPacketByteCount)
            let decoded = try SCTPPacket.decode(from: encoded)
            let decodedChunk = try decodedDataChunk(in: decoded)
            #expect(storageAddress(decodedChunk.userDataView.owner) == storageAddress(encoded))
            let result = try server.processPacketWithEvents(
                decoded,
                nowMillis: nowMillis + UInt64(index)
            )
            messages.append(contentsOf: result.receivedData)
        }
        return messages
    }

    private func exchangeWithFlowControl(
        initialPackets: [SCTPPacket],
        client: inout Engine,
        server: inout Engine,
        startingAt nowMillis: UInt64
    ) throws -> (packets: [SCTPPacket], messages: [SCTPReceivedMessage]) {
        var pendingPackets = initialPackets
        var allPackets = initialPackets
        var messages: [SCTPReceivedMessage] = []
        messages.reserveCapacity(1)
        var packetIndex = 0
        var eventMillis = nowMillis

        while packetIndex < pendingPackets.count {
            try #require(packetIndex < 10_000)
            let packet = pendingPackets[packetIndex]
            packetIndex += 1

            let encoded = packet.encodeBytes()
            #expect(encoded.count == packet.encodedByteCount)
            #expect(encoded.count <= Engine.defaultMaximumPacketByteCount)
            let decoded = try SCTPPacket.decode(from: encoded)
            let decodedChunk = try decodedDataChunk(in: decoded)
            #expect(storageAddress(decodedChunk.userDataView.owner) == storageAddress(encoded))

            let receiverResult = try server.processPacketWithEvents(
                decoded,
                nowMillis: eventMillis
            )
            eventMillis += 1
            messages.append(contentsOf: receiverResult.receivedData)

            for acknowledgment in receiverResult.responses {
                let encodedAcknowledgment = acknowledgment.encodeBytes()
                let decodedAcknowledgment = try SCTPPacket.decode(
                    from: encodedAcknowledgment
                )
                let senderResult = try client.processPacketWithEvents(
                    decodedAcknowledgment,
                    nowMillis: eventMillis
                )
                eventMillis += 1

                for response in senderResult.responses {
                    _ = try decodedDataChunk(in: response)
                    pendingPackets.append(response)
                    allPackets.append(response)
                }
            }
        }

        try #require(!client.hasUnacknowledgedData)
        return (allPackets, messages)
    }

    @Test(
        "UInt16 DATA boundary fragments without trapping and preserves B/E/TSN/SSN",
        .timeLimit(.minutes(1))
    )
    func uint16BoundaryRoundTrip() throws {
        var pair = try establishPair()
        var expectedFirstTSN: UInt32 = 100

        for (messageIndex, byteCount) in [65_519, 65_520].enumerated() {
            let expected = payload(byteCount: byteCount)
            let initialPackets = try pair.client.sendDataPackets(
                streamID: 0,
                payloadProtocolIdentifier: 53,
                data: expected,
                unordered: false,
                nowMillis: 10 + UInt64(messageIndex)
            )

            #expect(initialPackets.count == 4)
            let exchange = try exchangeWithFlowControl(
                initialPackets: initialPackets,
                client: &pair.client,
                server: &pair.server,
                startingAt: 100 + UInt64(messageIndex * 1_000)
            )
            let packets = exchange.packets
            #expect(packets.count > 1)
            let chunks = try packets.map { try decodedDataChunk(in: $0) }
            let expectedOwnerAddress = storageAddress(expected)
            #expect(chunks.allSatisfy {
                storageAddress($0.userDataView.owner) == expectedOwnerAddress
            })
            let firstChunk = try #require(chunks.first)
            let lastChunk = try #require(chunks.last)
            #expect(firstChunk.flags & 0x02 != 0)
            #expect(firstChunk.flags & 0x01 == 0)
            #expect(lastChunk.flags & 0x02 == 0)
            #expect(lastChunk.flags & 0x01 != 0)
            #expect(chunks.allSatisfy { $0.flags & 0x04 == 0 })
            #expect(chunks.allSatisfy {
                $0.streamSequenceNumber == UInt16(messageIndex)
            })
            for (fragmentIndex, chunk) in chunks.enumerated() {
                #expect(chunk.tsn == expectedFirstTSN &+ UInt32(fragmentIndex))
            }

            let delivered = exchange.messages
            #expect(delivered.count == 1)
            #expect(delivered.first?.data == expected)
            expectedFirstTSN &+= UInt32(chunks.count)
        }
    }

    @Test(
        "One MiB message round-trips as one delivery within the MTU budget",
        .timeLimit(.minutes(1))
    )
    func oneMiBRoundTrip() throws {
        var pair = try establishPair()
        let expected = payload(byteCount: 1 * 1_024 * 1_024)

        let initialPackets = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: expected,
            unordered: true,
            nowMillis: 10
        )
        #expect(initialPackets.count == 4)

        let exchange = try exchangeWithFlowControl(
            initialPackets: initialPackets,
            client: &pair.client,
            server: &pair.server,
            startingAt: 100
        )
        let packets = exchange.packets
        #expect(packets.count > 1)

        let chunks = try packets.map { try decodedDataChunk(in: $0) }
        #expect(chunks.allSatisfy { $0.streamSequenceNumber == 0 })
        #expect(chunks.allSatisfy { $0.flags & 0x04 != 0 })

        let delivered = exchange.messages
        #expect(delivered.count == 1)
        #expect(delivered.first?.data == expected)
    }

    @Test("Caller packet budget controls fragment sizing")
    func customPacketBudgetRoundTrip() throws {
        var pair = try establishPair()
        let expected = payload(byteCount: 1_000)
        let maximumPacketByteCount = 256

        let initialPackets = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: expected,
            unordered: false,
            nowMillis: 10,
            maximumPacketByteCount: maximumPacketByteCount
        )

        #expect(initialPackets.count == 4)
        let exchange = try exchangeWithFlowControl(
            initialPackets: initialPackets,
            client: &pair.client,
            server: &pair.server,
            startingAt: 100
        )
        let packets = exchange.packets
        #expect(packets.count == 5)
        #expect(packets.allSatisfy {
            $0.encodedByteCount <= maximumPacketByteCount
        })
        let delivered = exchange.messages
        #expect(delivered.count == 1)
        #expect(delivered.first?.data == expected)
    }

    @Test("Invalid packet budget fails before TSN or SSN state changes")
    func invalidPacketBudgetIsAtomic() throws {
        var pair = try establishPair()

        do {
            _ = try pair.client.sendDataPackets(
                streamID: 0,
                payloadProtocolIdentifier: 53,
                data: [0xAA],
                unordered: false,
                nowMillis: 10,
                maximumPacketByteCount: 31
            )
            Issue.record("Expected typed packet-budget validation failure")
        } catch {
            guard case .invalidMaximumPacketByteCount(let actual, let minimum) = error else {
                Issue.record("Unexpected SCTP error: \(error)")
                return
            }
            #expect(actual == 31)
            #expect(minimum == 32)
        }

        let packet = try pair.client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xBB],
            unordered: false,
            nowMillis: 11
        )
        let chunk = try decodedDataChunk(in: packet)
        #expect(chunk.tsn == 100)
        #expect(chunk.streamSequenceNumber == 0)
    }

    @Test("Batch admission failure leaves TSN and SSN unchanged")
    func batchFailureIsAtomic() throws {
        var pair = try establishPair()
        let oversized = payload(byteCount: 1 * 1_024 * 1_024 + 1)

        do {
            _ = try pair.client.sendDataPackets(
                streamID: 0,
                payloadProtocolIdentifier: 53,
                data: oversized,
                unordered: false,
                nowMillis: 10
            )
            Issue.record("Expected typed retransmission-window backpressure")
        } catch {
            guard case .sendQueueFull(let bytesInFlight, let limit) = error else {
                Issue.record("Unexpected SCTP error: \(error)")
                return
            }
            #expect(bytesInFlight == 0)
            #expect(limit == 1 * 1_024 * 1_024)
        }

        let packet = try pair.client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xAA],
            unordered: false,
            nowMillis: 11
        )
        let chunk = try decodedDataChunk(in: packet)
        #expect(chunk.tsn == 100)
        #expect(chunk.streamSequenceNumber == 0)
    }

    @Test("Legacy single-packet API rejects fragmentation without committing state")
    func legacyAPIRejectsLargeMessageWithoutTrap() throws {
        var pair = try establishPair()
        let large = payload(byteCount: 65_520)

        do {
            _ = try pair.client.sendData(
                streamID: 0,
                payloadProtocolIdentifier: 53,
                data: large,
                unordered: false,
                nowMillis: 10
            )
            Issue.record("Expected packet-batch requirement")
        } catch {
            guard case .messageRequiresPacketBatch(
                let payloadByteCount,
                let maximumSinglePacketPayloadByteCount
            ) = error else {
                Issue.record("Unexpected SCTP error: \(error)")
                return
            }
            #expect(payloadByteCount == large.count)
            #expect(maximumSinglePacketPayloadByteCount == 1_172)
        }

        let packet = try pair.client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xBB],
            unordered: false,
            nowMillis: 11
        )
        let chunk = try decodedDataChunk(in: packet)
        #expect(chunk.tsn == 100)
        #expect(chunk.streamSequenceNumber == 0)
    }

    @Test("DATA send requires ESTABLISHED and a negotiated outbound stream")
    func sendStateAndStreamValidationIsAtomic() throws {
        var unestablished = makeEngine(
            initiateTag: 0x3333_3333,
            initialTSN: 300
        )
        do {
            _ = try unestablished.sendDataPackets(
                streamID: 0,
                payloadProtocolIdentifier: 53,
                data: [0xAA],
                unordered: false,
                nowMillis: 1
            )
            Issue.record("Expected pre-establishment DATA send rejection")
        } catch {
            guard case .invalidState = error else {
                Issue.record("Unexpected SCTP error: \(error)")
                return
            }
        }

        var pair = try establishPair()
        do {
            _ = try pair.client.sendDataPackets(
                streamID: 32,
                payloadProtocolIdentifier: 53,
                data: [0xBB],
                unordered: false,
                nowMillis: 10
            )
            Issue.record("Expected negotiated stream validation failure")
        } catch {
            guard case .invalidStreamIdentifier(let streamID, let negotiated) = error else {
                Issue.record("Unexpected SCTP error: \(error)")
                return
            }
            #expect(streamID == 32)
            #expect(negotiated == 32)
        }

        let packet = try pair.client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xCC],
            unordered: false,
            nowMillis: 11
        )
        let chunk = try decodedDataChunk(in: packet)
        #expect(chunk.tsn == 100)
        #expect(chunk.streamSequenceNumber == 0)
    }

    @Test("Consecutive unordered fragmented messages remain distinct when reordered")
    func unorderedFragmentBoundariesSurviveReordering() throws {
        var pair = try establishPair()
        let first = Array(UInt8(0xA0)...UInt8(0xAB))
        let second = Array(UInt8(0xB0)...UInt8(0xBB))

        let firstPackets = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: first,
            unordered: true,
            nowMillis: 10,
            maximumPacketByteCount: 32
        )
        let secondPackets = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: second,
            unordered: true,
            nowMillis: 11,
            maximumPacketByteCount: 32
        )
        #expect(firstPackets.count == 3)
        #expect(secondPackets.count == 3)

        let chunks = try (firstPackets + secondPackets).map {
            try decodedDataChunk(in: $0)
        }
        #expect(chunks.allSatisfy { $0.streamSequenceNumber == 0 })

        let reordered = [
            firstPackets[1],
            secondPackets[0],
            secondPackets[1],
            firstPackets[2],
            firstPackets[0],
            secondPackets[2],
        ]
        let delivered = try deliver(
            reordered,
            to: &pair.server,
            startingAt: 100
        )
        #expect(delivered.count == 2)
        #expect(Set(delivered.map(\.data)) == Set([first, second]))
    }

    @Test("Cleanup retains future ordered fragments across a TSN gap")
    func orderedFutureFragmentsSurviveCleanup() throws {
        var pair = try establishPair()
        let expected = Array(UInt8(0xC0)...UInt8(0xCB))
        let packets = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: expected,
            unordered: false,
            nowMillis: 10,
            maximumPacketByteCount: 32
        )
        #expect(packets.count == 3)

        // TSN 101 and 102 are ahead of cumulative TSN 99. Cleanup must not
        // interpret wrapping subtraction as a very old fragment age.
        let delivered = try deliver(
            [packets[1], packets[2], packets[0]],
            to: &pair.server,
            startingAt: 100
        )
        #expect(delivered.count == 1)
        #expect(delivered.first?.data == expected)
    }

    @Test("Oversized generic and DATA chunks fail with typed wire errors")
    func oversizedChunkConstructionIsTyped() throws {
        let oversizedValue = payload(byteCount: Int(UInt16.max) - 3)
        do {
            _ = try SCTPChunk(
                chunkType: SCTPChunkType.heartbeat.rawValue,
                value: oversizedValue
            )
            Issue.record("Expected the generic chunk length bound to fail")
        } catch {
            guard case .chunkValueTooLarge(let actual, let maximum) = error else {
                Issue.record("Unexpected wire error: \(error)")
                return
            }
            #expect(actual == 65_532)
            #expect(maximum == 65_531)
        }

        let oversizedData = SCTPDataChunk(
            tsn: 1,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53,
            userData: payload(byteCount: 65_520)
        )
        do {
            _ = try oversizedData.toChunk()
            Issue.record("Expected the DATA chunk length bound to fail")
        } catch {
            guard case .chunkValueTooLarge(let actual, let maximum) = error else {
                Issue.record("Unexpected wire error: \(error)")
                return
            }
            #expect(actual == 65_532)
            #expect(maximum == 65_531)
        }
    }

    @Test("Pre-establishment DATA is discarded without receive-state mutation")
    func preEstablishmentDataDoesNotAdvanceTSN() throws {
        var client = makeEngine(
            initiateTag: 0x1111_1111,
            initialTSN: 100
        )
        var server = makeEngine(
            initiateTag: 0x2222_2222,
            initialTSN: 200
        )

        let initPacket = client.generateInit()
        let initAck = try #require(server.processPacketWithEvents(
            initPacket,
            nowMillis: 1
        ).responses.first)
        let cookieEcho = try #require(client.processPacketWithEvents(
            initAck,
            nowMillis: 2
        ).responses.first)
        #expect(client.state == .cookieEchoed)

        let earlyData = SCTPDataChunk(
            tsn: 200,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53,
            userData: [0xEA]
        )
        let earlyPacket = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5000,
            verificationTag: 0x1111_1111,
            chunks: [try earlyData.toChunk()]
        )
        let earlyResult = try client.processPacketWithEvents(
            earlyPacket,
            nowMillis: 3
        )
        #expect(earlyResult.responses.isEmpty)
        #expect(earlyResult.events.isEmpty)
        #expect(client.state == .cookieEchoed)

        let cookieAck = try #require(server.processPacketWithEvents(
            cookieEcho,
            nowMillis: 4
        ).responses.first)
        _ = try client.processPacketWithEvents(cookieAck, nowMillis: 5)
        #expect(client.state == .established)

        let validPacket = try server.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xEB],
            unordered: false,
            nowMillis: 6
        )
        let validChunk = try decodedDataChunk(in: validPacket)
        #expect(validChunk.tsn == 200)
        let validResult = try client.processPacketWithEvents(
            validPacket,
            nowMillis: 7
        )
        #expect(validResult.receivedData.count == 1)
        #expect(validResult.receivedData.first?.data == [0xEB])
    }
}
