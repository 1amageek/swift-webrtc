/// Regression tests for SCTP association packet processing,
/// retransmission, and reassembly limits.

import Testing
import Foundation
@testable import WebRTC
@Suite("SCTP Association Tests")
struct SCTPAssociationTests {

    /// Run the full 4-way handshake between two associations
    private func establishPair() throws -> (client: SCTPAssociation, server: SCTPAssociation) {
        let client = SCTPAssociation()
        let server = SCTPAssociation()

        let initPacket = client.generateInit()
        let (initAckResponses, _) = try server.processPacket(initPacket)
        let initAck = try #require(initAckResponses.first)

        let (cookieEchoResponses, _) = try client.processPacket(initAck)
        let cookieEcho = try #require(cookieEchoResponses.first)

        let (cookieAckResponses, _) = try server.processPacket(cookieEcho)
        let cookieAck = try #require(cookieAckResponses.first)

        _ = try client.processPacket(cookieAck)
        return (client, server)
    }

    @Test("Full 4-way handshake establishes both sides")
    func fullHandshakeEstablishes() throws {
        let (client, server) = try establishPair()
        #expect(client.state == .established)
        #expect(server.state == .established)
    }

    @Test("Packet with wrong verification tag is rejected")
    func verificationTagMismatchThrows() throws {
        let (client, server) = try establishPair()

        let valid = try client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: Data("hello".utf8)
        )
        let spoofed = SCTPPacket(
            sourcePort: valid.sourcePort,
            destinationPort: valid.destinationPort,
            verificationTag: valid.verificationTag &+ 1,
            chunks: valid.chunks
        )

        #expect(throws: SCTPError.self) {
            _ = try server.processPacket(spoofed)
        }
    }

    @Test("Out-of-the-blue INIT with a nonzero tag gets a reflected ABORT")
    func initPacketRequiresZeroTag() throws {
        let server = SCTPAssociation()
        let initChunk = SCTPInitChunk(initiateTag: 0x1234, initialTSN: 1)
        let packet = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5000,
            verificationTag: 0xDEADBEEF,
            chunks: [initChunk.toChunk()]
        )

        let (responses, received) = try server.processPacket(packet)
        let response = try #require(responses.first)
        let abort = try #require(response.chunks.first)
        #expect(received.isEmpty)
        #expect(response.verificationTag == 0xDEADBEEF)
        #expect(abort.chunkType == SCTPChunkType.abort.rawValue)
        #expect(abort.flags & 0x01 == 0x01)
        #expect(server.state == .closed)
    }

    @Test("ABORT closes the association and surfaces an error")
    func abortClosesAssociation() throws {
        let (client, server) = try establishPair()

        // Reuse a valid packet's tag so the ABORT passes tag validation
        let valid = try client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: Data("x".utf8)
        )
        let abort = SCTPPacket(
            sourcePort: valid.sourcePort,
            destinationPort: valid.destinationPort,
            verificationTag: valid.verificationTag,
            chunks: [try SCTPChunk(chunkType: SCTPChunkType.abort.rawValue, value: Data())]
        )

        #expect(throws: SCTPError.self) {
            _ = try server.processPacket(abort)
        }
        #expect(server.state == .closed)
    }

    @Test("Multiple DATA chunks in one packet produce exactly one SACK")
    func singleSackPerPacket() throws {
        let (client, server) = try establishPair()

        let p1 = try client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("a".utf8))
        let p2 = try client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("b".utf8))
        let bundled = SCTPPacket(
            sourcePort: p1.sourcePort,
            destinationPort: p1.destinationPort,
            verificationTag: p1.verificationTag,
            chunks: p1.chunks + p2.chunks
        )

        let (responses, received) = try server.processPacket(bundled)

        let sackCount = responses.reduce(0) { count, packet in
            count + packet.chunks.filter { $0.chunkType == SCTPChunkType.sack.rawValue }.count
        }
        #expect(sackCount == 1)
        #expect(received.count == 2)
        #expect(received[0].data == Data("a".utf8))
        #expect(received[1].data == Data("b".utf8))
    }

    @Test("SACK advertises a window reduced by buffered fragment bytes")
    func sackAdvertisesDynamicWindow() throws {
        let (client, server) = try establishPair()

        // Learn a valid TSN/tag by letting the client build a normal packet,
        // then replace its DATA chunk with a beginning-only fragment that
        // the server must hold in its reassembly buffer.
        let payload = Data(repeating: 0x42, count: 1000)
        let valid = try client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: payload)
        let originalChunk = try #require(valid.chunks.first)
        let original = try SCTPDataChunk.decode(from: originalChunk.value, flags: originalChunk.flags)

        let fragment = SCTPDataChunk(
            tsn: original.tsn,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53,
            userData: payload,
            beginningFragment: true,
            endingFragment: false
        )
        let packet = SCTPPacket(
            sourcePort: valid.sourcePort,
            destinationPort: valid.destinationPort,
            verificationTag: valid.verificationTag,
            chunks: [try fragment.toChunk()]
        )

        let (responses, received) = try server.processPacket(packet)
        #expect(received.isEmpty)

        let sackChunk = try #require(responses
            .flatMap(\.chunks)
            .first { $0.chunkType == SCTPChunkType.sack.rawValue })
        let sack = try SCTPSackChunk.decode(from: sackChunk.value)
        #expect(
            sack.advertisedReceiverWindowCredit
                == UInt32(FragmentReassembler.defaultMaxBufferedBytes - 1000)
        )
    }

    @Test("SACK acknowledgment clears the retransmission queue")
    func sackClearsRetransmissionQueue() throws {
        let (client, server) = try establishPair()

        let dataPacket = try client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: Data("payload".utf8)
        )
        #expect(client.hasUnacknowledgedData)

        let (responses, _) = try server.processPacket(dataPacket)
        let sack = try #require(responses.first)
        _ = try client.processPacket(sack)

        #expect(!client.hasUnacknowledgedData)
    }

    @Test("Out-of-the-blue SACK produces a reflected-tag ABORT")
    func closedSackProducesReflectedAbort() throws {
        let association = SCTPAssociation(localPort: 5000, remotePort: 6000)
        let reflectedTag: UInt32 = 0xDEAD_BEEF
        let sack = try SCTPChunk(
            chunkType: SCTPChunkType.sack.rawValue,
            value: Data()
        )
        let packet = SCTPPacket(
            sourcePort: 6000,
            destinationPort: 5000,
            verificationTag: reflectedTag,
            chunks: [sack]
        )

        let (responses, received) = try association.processPacket(packet)
        let response = try #require(responses.first)
        let abort = try #require(response.chunks.first)

        #expect(responses.count == 1)
        #expect(received.isEmpty)
        #expect(association.state == .closed)
        #expect(response.sourcePort == 5000)
        #expect(response.destinationPort == 6000)
        #expect(response.verificationTag == reflectedTag)
        #expect(abort.chunkType == SCTPChunkType.abort.rawValue)
        #expect(abort.flags & 0x01 == 0x01)
    }

    @Test("Out-of-the-blue packet containing ABORT and SACK is discarded")
    func closedAbortAndSackAreDiscarded() throws {
        let association = SCTPAssociation()
        let abort = try SCTPChunk(
            chunkType: SCTPChunkType.abort.rawValue,
            value: Data()
        )
        let sack = try SCTPChunk(
            chunkType: SCTPChunkType.sack.rawValue,
            value: Data()
        )
        let packet = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5000,
            verificationTag: 0x1234_5678,
            chunks: [abort, sack]
        )

        let (responses, received) = try association.processPacket(packet)

        #expect(responses.isEmpty)
        #expect(received.isEmpty)
        #expect(association.state == .closed)
    }

    @Test("COOKIE-WAIT discards malformed SACK before decoding")
    func cookieWaitDiscardsMalformedSack() throws {
        let association = SCTPAssociation()
        let initPacket = association.generateInit()
        let initChunk = try SCTPInitChunk.decode(from: initPacket.chunks[0].value)
        let malformedSack = try SCTPChunk(
            chunkType: SCTPChunkType.sack.rawValue,
            value: Data()
        )
        let packet = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5000,
            verificationTag: initChunk.initiateTag,
            chunks: [malformedSack]
        )

        let (responses, received) = try association.processPacket(packet)

        #expect(responses.isEmpty)
        #expect(received.isEmpty)
        #expect(association.state == .cookieWait)
    }

    @Test("ESTABLISHED processes SACK and reports malformed input")
    func establishedRejectsMalformedSack() throws {
        let (client, server) = try establishPair()
        let validHeader = try server.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: Data("header".utf8)
        )
        let malformedSack = try SCTPChunk(
            chunkType: SCTPChunkType.sack.rawValue,
            value: Data()
        )
        let packet = SCTPPacket(
            sourcePort: validHeader.sourcePort,
            destinationPort: validHeader.destinationPort,
            verificationTag: validHeader.verificationTag,
            chunks: [malformedSack]
        )

        #expect(throws: SCTPError.self) {
            _ = try client.processPacket(packet)
        }
        #expect(client.state == .established)
    }

    @Test("Unknown chunk with upper bits 00 stops packet processing")
    func unknownChunkStopAction() throws {
        let (client, server) = try establishPair()

        // Chunk type 0x3F: upper two bits 00 → stop processing this packet.
        // The DATA chunk bundled after it must NOT be processed (no SACK).
        let valid = try client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("x".utf8))
        let unknown = try SCTPChunk(chunkType: 0x3F, value: Data())
        let packet = SCTPPacket(
            sourcePort: valid.sourcePort,
            destinationPort: valid.destinationPort,
            verificationTag: valid.verificationTag,
            chunks: [unknown] + valid.chunks
        )

        let (responses, received) = try server.processPacket(packet)
        #expect(responses.isEmpty)
        #expect(received.isEmpty)
    }

    @Test("Unknown chunk with upper bits 11 is skipped, rest is processed")
    func unknownChunkSkipAction() throws {
        let (client, server) = try establishPair()

        // Chunk type 0xFF: upper bits 11 → report, skip, and continue.
        let valid = try client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("x".utf8))
        let unknown = try SCTPChunk(chunkType: 0xFF, flags: 0xA5, value: Data([0x01]))
        let packet = SCTPPacket(
            sourcePort: valid.sourcePort,
            destinationPort: valid.destinationPort,
            verificationTag: valid.verificationTag,
            chunks: [unknown] + valid.chunks
        )

        let (responses, received) = try server.processPacket(packet)
        #expect(received.count == 1)
        let sackCount = responses.reduce(0) { count, packet in
            count + packet.chunks.filter { $0.chunkType == SCTPChunkType.sack.rawValue }.count
        }
        let errors = responses.flatMap(\.chunks).filter {
            $0.chunkType == SCTPChunkType.error.rawValue
        }
        #expect(sackCount == 1)
        let cause = try SCTPUnrecognizedChunkErrorCause.decode(from: #require(errors.first))
        #expect(errors.count == 1)
        #expect(cause.unrecognizedChunk.chunkType == 0xFF)
        #expect(cause.unrecognizedChunk.flags == 0xA5)
        #expect(cause.unrecognizedChunk.value == [0x01])
    }

    @Test("Unknown chunk with upper bits 01 reports and stops")
    func unknownChunkReportStopAction() throws {
        let (client, server) = try establishPair()
        let valid = try client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: Data("x".utf8)
        )
        let unknown = try SCTPChunk(chunkType: 0x7F, value: Data([0x02]))
        let packet = SCTPPacket(
            sourcePort: valid.sourcePort,
            destinationPort: valid.destinationPort,
            verificationTag: valid.verificationTag,
            chunks: [unknown] + valid.chunks
        )

        let (responses, received) = try server.processPacket(packet)
        let chunks = responses.flatMap(\.chunks)
        let error = try #require(chunks.first)
        let cause = try SCTPUnrecognizedChunkErrorCause.decode(from: error)

        #expect(received.isEmpty)
        #expect(chunks.count == 1)
        #expect(cause.unrecognizedChunk.chunkType == 0x7F)
        #expect(cause.unrecognizedChunk.value == [0x02])
    }

    @Test("Unknown chunk with upper bits 10 skips without reporting")
    func unknownChunkSkipWithoutReportAction() throws {
        let (client, server) = try establishPair()
        let valid = try client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: Data("x".utf8)
        )
        let unknown = try SCTPChunk(chunkType: 0xBF, value: Data([0x03]))
        let packet = SCTPPacket(
            sourcePort: valid.sourcePort,
            destinationPort: valid.destinationPort,
            verificationTag: valid.verificationTag,
            chunks: [unknown] + valid.chunks
        )

        let (responses, received) = try server.processPacket(packet)
        let chunks = responses.flatMap(\.chunks)

        #expect(received.count == 1)
        #expect(chunks.filter { $0.chunkType == SCTPChunkType.sack.rawValue }.count == 1)
        #expect(chunks.allSatisfy { $0.chunkType != SCTPChunkType.error.rawValue })
    }

    @Test("INIT unknown parameter action 00 stops without reporting")
    func initUnknownParameterStopAction() throws {
        try verifyInitParameterAction(
            type: 0x3FFE,
            expectsReport: false,
            expectsFollowingParameterProcessing: false
        )
    }

    @Test("INIT unknown parameter action 01 reports and stops")
    func initUnknownParameterReportStopAction() throws {
        try verifyInitParameterAction(
            type: 0x7FFE,
            expectsReport: true,
            expectsFollowingParameterProcessing: false
        )
    }

    @Test("INIT unknown parameter action 10 skips without reporting")
    func initUnknownParameterSkipAction() throws {
        try verifyInitParameterAction(
            type: 0xBFFE,
            expectsReport: false,
            expectsFollowingParameterProcessing: true
        )
    }

    @Test("INIT unknown parameter action 11 reports and continues")
    func initUnknownParameterReportContinueAction() throws {
        try verifyInitParameterAction(
            type: 0xFFFE,
            expectsReport: true,
            expectsFollowingParameterProcessing: true
        )
    }

    @Test("INIT-ACK unknown parameter action 00 stops without reporting")
    func initAckUnknownParameterStopAction() throws {
        try verifyInitAckParameterAction(
            type: 0x3FFE,
            expectsReport: false,
            expectsFollowingParameterProcessing: false
        )
    }

    @Test("INIT-ACK unknown parameter action 01 reports and stops")
    func initAckUnknownParameterReportStopAction() throws {
        try verifyInitAckParameterAction(
            type: 0x7FFE,
            expectsReport: true,
            expectsFollowingParameterProcessing: false
        )
    }

    @Test("INIT-ACK unknown parameter action 10 skips without reporting")
    func initAckUnknownParameterSkipAction() throws {
        try verifyInitAckParameterAction(
            type: 0xBFFE,
            expectsReport: false,
            expectsFollowingParameterProcessing: true
        )
    }

    @Test("INIT-ACK unknown parameter action 11 reports and continues")
    func initAckUnknownParameterReportContinueAction() throws {
        try verifyInitAckParameterAction(
            type: 0xFFFE,
            expectsReport: true,
            expectsFollowingParameterProcessing: true
        )
    }

    @Test("INIT-ACK stop actions still echo a mandatory cookie after the unknown parameter")
    func initAckStopActionsFindFollowingCookie() throws {
        try verifyInitAckParameterAction(
            type: 0x3FFE,
            expectsReport: false,
            expectsFollowingParameterProcessing: false,
            cookiePrecedesUnknown: false
        )
        try verifyInitAckParameterAction(
            type: 0x7FFE,
            expectsReport: true,
            expectsFollowingParameterProcessing: false,
            cookiePrecedesUnknown: false
        )
    }

    @Test("Unrecognized parameter codecs preserve complete TLVs and padding")
    func unrecognizedParameterCodecsRoundTrip() throws {
        let first = unknownParameter(type: 0x7FFE, value: [0xA1])
        let second = unknownParameter(type: 0xFFFE, value: [0xB1, 0xB2])

        let encoded = try SCTPUnrecognizedParameter(
            unrecognizedParameter: first
        ).encodeParameterBytes()
        #expect(encoded.count == 12)
        #expect(encoded[0..<4] == [0x00, 0x08, 0x00, 0x09])
        let decoded = try SCTPUnrecognizedParameter.decode(
            from: encoded,
            offset: 0,
            length: 9
        )
        #expect(decoded.unrecognizedParameter == first)

        let chunk = try SCTPUnrecognizedParametersErrorCause(
            unrecognizedParameters: [first, second]
        ).toChunk()
        let cause = try SCTPUnrecognizedParametersErrorCause.decode(
            from: chunk
        )
        #expect(cause.unrecognizedParameters == [first, second])
    }

    private func verifyInitParameterAction(
        type: UInt16,
        expectsReport: Bool,
        expectsFollowingParameterProcessing: Bool
    ) throws {
        let client = SCTPAssociation()
        let server = SCTPAssociation()
        let generated = client.generateInit()
        let fixedFields = Array(try #require(generated.chunks.first).value.prefix(16))
        let unknown = unknownParameter(type: type, value: [0xA5])

        var value = fixedFields
        appendPadded(unknown, to: &value)
        value.append(contentsOf: try SCTPSupportedExtensionsParameter(
            chunkTypes: [SCTPChunkType.reConfig.rawValue]
        ).encodeParameterBytes())
        let packet = SCTPPacket(
            sourcePort: generated.sourcePort,
            destinationPort: generated.destinationPort,
            verificationTag: generated.verificationTag,
            chunks: [try SCTPChunk(
                chunkType: SCTPChunkType.initChunk.rawValue,
                value: value
            )]
        )

        let (initAckResponses, _) = try server.processPacket(packet)
        let initAck = try #require(initAckResponses.first)
        let initAckChunk = try #require(initAck.chunks.first)
        let reports = try unrecognizedParameterReports(in: initAckChunk)
        #expect(reports == (expectsReport ? [unknown] : []))

        let (cookieEchoResponses, _) = try client.processPacket(initAck)
        let cookieEcho = try #require(cookieEchoResponses.first)
        let (cookieAckResponses, _) = try server.processPacket(cookieEcho)
        let cookieAck = try #require(cookieAckResponses.first)
        _ = try client.processPacket(cookieAck)

        #expect(
            server.supportsStreamReconfiguration
                == expectsFollowingParameterProcessing
        )
    }

    private func verifyInitAckParameterAction(
        type: UInt16,
        expectsReport: Bool,
        expectsFollowingParameterProcessing: Bool,
        cookiePrecedesUnknown: Bool = true
    ) throws {
        let client = SCTPAssociation()
        let generated = client.generateInit()
        let generatedInit = try SCTPInitChunk.decode(
            from: try #require(generated.chunks.first).value
        )
        let unknown = unknownParameter(type: type, value: [0xC5])

        var value = SCTPInitChunk(
            initiateTag: 0x2222_2222,
            advertisedReceiverWindowCredit: 64 * 1_024,
            numberOfOutboundStreams: 32,
            numberOfInboundStreams: 32,
            initialTSN: 200
        ).encodeBytes()
        let cookie = stateCookieParameter([0x10, 0x20, 0x30, 0x40])
        if cookiePrecedesUnknown {
            appendPadded(cookie, to: &value)
            appendPadded(unknown, to: &value)
        } else {
            appendPadded(unknown, to: &value)
            appendPadded(cookie, to: &value)
        }
        value.append(contentsOf: try SCTPSupportedExtensionsParameter(
            chunkTypes: [SCTPChunkType.reConfig.rawValue]
        ).encodeParameterBytes())

        let packet = SCTPPacket(
            sourcePort: generated.sourcePort,
            destinationPort: generated.destinationPort,
            verificationTag: generatedInit.initiateTag,
            chunks: [try SCTPChunk(
                chunkType: SCTPChunkType.initAck.rawValue,
                value: value
            )]
        )
        let (responses, _) = try client.processPacket(packet)
        let response = try #require(responses.first)

        #expect(responses.count == 1)
        #expect(
            response.encodedByteCount
                <= SCTPAssociationLimits.defaultMaximumPacketByteCount
        )
        #expect(response.chunks.first?.chunkType == SCTPChunkType.cookieEcho.rawValue)
        #expect(
            client.supportsStreamReconfiguration
                == expectsFollowingParameterProcessing
        )

        let errorChunks = response.chunks.filter {
            $0.chunkType == SCTPChunkType.error.rawValue
        }
        if expectsReport {
            let error = try #require(errorChunks.first)
            let cause = try SCTPUnrecognizedParametersErrorCause.decode(
                from: error
            )
            #expect(errorChunks.count == 1)
            #expect(cause.unrecognizedParameters == [unknown])
        } else {
            #expect(errorChunks.isEmpty)
        }
    }

    private func unknownParameter(
        type: UInt16,
        value: [UInt8]
    ) -> [UInt8] {
        let length = UInt16(4 + value.count)
        return [
            UInt8(type >> 8),
            UInt8(type & 0xFF),
            UInt8(length >> 8),
            UInt8(length & 0xFF),
        ] + value
    }

    private func stateCookieParameter(_ cookie: [UInt8]) -> [UInt8] {
        let length = UInt16(4 + cookie.count)
        return [
            0x00,
            0x07,
            UInt8(length >> 8),
            UInt8(length & 0xFF),
        ] + cookie
    }

    private func appendPadded(
        _ parameter: [UInt8],
        to bytes: inout [UInt8]
    ) {
        bytes.append(contentsOf: parameter)
        while (bytes.count & 3) != 0 {
            bytes.append(0)
        }
    }

    private func unrecognizedParameterReports(
        in initAck: SCTPChunk
    ) throws -> [[UInt8]] {
        let value = initAck.value
        var reports: [[UInt8]] = []
        var offset = 16
        while offset < value.count {
            let type = UInt16(value[offset]) << 8
                | UInt16(value[offset + 1])
            let length = Int(UInt16(value[offset + 2]) << 8
                | UInt16(value[offset + 3]))
            if type == SCTPUnrecognizedParameter.parameterType {
                reports.append(try SCTPUnrecognizedParameter.decode(
                    from: value,
                    offset: offset,
                    length: length
                ).unrecognizedParameter)
            }
            let end = offset + length
            offset = end == value.count ? end : offset + ((length + 3) & ~3)
        }
        return reports
    }

    @Test("Local initiate tag is never zero")
    func initiateTagNonZero() {
        for _ in 0..<100 {
            #expect(SCTPSecureRandom.uint32NonZero() != 0)
        }
    }

    // MARK: - COOKIE-ECHO retransmission

    /// Drive INIT/INIT-ACK and capture the client's COOKIE-ECHO packet.
    private func cookieEcho(client: SCTPAssociation, server: SCTPAssociation) throws -> SCTPPacket {
        let initPacket = client.generateInit()
        let (initAckResponses, _) = try server.processPacket(initPacket)
        let initAck = try #require(initAckResponses.first)
        let (cookieEchoResponses, _) = try client.processPacket(initAck)
        return try #require(cookieEchoResponses.first)
    }

    @Test("Retransmitted COOKIE-ECHO receives another COOKIE-ACK")
    func retransmittedCookieEchoIsAcknowledged() throws {
        let client = SCTPAssociation()
        let server = SCTPAssociation()

        let cookieEcho = try cookieEcho(client: client, server: server)

        // First COOKIE-ECHO establishes the server.
        let (firstResponses, _) = try server.processPacket(cookieEcho)
        #expect(firstResponses.contains { $0.chunks.contains { $0.chunkType == SCTPChunkType.cookieAck.rawValue } })
        #expect(server.state == .established)

        // COOKIE-ACK might have been lost. RFC 9260 Table 12 Action D requires
        // another COOKIE-ACK without replacing the established TCB.
        let (retransmitResponses, retransmitData) = try server.processPacket(cookieEcho)
        #expect(retransmitResponses.contains {
            $0.chunks.contains { $0.chunkType == SCTPChunkType.cookieAck.rawValue }
        })
        #expect(retransmitData.isEmpty)
        #expect(server.state == .established)
    }

    @Test("Invalid COOKIE-ECHO MAC is silently discarded without TCB mutation")
    func invalidCookieMACIsSilentlyDiscarded() throws {
        let client = SCTPAssociation()
        let server = SCTPAssociation()
        let cookieEcho = try cookieEcho(client: client, server: server)
        let originalChunk = try #require(cookieEcho.chunks.first)
        var tamperedValue = originalChunk.value
        tamperedValue[tamperedValue.count - 1] ^= 0x01
        let tamperedChunk = try SCTPChunk(
            chunkType: originalChunk.chunkType,
            flags: originalChunk.flags,
            value: Data(tamperedValue)
        )
        let tamperedPacket = SCTPPacket(
            sourcePort: cookieEcho.sourcePort,
            destinationPort: cookieEcho.destinationPort,
            verificationTag: cookieEcho.verificationTag,
            chunks: [tamperedChunk]
        )

        let (responses, receivedData) = try server.processPacket(tamperedPacket)
        #expect(responses.isEmpty)
        #expect(receivedData.isEmpty)
        #expect(server.state != .established)
    }

    // MARK: - Finding 3: INIT while established does not reset TSN tracking

    @Test("INIT while established does not reset TSN tracking or tags")
    func initWhileEstablishedPreservesState() throws {
        let (client, server) = try establishPair()

        // Push one DATA chunk so the server's TSN tracker has advanced.
        let dataPacket = try client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("hi".utf8))
        let (sackResponses, received) = try server.processPacket(dataPacket)
        #expect(received.count == 1)
        let sackBefore = try #require(sackResponses
            .flatMap(\.chunks)
            .first { $0.chunkType == SCTPChunkType.sack.rawValue })
        let cumulativeBefore = try SCTPSackChunk.decode(from: sackBefore.value).cumulativeTSNAck

        // A fresh INIT (tag 0) arrives while the server is established.
        let foreignInit = SCTPInitChunk(initiateTag: 0x7777_7777, initialTSN: 999_999)
        let initPacket = SCTPPacket(
            sourcePort: 5000, destinationPort: 5000,
            verificationTag: 0, chunks: [foreignInit.toChunk()])
        let (initAckResponses, _) = try server.processPacket(initPacket)
        // Server still replies with an INIT-ACK (RFC 4960 §5.2.2) ...
        #expect(initAckResponses.contains { $0.chunks.contains { $0.chunkType == SCTPChunkType.initAck.rawValue } })
        // ... but stays established and keeps its TSN tracking.
        #expect(server.state == .established)

        // Another DATA from the original peer is still SACKed against the
        // unchanged cumulative TSN line (tracker was not reset to 999_998).
        let data2 = try client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("yo".utf8))
        let (sackResponses2, received2) = try server.processPacket(data2)
        #expect(received2.count == 1)
        let sackAfter = try #require(sackResponses2
            .flatMap(\.chunks)
            .first { $0.chunkType == SCTPChunkType.sack.rawValue })
        let cumulativeAfter = try SCTPSackChunk.decode(from: sackAfter.value).cumulativeTSNAck
        #expect(cumulativeAfter == cumulativeBefore &+ 1)
    }

    // MARK: - Finding 5: out-of-range stream IDs rejected

    @Test("DATA for a stream ID beyond the negotiated count is rejected")
    func dataBeyondNegotiatedStreamsRejected() throws {
        // Server accepts only 4 inbound streams; client opens 4 outbound.
        let client = SCTPAssociation(maxInboundStreams: 4, maxOutboundStreams: 4)
        let server = SCTPAssociation(maxInboundStreams: 4, maxOutboundStreams: 4)

        let initPacket = client.generateInit()
        let (initAckResponses, _) = try server.processPacket(initPacket)
        let initAck = try #require(initAckResponses.first)
        let (cookieEchoResponses, _) = try client.processPacket(initAck)
        let cookieEcho = try #require(cookieEchoResponses.first)
        let (cookieAckResponses, _) = try server.processPacket(cookieEcho)
        let cookieAck = try #require(cookieAckResponses.first)
        _ = try client.processPacket(cookieAck)

        // Stream 0 (< 4) is accepted.
        let ok = try client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("a".utf8))
        let (_, received) = try server.processPacket(ok)
        #expect(received.count == 1)

        // Stream 9 (>= negotiated 4) must be rejected. Build a DATA chunk on
        // stream 9 reusing the valid tag.
        let bad = SCTPDataChunk(
            tsn: 100, streamIdentifier: 9, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: Data("x".utf8))
        let badPacket = SCTPPacket(
            sourcePort: ok.sourcePort, destinationPort: ok.destinationPort,
            verificationTag: ok.verificationTag, chunks: [try bad.toChunk()])

        #expect(throws: SCTPError.self) {
            _ = try server.processPacket(badPacket)
        }
    }

    // MARK: - Finding 7: max retransmits aborts the association

    @Test("Exceeding max retransmits transitions the association to closed")
    func maxRetransmitsClosesAssociation() throws {
        let (client, _) = try establishPair()
        #expect(client.state == .established)

        // Send one chunk so there is something to retransmit.
        _ = try client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("p".utf8))

        // Drive timer-based retransmissions with an injected clock that jumps
        // far past any RTO (max 60s) each tick, guaranteeing expiry. After
        // maxRetransmit (10) retransmissions the queue reports failure and the
        // association must transition to closed (RFC 4960 §8.2).
        var now = ContinuousClock.now
        var sawFailure = false
        for _ in 0..<20 {
            now = now + .seconds(120)
            switch client.pollOutboundPackets(now: now) {
            case .success:
                continue
            case .failure:
                sawFailure = true
            }
            if sawFailure { break }
        }
        #expect(sawFailure)
        #expect(client.state == .closed)
    }

    // MARK: - Finding 13: malformed INIT-ACK TLV is rejected

    @Test("INIT-ACK with a sub-minimum parameter length is rejected")
    func initAckBadParameterLengthRejected() throws {
        let client = SCTPAssociation()
        // The INIT carries the client's local verification tag as initiateTag;
        // the INIT-ACK must echo that same tag to pass tag validation.
        let initPacket = client.generateInit() // moves client to cookieWait
        let initChunk = try SCTPInitChunk.decode(from: initPacket.chunks[0].value)
        let clientLocalTag = initChunk.initiateTag

        // INIT-ACK value: 16 fixed bytes + a malformed parameter whose declared
        // length (2) is below the 4-byte minimum (RFC 4960 §3.2.1).
        var value = SCTPInitChunk(initiateTag: 0x1111_1111, initialTSN: 1).encode()
        value.append(contentsOf: [0x00, 0x07]) // type = State Cookie
        value.append(contentsOf: [0x00, 0x02]) // length = 2 (invalid)
        let chunk = try SCTPChunk(chunkType: SCTPChunkType.initAck.rawValue, value: value)
        let packet = SCTPPacket(
            sourcePort: 5000, destinationPort: 5000,
            verificationTag: clientLocalTag, chunks: [chunk])

        #expect(throws: SCTPError.self) {
            _ = try client.processPacket(packet)
        }
    }

    // MARK: - Finding 8: forged reflected-tag ABORT must not tear down

    @Test("Forged ABORT bearing the peer's own (reflected) tag does not tear down the association")
    func forgedReflectedTagAbortIgnored() throws {
        let (_, server) = try establishPair()
        #expect(server.state == .established)

        // A packet the SERVER sends carries verificationTag ==
        // server.remoteVerificationTag, i.e. the peer's (client's) own tag.
        // That tag travels in cleartext, so an off-path attacker who sniffs one
        // datagram can read it and forge an ABORT reflecting it. This reflected
        // tag must NOT be accepted as authoritative for tearing down a live
        // association (origin authenticity comes from the verified DTLS layer).
        let serverPacket = try server.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("p".utf8))
        let reflectedPeerTag = serverPacket.verificationTag

        let forgedAbort = SCTPPacket(
            sourcePort: serverPacket.sourcePort,
            destinationPort: serverPacket.destinationPort,
            verificationTag: reflectedPeerTag,
            chunks: [try SCTPChunk(chunkType: SCTPChunkType.abort.rawValue, value: Data())])

        // Verification-tag validation rejects it (it is not our local tag and
        // reflected-tag ABORTs are no longer accepted), so the association
        // stays established.
        #expect(throws: SCTPError.self) {
            _ = try server.processPacket(forgedAbort)
        }
        #expect(server.state == .established)
    }

    @Test("Legitimate ABORT bearing our local tag still tears down the association")
    func legitimateAbortStillWorks() throws {
        let (client, server) = try establishPair()

        // A real peer aborting uses OUR local verification tag (learned during
        // the handshake). A packet the client sends carries exactly that tag.
        let clientPacket = try client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("x".utf8))
        let abort = SCTPPacket(
            sourcePort: clientPacket.sourcePort,
            destinationPort: clientPacket.destinationPort,
            verificationTag: clientPacket.verificationTag,
            chunks: [try SCTPChunk(chunkType: SCTPChunkType.abort.rawValue, value: Data())])

        #expect(throws: SCTPError.self) {
            _ = try server.processPacket(abort)
        }
        #expect(server.state == .closed)
    }
}

@Suite("Retransmission Queue Tests")
struct RetransmissionQueueTests {

    private func makeChunk(tsn: UInt32) -> SCTPDataChunk {
        SCTPDataChunk(
            tsn: tsn,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53,
            userData: Data("payload".utf8)
        )
    }

    @Test("Three SACK miss indications trigger fast retransmit")
    func fastRetransmitAfterThreeMisses() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now

        for tsn: UInt32 in 10...13 {
            try queue.enqueue(makeChunk(tsn: tsn), sentTime: sentTime)
        }

        // Each SACK newly acknowledges a higher TSN while TSN 10 remains the
        // same hole. RFC 4960 §7.2.4 increments miss indications against the
        // Highest TSN Newly Acknowledged, not repeated identical SACKs.
        _ = queue.acknowledge(cumulativeTSN: 9, gapBlocks: [(start: 2, end: 2)])
        _ = queue.acknowledge(cumulativeTSN: 9, gapBlocks: [(start: 2, end: 3)])
        _ = queue.acknowledge(cumulativeTSN: 9, gapBlocks: [(start: 2, end: 4)])

        // RTO (3s) has not expired, so only the fast-retransmit-marked
        // chunk should be returned
        switch queue.pendingRetransmissions(now: sentTime + .milliseconds(100)) {
        case .success(let chunks):
            #expect(chunks.map(\.tsn) == [10])
        case .failure(let error):
            Issue.record("Unexpected failure: \(error)")
        }
    }

    @Test("Fewer than three miss indications do not retransmit")
    func noFastRetransmitBelowThreshold() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now

        try queue.enqueue(makeChunk(tsn: 10), sentTime: sentTime)
        try queue.enqueue(makeChunk(tsn: 11), sentTime: sentTime)

        for _ in 0..<2 {
            _ = queue.acknowledge(cumulativeTSN: 9, gapBlocks: [(start: 2, end: 2)])
        }

        switch queue.pendingRetransmissions(now: sentTime + .milliseconds(100)) {
        case .success(let chunks):
            #expect(chunks.isEmpty)
        case .failure(let error):
            Issue.record("Unexpected failure: \(error)")
        }
    }

    @Test("Timer expiry retransmits and backs off RTO once per event")
    func timerExpiryBacksOffOnce() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now

        try queue.enqueue(makeChunk(tsn: 10), sentTime: sentTime)
        try queue.enqueue(makeChunk(tsn: 11), sentTime: sentTime)

        let initialRTO = queue.currentRTO
        switch queue.pendingRetransmissions(now: sentTime + initialRTO + .milliseconds(1)) {
        case .success(let chunks):
            // The timeout marks both chunks but RFC 9260 §7.2.3 permits one
            // physical packet until its acknowledgment advances recovery.
            #expect(chunks.map(\.tsn) == [10])
            // One path-level timeout doubles RTO once, not once per chunk.
            #expect(queue.currentRTO == initialRTO * 2)
        case .failure(let error):
            Issue.record("Unexpected failure: \(error)")
        }
    }

    private func makeChunk(tsn: UInt32, size: Int) -> SCTPDataChunk {
        SCTPDataChunk(
            tsn: tsn, streamIdentifier: 0, streamSequenceNumber: UInt16(truncatingIfNeeded: tsn),
            payloadProtocolIdentifier: 53, userData: Data(repeating: 0x5A, count: size))
    }

    // MARK: - Finding 6: send-window backpressure

    @Test("Enqueue beyond the send-window ceiling throws typed backpressure")
    func enqueueBackpressureThrows() throws {
        var queue = RetransmissionQueue()
        let now = ContinuousClock.now
        // Default ceiling is 1 MiB; enqueue ~1 MiB worth then expect the next
        // large chunk to be refused.
        var tsn: UInt32 = 0
        // 1 MiB / 64 KiB = 16 chunks fill it exactly.
        for _ in 0..<16 {
            try queue.enqueue(makeChunk(tsn: tsn, size: 64 * 1024), sentTime: now)
            tsn += 1
        }
        #expect(throws: SCTPError.self) {
            try queue.enqueue(makeChunk(tsn: tsn, size: 1), sentTime: now)
        }
    }

    @Test("Re-enqueueing the same TSN does not double-count bytes")
    func reEnqueueDoesNotDoubleCount() throws {
        var queue = RetransmissionQueue()
        let now = ContinuousClock.now
        try queue.enqueue(makeChunk(tsn: 1, size: 1000), sentTime: now)
        #expect(queue.bytesInFlight == 1000)
        // Same TSN again (e.g. a re-send) must not add another 1000.
        try queue.enqueue(makeChunk(tsn: 1, size: 1000), sentTime: now)
        #expect(queue.bytesInFlight == 1000)
    }

    // MARK: - Finding 6: bytesInFlight underflow guard

    @Test("Double cumulative ack does not underflow bytesInFlight")
    func doubleAckNoUnderflow() throws {
        var queue = RetransmissionQueue()
        let now = ContinuousClock.now
        try queue.enqueue(makeChunk(tsn: 1, size: 500), sentTime: now)
        try queue.enqueue(makeChunk(tsn: 2, size: 500), sentTime: now)
        #expect(queue.bytesInFlight == 1000)

        _ = queue.acknowledge(cumulativeTSN: 2, gapBlocks: [])
        #expect(queue.bytesInFlight == 0)
        // Re-acknowledging the same cumulative TSN must keep it at 0, not wrap.
        _ = queue.acknowledge(cumulativeTSN: 2, gapBlocks: [])
        #expect(queue.bytesInFlight == 0)
    }

    // MARK: - Finding 6: retransmission burst clamped to cwnd

    @Test("Retransmission burst is bounded by the collapsed cwnd")
    func retransmitBurstClampedToCwnd() throws {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now

        // Enqueue several MTU-sized chunks. On timer expiry cwnd collapses to
        // one MTU (1460), so the burst must carry at least one but far fewer
        // than all of them.
        for tsn: UInt32 in 0..<10 {
            try queue.enqueue(makeChunk(tsn: tsn, size: 1000), sentTime: sentTime)
        }

        let rto = queue.currentRTO
        switch queue.pendingRetransmissions(now: sentTime + rto + .milliseconds(1)) {
        case .success(let chunks):
            // cwnd collapses to 1460; first chunk always sent, second pushes
            // budget to 2000 > 1460 so it is deferred — exactly one chunk.
            #expect(chunks.count == 1)
            #expect(chunks.first?.tsn == 0)
        case .failure(let error):
            Issue.record("Unexpected failure: \(error)")
        }
    }
}

@Suite("Fragment Assembler Limit Tests")
struct FragmentAssemblerLimitTests {

    private func beginningFragment(tsn: UInt32, streamID: UInt16, seq: UInt16) -> SCTPDataChunk {
        SCTPDataChunk(
            tsn: tsn,
            streamIdentifier: streamID,
            streamSequenceNumber: seq,
            payloadProtocolIdentifier: 53,
            userData: Data("frag".utf8),
            beginningFragment: true,
            endingFragment: false
        )
    }

    @Test("Pending fragment group cap is enforced")
    func pendingGroupCapThrows() throws {
        var assembler = FragmentAssembler()

        // Fill to the cap with incomplete (beginning-only) groups.
        // Non-contiguous TSNs prevent accidental assembly.
        for i in 0..<1000 {
            _ = try assembler.process(
                chunk: beginningFragment(tsn: UInt32(i) * 2, streamID: 0, seq: UInt16(i % 65536))
            )
        }
        #expect(assembler.pendingCount == 1000)

        #expect(throws: SCTPError.self) {
            _ = try assembler.process(
                chunk: beginningFragment(tsn: 5000, streamID: 1, seq: 0)
            )
        }
    }

    @Test("Out-of-order unordered fragments still assemble")
    func outOfOrderUnorderedFragmentsAssemble() throws {
        var assembler = FragmentAssembler()
        let payload = Data("part".utf8)

        // Ending fragment arrives before the beginning fragment
        let end = SCTPDataChunk(
            tsn: 11, streamIdentifier: 0, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload,
            beginningFragment: false, endingFragment: true, unordered: true
        )
        let begin = SCTPDataChunk(
            tsn: 10, streamIdentifier: 0, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload,
            beginningFragment: true, endingFragment: false, unordered: true
        )

        let first = try assembler.process(chunk: end)
        #expect(first.isEmpty)

        let assembled = try assembler.process(chunk: begin)
        #expect(assembled.count == 1)
        #expect(assembled.first?.data == payload + payload)
    }

    @Test("bufferedBytes tracks incomplete fragments and drains on assembly")
    func bufferedBytesTracksFragments() throws {
        var assembler = FragmentAssembler()
        let payload = Data(repeating: 0xAB, count: 500)

        let begin = SCTPDataChunk(
            tsn: 10, streamIdentifier: 0, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload,
            beginningFragment: true, endingFragment: false
        )
        _ = try assembler.process(chunk: begin)
        #expect(assembler.bufferedBytes == 500)

        let end = SCTPDataChunk(
            tsn: 11, streamIdentifier: 0, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload,
            beginningFragment: false, endingFragment: true
        )
        let assembled = try assembler.process(chunk: end)
        #expect(assembled.count == 1)
        #expect(assembler.bufferedBytes == 0)
    }

    @Test("bufferedBytes tracks out-of-order messages and drains on delivery")
    func bufferedBytesTracksReorderBuffer() throws {
        var assembler = FragmentAssembler()
        let payload = Data(repeating: 0xCD, count: 300)

        // Sequence 1 arrives before expected sequence 0 — buffered
        _ = try assembler.process(chunk: SCTPDataChunk(
            tsn: 11, streamIdentifier: 0, streamSequenceNumber: 1,
            payloadProtocolIdentifier: 53, userData: payload
        ))
        #expect(assembler.bufferedBytes == 300)

        // Sequence 0 arrives — both deliver, buffer drains
        let delivered = try assembler.process(chunk: SCTPDataChunk(
            tsn: 10, streamIdentifier: 0, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload
        ))
        #expect(delivered.count == 2)
        #expect(assembler.bufferedBytes == 0)
    }

    @Test("resetStream releases buffered bytes")
    func resetStreamReleasesBufferedBytes() throws {
        var assembler = FragmentAssembler()
        let payload = Data(repeating: 0xEF, count: 400)

        _ = try assembler.process(chunk: SCTPDataChunk(
            tsn: 10, streamIdentifier: 7, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload,
            beginningFragment: true, endingFragment: false
        ))
        _ = try assembler.process(chunk: SCTPDataChunk(
            tsn: 20, streamIdentifier: 7, streamSequenceNumber: 5,
            payloadProtocolIdentifier: 53, userData: payload
        ))
        #expect(assembler.bufferedBytes == 800)

        assembler.resetStream(7)
        #expect(assembler.bufferedBytes == 0)
    }

    @Test("Per-stream reorder buffer cap is enforced")
    func reorderBufferCapThrows() throws {
        var assembler = FragmentAssembler()

        // Stream expects sequence 0; sequences 1...1024 are all out of
        // order, filling the reorder buffer to its cap
        for seq in 1...1024 {
            _ = try assembler.process(chunk: SCTPDataChunk(
                tsn: UInt32(seq),
                streamIdentifier: 0,
                streamSequenceNumber: UInt16(seq),
                payloadProtocolIdentifier: 53,
                userData: Data("m".utf8)
            ))
        }

        #expect(throws: SCTPError.self) {
            _ = try assembler.process(chunk: SCTPDataChunk(
                tsn: 2000, streamIdentifier: 0, streamSequenceNumber: 1500,
                payloadProtocolIdentifier: 53, userData: Data("m".utf8)
            ))
        }
    }

    // MARK: - Finding 2: total byte ceiling

    @Test("Total buffered-byte ceiling is enforced for incomplete fragments")
    func bufferedByteCeilingThrowsForFragments() throws {
        // Small ceiling so the test stays fast and deterministic.
        var assembler = FragmentAssembler(maxBufferedBytes: 1000)
        let payload = Data(repeating: 0xAB, count: 400)

        // Two 400-byte beginning-only fragments fit (800 <= 1000).
        _ = try assembler.process(chunk: SCTPDataChunk(
            tsn: 10, streamIdentifier: 0, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload,
            beginningFragment: true, endingFragment: false))
        _ = try assembler.process(chunk: SCTPDataChunk(
            tsn: 20, streamIdentifier: 1, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload,
            beginningFragment: true, endingFragment: false))
        #expect(assembler.bufferedBytes == 800)

        // A third 400-byte fragment would push past 1000 — reject it.
        #expect(throws: SCTPError.self) {
            _ = try assembler.process(chunk: SCTPDataChunk(
                tsn: 30, streamIdentifier: 2, streamSequenceNumber: 0,
                payloadProtocolIdentifier: 53, userData: payload,
                beginningFragment: true, endingFragment: false))
        }
        // The rejected fragment's bytes are not retained.
        #expect(assembler.bufferedBytes == 800)
    }

    @Test("Total byte ceiling is enforced for out-of-order ordered messages")
    func bufferedByteCeilingThrowsForReorderBuffer() throws {
        var assembler = FragmentAssembler(maxBufferedBytes: 1000)
        let payload = Data(repeating: 0xCD, count: 400)

        // Two out-of-order (seq > expected) single-chunk messages fit (800).
        _ = try assembler.process(chunk: SCTPDataChunk(
            tsn: 11, streamIdentifier: 0, streamSequenceNumber: 1,
            payloadProtocolIdentifier: 53, userData: payload))
        _ = try assembler.process(chunk: SCTPDataChunk(
            tsn: 12, streamIdentifier: 0, streamSequenceNumber: 2,
            payloadProtocolIdentifier: 53, userData: payload))
        #expect(assembler.bufferedBytes == 800)

        // A third would exceed 1000 — reject.
        #expect(throws: SCTPError.self) {
            _ = try assembler.process(chunk: SCTPDataChunk(
                tsn: 13, streamIdentifier: 0, streamSequenceNumber: 3,
                payloadProtocolIdentifier: 53, userData: payload))
        }
        #expect(assembler.bufferedBytes == 800)
    }
}

@Suite("TSN Tracker Tests")
struct TSNTrackerTests {

    // MARK: - Finding 2: out-of-order TSN cap

    @Test("Out-of-order TSN set is capped")
    func outOfOrderTSNCapEnforced() {
        var tracker = TSNTracker(initialTSN: 1)
        // cumulative starts at 0; TSN 1 is the next expected. Withhold it and
        // flood sparse out-of-order TSNs above it. Only up to the internal cap
        // (512) should be retained as gaps rather than tens of thousands.
        for tsn in stride(from: UInt32(3), through: 3 + 2 * 2000, by: 2) {
            _ = tracker.receive(tsn: tsn)
        }
        #expect(tracker.gapSize <= 512)
        #expect(tracker.gapSize > 0)
    }

    @Test("Gap blocks computed correctly from sorted out-of-order TSNs")
    func gapBlocksFromSortedEntries() {
        var tracker = TSNTracker(initialTSN: 1)
        // cumulative = 0; deliver 1 (advances cumulative to 1), then gaps.
        #expect(tracker.receive(tsn: 1) == true)
        // Out of order: 3,4 (block), 6 (block) — 2 and 5 are missing.
        #expect(tracker.receive(tsn: 4) == true)
        #expect(tracker.receive(tsn: 3) == true)
        #expect(tracker.receive(tsn: 6) == true)

        let blocks = tracker.gapBlocks
        // Offsets relative to cumulative (1): 3->2, 4->3, 6->5
        #expect(blocks.count == 2)
        #expect(blocks[0] == (2, 3))
        #expect(blocks[1] == (5, 5))
    }

    @Test("Filling the gap advances the cumulative TSN")
    func gapFillAdvancesCumulative() {
        var tracker = TSNTracker(initialTSN: 1)
        #expect(tracker.receive(tsn: 1) == true)
        #expect(tracker.cumulativeTSN == 1)
        #expect(tracker.receive(tsn: 3) == true) // buffer (gap at 2)
        #expect(tracker.cumulativeTSN == 1)
        #expect(tracker.receive(tsn: 2) == true) // fill — cumulative jumps to 3
        #expect(tracker.cumulativeTSN == 3)
        #expect(!tracker.hasGaps)
    }

    @Test("Duplicate out-of-order TSN is reported, not re-buffered")
    func duplicateOutOfOrderReported() {
        var tracker = TSNTracker(initialTSN: 1)
        #expect(tracker.receive(tsn: 1) == true)
        #expect(tracker.receive(tsn: 3) == true)
        #expect(tracker.receive(tsn: 3) == false) // duplicate
        #expect(tracker.gapSize == 1)
        #expect(tracker.takeDuplicates() == [3])
    }
}
