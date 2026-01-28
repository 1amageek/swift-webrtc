/// Tests for SCTP Core

import Testing
import Foundation
@testable import SCTPCore

@Suite("SCTP Packet Tests")
struct SCTPPacketTests {

    @Test("SCTP chunk encode/decode roundtrip")
    func chunkRoundtrip() throws {
        let value = Data([0x01, 0x02, 0x03, 0x04])
        let chunk = SCTPChunk(chunkType: SCTPChunkType.data.rawValue, flags: 0x03, value: value)

        let encoded = chunk.encode()
        let decoded = try SCTPChunk.decode(from: encoded)

        #expect(decoded.chunkType == SCTPChunkType.data.rawValue)
        #expect(decoded.flags == 0x03)
        #expect(decoded.value == value)
    }

    @Test("INIT chunk encode/decode")
    func initChunkRoundtrip() throws {
        let initChunk = SCTPInitChunk(
            initiateTag: 0x12345678,
            advertisedReceiverWindowCredit: 65535,
            numberOfOutboundStreams: 10,
            numberOfInboundStreams: 10,
            initialTSN: 1
        )

        let encoded = initChunk.encode()
        let decoded = try SCTPInitChunk.decode(from: encoded)

        #expect(decoded.initiateTag == 0x12345678)
        #expect(decoded.advertisedReceiverWindowCredit == 65535)
        #expect(decoded.numberOfOutboundStreams == 10)
        #expect(decoded.numberOfInboundStreams == 10)
        #expect(decoded.initialTSN == 1)
    }

    @Test("DATA chunk encode/decode")
    func dataChunkRoundtrip() throws {
        let dataChunk = SCTPDataChunk(
            tsn: 42,
            streamIdentifier: 0,
            streamSequenceNumber: 1,
            payloadProtocolIdentifier: 51, // WebRTC String
            userData: Data("hello".utf8)
        )

        let encoded = dataChunk.encode()
        let decoded = try SCTPDataChunk.decode(from: encoded, flags: dataChunk.flags)

        #expect(decoded.tsn == 42)
        #expect(decoded.streamIdentifier == 0)
        #expect(decoded.streamSequenceNumber == 1)
        #expect(decoded.payloadProtocolIdentifier == 51)
        #expect(decoded.userData == Data("hello".utf8))
    }

    @Test("SACK chunk encode/decode")
    func sackChunkRoundtrip() throws {
        let sack = SCTPSackChunk(
            cumulativeTSNAck: 10,
            advertisedReceiverWindowCredit: 65535
        )

        let encoded = sack.encode()
        let decoded = try SCTPSackChunk.decode(from: encoded)

        #expect(decoded.cumulativeTSNAck == 10)
        #expect(decoded.advertisedReceiverWindowCredit == 65535)
    }

    @Test("SCTP packet encode/decode")
    func packetRoundtrip() throws {
        let chunk = SCTPChunk(chunkType: SCTPChunkType.cookieAck.rawValue, value: Data())
        let packet = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5000,
            verificationTag: 0xABCD1234,
            chunks: [chunk]
        )

        let encoded = packet.encode()
        let decoded = try SCTPPacket.decode(from: encoded)

        #expect(decoded.sourcePort == 5000)
        #expect(decoded.destinationPort == 5000)
        #expect(decoded.verificationTag == 0xABCD1234)
        #expect(decoded.chunks.count == 1)
    }

    @Test("SCTP association init")
    func associationInit() {
        let assoc = SCTPAssociation()
        #expect(assoc.state == .closed)

        let initPacket = assoc.generateInit()
        #expect(!initPacket.chunks.isEmpty)
        #expect(assoc.state == .cookieWait)
    }
}
