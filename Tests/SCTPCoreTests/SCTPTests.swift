/// Tests for SCTP Core

import Testing
import Foundation
import P2PCoreBytes
import P2PCoreCrypto
import P2PCrypto
@testable import WebRTC
@Suite("SCTP Packet Tests")
struct SCTPPacketTests {

    @Test("SCTP chunk encode/decode roundtrip")
    func chunkRoundtrip() throws {
        let value = Data([0x01, 0x02, 0x03, 0x04])
        let chunk = try SCTPChunk(chunkType: SCTPChunkType.data.rawValue, flags: 0x03, value: value)

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

        let encoded = try sack.encode()
        let decoded = try SCTPSackChunk.decode(from: encoded)

        #expect(decoded.cumulativeTSNAck == 10)
        #expect(decoded.advertisedReceiverWindowCredit == 65535)
    }

    @Test("SACK construction rejects a value larger than the chunk length field")
    func oversizedSackThrows() {
        let sack = SCTPSackChunk(
            cumulativeTSNAck: 10,
            gapAckBlocks: Array(
                repeating: (start: UInt16(1), end: UInt16(1)),
                count: 16_380
            )
        )

        #expect(throws: SCTPWireError.self) {
            _ = try sack.toChunk()
        }
    }

    @Test("SCTP packet encode/decode")
    func packetRoundtrip() throws {
        let chunk = try SCTPChunk(chunkType: SCTPChunkType.cookieAck.rawValue, value: Data())
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

    @Test("SCTP cookie validates and rejects tampering")
    func sctpCookieValidation() throws {
        let secretKey = Data("01234567890123456789012345678901".utf8)
        let cookie = SCTPCookie.generate(
            secretKey: secretKey,
            peerTag: 0x12345678,
            localTag: 0x9ABCDEF0,
            localTieTag: 0,
            peerTieTag: 0,
            localInitialTSN: 24,
            peerInitialTSN: 42,
            peerARWC: 65535,
            outboundStreams: 8,
            inboundStreams: 8,
            localPort: 5_000,
            peerPort: 5_000
        )

        #expect(cookie.validate(secretKey: secretKey))

        var encoded = cookie.encode()
        encoded[encoded.startIndex] ^= 0xFF
        let tampered = try SCTPCookie.decode(from: encoded)
        #expect(!tampered.validate(secretKey: secretKey))
    }

    @Test("Non-generic cookie crypto matches the former generic HMAC seam")
    func cookieCryptoDifferentialFixture() {
        let secretKey = Array("01234567890123456789012345678901".utf8)
        let timestamp: UInt64 = 0x0102_0304_0506_0708
        let peerTag: UInt32 = 0x1234_5678
        let localTag: UInt32 = 0x9ABC_DEF0
        let localTieTag: UInt32 = 0x0102_0304
        let peerTieTag: UInt32 = 0x0506_0708
        let localInitialTSN: UInt32 = 24
        let peerInitialTSN: UInt32 = 42
        let peerARWC: UInt32 = 65_535
        let outboundStreams: UInt16 = 8
        let inboundStreams: UInt16 = 16
        let extensionFlags: UInt32 = 1
        let localPort: UInt16 = 5_000
        let peerPort: UInt16 = 5_001

        let cookie = SCTPCookieCore.generate(
            secretKey: secretKey,
            timestamp: timestamp,
            peerTag: peerTag,
            localTag: localTag,
            localTieTag: localTieTag,
            peerTieTag: peerTieTag,
            localInitialTSN: localInitialTSN,
            peerInitialTSN: peerInitialTSN,
            peerARWC: peerARWC,
            outboundStreams: outboundStreams,
            inboundStreams: inboundStreams,
            extensionFlags: extensionFlags,
            localPort: localPort,
            peerPort: peerPort,
            crypto: makeSCTPCookieCryptoContext()
        )
        let legacyInput = SCTPCookieCore.signableInput(
            timestamp: timestamp,
            peerTag: peerTag,
            localTag: localTag,
            localTieTag: localTieTag,
            peerTieTag: peerTieTag,
            localInitialTSN: localInitialTSN,
            peerInitialTSN: peerInitialTSN,
            peerARWC: peerARWC,
            outboundStreams: outboundStreams,
            inboundStreams: inboundStreams,
            extensionFlags: extensionFlags,
            localPort: localPort,
            peerPort: peerPort
        )
        let legacyMAC = legacyCookieAuthenticationCode(
            message: legacyInput,
            key: secretKey,
            as: DefaultHMACSHA256.self
        )

        #expect(cookie.hmac == legacyMAC)
        #expect(cookie.validateBinding(
            secretKey: secretKey,
            nowMillis: timestamp,
            maxAgeMillis: 60_000,
            crypto: makeSCTPCookieCryptoContext()
        ))
    }

    // MARK: - Finding 1: zero-length chunk must not loop / OOM

    @Test("Zero-length chunk is rejected by SCTPChunk.decode")
    func zeroLengthChunkRejected() {
        // type=0, flags=0, length=0
        let bytes = Data([0x00, 0x00, 0x00, 0x00])
        #expect(throws: SCTPError.self) {
            _ = try SCTPChunk.decode(from: bytes)
        }
    }

    @Test("Packet with a zero-length chunk terminates without hanging")
    func zeroLengthChunkInPacketTerminates() {
        // 12-byte SCTP common header + 4-byte zero-length chunk = 16 bytes.
        // Verification tag 0 so this isn't rejected as an INIT mismatch first.
        var packet = Data()
        packet.append(contentsOf: [0x13, 0x88, 0x13, 0x88]) // ports
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // verification tag
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // checksum placeholder
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // chunk: type/flags/len=0

        // Must throw (malformed) rather than loop forever building chunks.
        #expect(throws: SCTPError.self) {
            _ = try SCTPPacket.decode(from: packet, validateChecksum: false)
        }
    }

    // MARK: - Finding 14: CRC-32C is mandatory in the default decode path

    @Test("Default decode rejects a packet with a corrupt CRC-32C")
    func decodeRejectsBadChecksum() throws {
        let chunk = try SCTPChunk(chunkType: SCTPChunkType.cookieAck.rawValue, value: Data())
        let packet = SCTPPacket(
            sourcePort: 5000, destinationPort: 5000,
            verificationTag: 0xABCD1234, chunks: [chunk])
        var encoded = packet.encode()

        // Flip a payload bit AFTER the checksum field so the stored CRC no
        // longer matches. The default decode path must reject it.
        let flipIndex = encoded.startIndex + 12
        encoded[flipIndex] ^= 0xFF

        #expect(throws: SCTPError.self) {
            _ = try SCTPPacket.decode(from: encoded)
        }
    }

    @Test("SCTP cookie rejects future timestamp")
    func sctpCookieRejectsFutureTimestamp() throws {
        let secretKey = Data("01234567890123456789012345678901".utf8)
        let cookie = SCTPCookie.generate(
            secretKey: secretKey,
            peerTag: 0x12345678,
            localTag: 0x9ABCDEF0,
            localTieTag: 0,
            peerTieTag: 0,
            localInitialTSN: 24,
            peerInitialTSN: 42,
            peerARWC: 65535,
            outboundStreams: 8,
            inboundStreams: 8,
            localPort: 5_000,
            peerPort: 5_000
        )

        var encoded = cookie.encode()
        let futureTimestamp = cookie.timestamp + 60_000

        encoded[0] = UInt8((futureTimestamp >> 56) & 0xFF)
        encoded[1] = UInt8((futureTimestamp >> 48) & 0xFF)
        encoded[2] = UInt8((futureTimestamp >> 40) & 0xFF)
        encoded[3] = UInt8((futureTimestamp >> 32) & 0xFF)
        encoded[4] = UInt8((futureTimestamp >> 24) & 0xFF)
        encoded[5] = UInt8((futureTimestamp >> 16) & 0xFF)
        encoded[6] = UInt8((futureTimestamp >> 8) & 0xFF)
        encoded[7] = UInt8(futureTimestamp & 0xFF)

        let futureCookie = try SCTPCookie.decode(from: encoded)
        #expect(!futureCookie.validate(secretKey: secretKey))
    }
}

private func legacyCookieAuthenticationCode<MAC: MessageAuthenticationCode>(
    message: [UInt8],
    key: [UInt8],
    as macType: MAC.Type
) -> [UInt8] {
    MAC.authenticationCode(for: message.span, key: key.span)
}

/// Regression coverage for the ordered-delivery Stream-Sequence-Number (SSN)
/// wrap. Reassembly now uses RFC 1982 serial-number arithmetic (matching the TSN
/// path) instead of a fixed 0xF000/0x1000 band, so a message that legitimately
/// straddles the 0xFFFF→0x0000 wrap is neither dropped nor spuriously buffered.
@Suite("SCTP Ordered SSN Wrap Tests")
struct SCTPOrderedSSNWrapTests {

    private func dataChunk(
        tsn: UInt32,
        streamSequenceNumber: UInt16,
        userData: [UInt8] = [0xAA]
    ) -> SCTPDataChunk {
        SCTPDataChunk(
            tsn: tsn,
            streamIdentifier: 0,
            streamSequenceNumber: streamSequenceNumber,
            payloadProtocolIdentifier: 53,
            userData: userData
        )
    }

    /// A delayed message whose SSN is the one just BEFORE the wrap (0xFFFF) — i.e.
    /// serially the predecessor of the stream's current expected SSN 0 — must be
    /// treated as OLD and discarded, NOT buffered as "future". The old
    /// `seqNum > expected` band (0xFFFF > 0) buffered it forever, stalling the
    /// stream and leaking the buffer slot.
    @Test("Pre-wrap stale SSN is discarded, not buffered as future")
    func staleSSNBeforeWrapDiscarded() throws {
        var assembler = FragmentAssembler()

        // Deliver SSN 0 in order (expected advances 0 → 1).
        let first = try assembler.process(
            chunk: dataChunk(tsn: 0, streamSequenceNumber: 0)
        )
        #expect(first.count == 1)

        // A straggler with SSN 0xFFFF is serially BEFORE 0 (the wrap predecessor),
        // hence old relative to expected (1): it must be discarded with no buffered
        // state. Serial arithmetic decides this; the old band would have buffered it.
        let straggler = try assembler.process(
            chunk: dataChunk(tsn: 100, streamSequenceNumber: 0xFFFF)
        )
        #expect(straggler.isEmpty)
        #expect(assembler.bufferedBytes == 0)
        #expect(assembler.pendingCount == 0)
    }

    /// A genuinely future message that straddles the 0xFFFF→0x0000 wrap is
    /// buffered when it arrives early, then flushed in order once the gap is
    /// filled — proving the wrap does not silently drop a valid message. The
    /// stream is first advanced so its expected SSN sits just below the wrap.
    @Test("Out-of-order future SSN across the wrap is buffered then delivered")
    func futureSSNAcrossWrapDeliveredInOrder() throws {
        var assembler = FragmentAssembler()

        // Advance the stream in order up to expected SSN 0xFFFF.
        var ssn: UInt16 = 0
        var tsn: UInt32 = 0
        while ssn != 0xFFFF {
            _ = try assembler.process(chunk: dataChunk(tsn: tsn, streamSequenceNumber: ssn))
            ssn &+= 1
            tsn &+= 1
        }
        // expected is now 0xFFFF.

        // Deliver the POST-wrap message 0x0000 first (out of order): it is one SSN
        // ahead of expected (0xFFFF), so it is buffered, not delivered.
        let early = try assembler.process(
            chunk: dataChunk(tsn: tsn &+ 1, streamSequenceNumber: 0x0000, userData: [0x01])
        )
        #expect(early.isEmpty)
        #expect(assembler.bufferedBytes == 1)

        // Now fill the gap with 0xFFFF: it delivers and then drains the buffered
        // 0x0000 in order. A fixed-band heuristic could drop one across the wrap.
        let drained = try assembler.process(
            chunk: dataChunk(tsn: tsn, streamSequenceNumber: 0xFFFF, userData: [0x02])
        )
        #expect(drained.count == 2)
        #expect(drained[0].sequenceNumber == 0xFFFF)
        #expect(drained[1].sequenceNumber == 0x0000)
        #expect(assembler.bufferedBytes == 0)
    }
}
