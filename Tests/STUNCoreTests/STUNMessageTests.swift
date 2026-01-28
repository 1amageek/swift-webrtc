/// Tests for STUN message encoding/decoding

import Testing
import Foundation
@testable import STUNCore

@Suite("STUN Message Tests")
struct STUNMessageTests {

    @Test("Binding request encode/decode roundtrip")
    func bindingRequestRoundtrip() throws {
        let msg = STUNMessage.bindingRequest()
        let encoded = msg.encode()

        #expect(encoded.count >= stunHeaderSize)
        // First two bits must be 0
        #expect(encoded[0] & 0xC0 == 0)

        let decoded = try STUNMessage.decode(from: encoded)
        #expect(decoded.messageType == .bindingRequest)
        #expect(decoded.transactionID == msg.transactionID)
    }

    @Test("Magic cookie is present")
    func magicCookiePresent() {
        let msg = STUNMessage(messageType: .bindingRequest)
        let encoded = msg.encode()

        let cookie = UInt32(encoded[4]) << 24 | UInt32(encoded[5]) << 16 |
                     UInt32(encoded[6]) << 8 | UInt32(encoded[7])
        #expect(cookie == stunMagicCookie)
    }

    @Test("Message type encoding")
    func messageTypeEncoding() {
        let bindReq = STUNMessageType.bindingRequest
        #expect(bindReq.method == .binding)
        #expect(bindReq.messageClass == .request)

        let bindResp = STUNMessageType.bindingSuccessResponse
        #expect(bindResp.method == .binding)
        #expect(bindResp.messageClass == .successResponse)

        let bindErr = STUNMessageType.bindingErrorResponse
        #expect(bindErr.method == .binding)
        #expect(bindErr.messageClass == .errorResponse)
    }

    @Test("isSTUN detection")
    func isSTUNDetection() {
        let msg = STUNMessage(messageType: .bindingRequest)
        let encoded = msg.encode()
        #expect(STUNMessage.isSTUN(encoded))

        // Non-STUN data
        let notSTUN = Data([0xFF, 0xFF, 0x00, 0x00] + Array(repeating: UInt8(0), count: 16))
        #expect(!STUNMessage.isSTUN(notSTUN))

        // Too short
        #expect(!STUNMessage.isSTUN(Data([0x00, 0x01])))
    }

    @Test("Binding request with attributes")
    func bindingRequestWithAttributes() throws {
        let msg = STUNMessage.bindingRequest(
            username: "user:remote",
            priority: 100,
            useCandidate: true
        )

        let encoded = msg.encode()
        let decoded = try STUNMessage.decode(from: encoded)

        #expect(decoded.attribute(ofType: .username) != nil)
        #expect(decoded.attribute(ofType: .priority) != nil)
        #expect(decoded.attribute(ofType: .useCandidate) != nil)

        let usernameAttr = decoded.attribute(ofType: .username)!
        #expect(String(data: usernameAttr.value, encoding: .utf8) == "user:remote")
    }

    @Test("Success response with XOR-MAPPED-ADDRESS")
    func successResponseXorMappedAddress() throws {
        let txID = TransactionID.random()
        let address = Data([192, 168, 1, 100]) // IPv4
        let port: UInt16 = 12345

        let msg = STUNMessage.bindingSuccessResponse(
            transactionID: txID,
            address: address,
            port: port
        )

        let encoded = msg.encode()
        let decoded = try STUNMessage.decode(from: encoded)

        #expect(decoded.messageType == .bindingSuccessResponse)
        #expect(decoded.transactionID == txID)

        let xma = decoded.attribute(ofType: .xorMappedAddress)!
        let parsed = xma.parseXorMappedAddress(transactionID: txID)!
        #expect(parsed.address == address)
        #expect(parsed.port == port)
    }

    @Test("Error response")
    func errorResponse() throws {
        let txID = TransactionID.random()
        let msg = STUNMessage.bindingErrorResponse(
            transactionID: txID,
            errorCode: 401,
            reason: "Unauthorized"
        )

        let encoded = msg.encode()
        let decoded = try STUNMessage.decode(from: encoded)

        #expect(decoded.messageType == .bindingErrorResponse)
        let errorAttr = decoded.attribute(ofType: .errorCode)!
        // Error class (4) and number (01)
        #expect(errorAttr.value[2] == 4) // class
        #expect(errorAttr.value[3] == 1) // number
    }

    @Test("Transaction ID uniqueness")
    func transactionIDUniqueness() {
        let id1 = TransactionID.random()
        let id2 = TransactionID.random()
        #expect(id1 != id2)
        #expect(id1.bytes.count == 12)
    }

    @Test("Attribute padding")
    func attributePadding() throws {
        // Username with odd length should be padded
        let msg = STUNMessage(
            messageType: .bindingRequest,
            attributes: [.username("abc")] // 3 bytes → padded to 4
        )

        let encoded = msg.encode()
        let decoded = try STUNMessage.decode(from: encoded)

        let attr = decoded.attribute(ofType: .username)!
        #expect(String(data: attr.value, encoding: .utf8) == "abc")
    }
}

@Suite("STUN Fingerprint Tests")
struct STUNFingerprintTests {

    @Test("CRC-32 fingerprint computation")
    func fingerprintComputation() {
        let data = Data("test data for CRC".utf8)
        let fp1 = STUNFingerprint.compute(data: data)
        let fp2 = STUNFingerprint.compute(data: data)
        #expect(fp1 == fp2)
        #expect(fp1.count == 4)
    }

    @Test("Different data produces different fingerprints")
    func fingerprintDifferent() {
        let fp1 = STUNFingerprint.compute(data: Data("hello".utf8))
        let fp2 = STUNFingerprint.compute(data: Data("world".utf8))
        #expect(fp1 != fp2)
    }
}

@Suite("STUN Message Integrity Tests")
struct STUNMessageIntegrityTests {

    @Test("HMAC-SHA1 computation")
    func hmacComputation() {
        let data = Data("test message".utf8)
        let key = Data("secret key".utf8)
        let mac1 = MessageIntegrity.compute(data: data, key: key)
        let mac2 = MessageIntegrity.compute(data: data, key: key)
        #expect(mac1 == mac2)
        #expect(mac1.count == 20) // SHA-1 output
    }

    @Test("Different keys produce different MACs")
    func differentKeys() {
        let data = Data("test".utf8)
        let mac1 = MessageIntegrity.compute(data: data, key: Data("key1".utf8))
        let mac2 = MessageIntegrity.compute(data: data, key: Data("key2".utf8))
        #expect(mac1 != mac2)
    }
}
