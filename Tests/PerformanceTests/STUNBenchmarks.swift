/// STUN Performance Benchmarks
///
/// Measures performance of STUN message encoding, decoding, and integrity verification.

import Testing
import Foundation
@testable import STUNCore

@Suite("STUN Benchmarks")
struct STUNBenchmarks {

    // MARK: - Message Encoding

    @Test("Benchmark: STUN Binding Request encoding")
    func benchmarkBindingRequestEncode() {
        let msg = STUNMessage.bindingRequest(
            username: "user1234:user5678",
            priority: 12345,
            iceControlling: 9876543210
        )

        let result = benchmark("BindingRequest.encode", iterations: 10000) {
            _ = msg.encode()
        }
        print(result)
    }

    @Test("Benchmark: STUN Binding Request with integrity encoding")
    func benchmarkBindingRequestWithIntegrity() {
        let msg = STUNMessage.bindingRequest(
            username: "user1234:user5678",
            priority: 12345,
            iceControlling: 9876543210
        )
        let key = Data("password123456789012".utf8)

        let result = benchmark("BindingRequest.encodeWithIntegrity", iterations: 10000) {
            _ = msg.encodeWithIntegrity(key: key)
        }
        print(result)
    }

    // MARK: - Message Decoding

    @Test("Benchmark: STUN message decoding")
    func benchmarkMessageDecode() throws {
        let msg = STUNMessage.bindingRequest(
            username: "user1234:user5678",
            priority: 12345,
            iceControlling: 9876543210
        )
        let key = Data("password123456789012".utf8)
        let encoded = msg.encodeWithIntegrity(key: key)

        let result = try benchmark("STUNMessage.decode", iterations: 10000) {
            _ = try STUNMessage.decode(from: encoded)
        }
        print(result)
    }

    // MARK: - MESSAGE-INTEGRITY

    @Test("Benchmark: MESSAGE-INTEGRITY computation")
    func benchmarkIntegrityCompute() {
        // Simulate a typical STUN message (100 bytes)
        let data = Data(repeating: 0x42, count: 100)
        let key = Data("password123456789012".utf8)

        let result = benchmark("MessageIntegrity.compute", iterations: 10000) {
            _ = MessageIntegrity.compute(data: data, key: key)
        }
        print(result)
    }

    @Test("Benchmark: MESSAGE-INTEGRITY verification (small message)")
    func benchmarkIntegrityVerifySmall() {
        let msg = STUNMessage.bindingRequest(username: "u:v")
        let key = Data("password123456789012".utf8)
        let encoded = msg.encodeWithIntegrity(key: key)

        let result = benchmark("MessageIntegrity.verify (small)", iterations: 10000) {
            _ = MessageIntegrity.verifyWithResult(message: encoded, key: key)
        }
        print(result)
        print("  Message size: \(encoded.count) bytes")
    }

    @Test("Benchmark: MESSAGE-INTEGRITY verification (large message)")
    func benchmarkIntegrityVerifyLarge() {
        // Create message with many attributes
        var msg = STUNMessage.bindingRequest(
            username: String(repeating: "a", count: 500) + ":" + String(repeating: "b", count: 500),
            priority: 12345,
            iceControlling: 9876543210
        )
        // Add padding attributes to simulate larger message
        for i in 0..<10 {
            msg.attributes.append(STUNAttribute(
                type: 0x8000 + UInt16(i),
                value: Data(repeating: UInt8(i), count: 100)
            ))
        }
        let key = Data("password123456789012".utf8)
        let encoded = msg.encodeWithIntegrity(key: key)

        let result = benchmark("MessageIntegrity.verify (large)", iterations: 10000) {
            _ = MessageIntegrity.verifyWithResult(message: encoded, key: key)
        }
        print(result)
        print("  Message size: \(encoded.count) bytes")
    }

    // MARK: - FINGERPRINT

    @Test("Benchmark: FINGERPRINT computation")
    func benchmarkFingerprintCompute() {
        let data = Data(repeating: 0x42, count: 100)

        let result = benchmark("STUNFingerprint.compute", iterations: 10000) {
            _ = STUNFingerprint.compute(data: data)
        }
        print(result)
    }

    @Test("Benchmark: FINGERPRINT verification")
    func benchmarkFingerprintVerify() {
        let msg = STUNMessage.bindingRequest(username: "user:pass")
        let key = Data("password123456789012".utf8)
        let encoded = msg.encodeWithIntegrity(key: key)

        let result = benchmark("STUNFingerprint.verify", iterations: 10000) {
            _ = STUNFingerprint.verify(message: encoded)
        }
        print(result)
    }

    // MARK: - Full Pipeline

    @Test("Benchmark: Full STUN request/response cycle")
    func benchmarkFullCycle() throws {
        let key = Data("password123456789012".utf8)

        let result = try benchmark("Full STUN cycle", iterations: 5000) {
            // Encode request
            let request = STUNMessage.bindingRequest(
                username: "remote:local",
                iceControlling: 12345
            )
            let encoded = request.encodeWithIntegrity(key: key)

            // Decode request
            let decoded = try STUNMessage.decode(from: encoded)

            // Verify integrity
            let integrityResult = MessageIntegrity.verifyWithResult(message: encoded, key: key)
            guard integrityResult == .valid else { return }

            // Create response
            let response = STUNMessage.bindingSuccessResponse(
                transactionID: decoded.transactionID,
                address: Data([192, 168, 1, 1]),
                port: 5000
            )
            _ = response.encodeWithIntegrity(key: key)
        }
        print(result)
    }
}
