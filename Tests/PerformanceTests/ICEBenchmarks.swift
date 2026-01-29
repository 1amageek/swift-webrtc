/// ICE Performance Benchmarks
///
/// Measures performance of ICE Lite agent operations.

import Testing
import Foundation
@testable import ICELite
@testable import STUNCore

@Suite("ICE Benchmarks")
struct ICEBenchmarks {

    // MARK: - Credential Generation

    @Test("Benchmark: ICE credential generation")
    func benchmarkCredentialGeneration() {
        let result = benchmark("ICECredentials()", iterations: 10000) {
            _ = ICECredentials()
        }
        print(result)
    }

    // MARK: - STUN Processing

    @Test("Benchmark: ICE STUN request processing")
    func benchmarkSTUNProcessing() {
        let agent = ICELiteAgent()
        agent.setRemoteCredentials(ufrag: "remoteUfrag", password: "remotePassword12345678")

        let username = "remoteUfrag:\(agent.credentials.localUfrag)"
        let key = agent.credentials.stunKey
        let msg = STUNMessage.bindingRequest(
            username: username,
            iceControlling: 12345
        )
        let encoded = msg.encodeWithIntegrity(key: key)
        let sourceAddress = Data([192, 168, 1, 1])

        let result = benchmark("ICELiteAgent.processSTUN", iterations: 10000) {
            _ = agent.processSTUN(
                data: encoded,
                sourceAddress: sourceAddress,
                sourcePort: 5000
            )
        }
        print(result)
        print("  Request size: \(encoded.count) bytes")
    }

    @Test("Benchmark: ICE STUN with fingerprint verification")
    func benchmarkSTUNWithFingerprint() {
        let agent = ICELiteAgent()
        agent.setRemoteCredentials(ufrag: "remoteUfrag", password: "remotePassword12345678")

        let username = "remoteUfrag:\(agent.credentials.localUfrag)"
        let key = agent.credentials.stunKey
        let msg = STUNMessage.bindingRequest(
            username: username,
            iceControlling: 12345
        )
        // encodeWithIntegrity adds both MESSAGE-INTEGRITY and FINGERPRINT
        let encoded = msg.encodeWithIntegrity(key: key)
        let sourceAddress = Data([192, 168, 1, 1])

        let result = benchmark("ICELiteAgent.processSTUN (with fingerprint)", iterations: 10000) {
            _ = agent.processSTUN(
                data: encoded,
                sourceAddress: sourceAddress,
                sourcePort: 5000
            )
        }
        print(result)
    }

    // MARK: - Peer Validation

    @Test("Benchmark: Peer validation lookup")
    func benchmarkPeerValidation() {
        let agent = ICELiteAgent()
        agent.setRemoteCredentials(ufrag: "remoteUfrag", password: "remotePassword12345678")

        // Validate some peers first
        let key = agent.credentials.stunKey
        for i in 0..<100 {
            let username = "remoteUfrag:\(agent.credentials.localUfrag)"
            let msg = STUNMessage.bindingRequest(username: username, iceControlling: UInt64(i))
            let encoded = msg.encodeWithIntegrity(key: key)
            _ = agent.processSTUN(
                data: encoded,
                sourceAddress: Data([192, 168, UInt8(i / 256), UInt8(i % 256)]),
                sourcePort: UInt16(5000 + i)
            )
        }

        let testAddress = Data([192, 168, 0, 50])

        let result = benchmark("ICELiteAgent.isPeerValidated", iterations: 100000) {
            _ = agent.isPeerValidated(address: testAddress, port: 5050)
        }
        print(result)
    }
}
