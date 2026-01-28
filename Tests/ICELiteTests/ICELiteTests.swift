/// Tests for ICE Lite Agent

import Testing
import Foundation
@testable import ICELite
@testable import STUNCore

@Suite("ICE Lite Tests")
struct ICELiteTests {

    @Test("ICE credentials generation")
    func credentialsGeneration() {
        let creds = ICECredentials()
        #expect(creds.localUfrag.count >= 4)
        #expect(creds.localPassword.count >= 22)
        #expect(creds.remoteUfrag == nil)
        #expect(creds.remotePassword == nil)
    }

    @Test("ICE credentials uniqueness")
    func credentialsUniqueness() {
        let creds1 = ICECredentials()
        let creds2 = ICECredentials()
        #expect(creds1.localUfrag != creds2.localUfrag)
        #expect(creds1.localPassword != creds2.localPassword)
    }

    @Test("STUN username format")
    func stunUsername() {
        var creds = ICECredentials()
        creds.remoteUfrag = "remote"
        #expect(creds.stunUsername == "remote:\(creds.localUfrag)")
    }

    @Test("ICE state transitions")
    func stateTransitions() {
        let agent = ICELiteAgent()
        #expect(agent.state == .new)

        agent.setRemoteCredentials(ufrag: "remote", password: "remotepass")
        #expect(agent.state == .checking)

        agent.close()
        #expect(agent.state == .closed)
    }

    @Test("Process STUN binding request")
    func processBindingRequest() throws {
        let agent = ICELiteAgent()

        // Create a STUN binding request with proper MESSAGE-INTEGRITY
        let key = agent.credentials.stunKey
        let msg = STUNMessage.bindingRequest()
        let encoded = msg.encodeWithIntegrity(key: key)

        let sourceAddress = Data([192, 168, 1, 1])
        let sourcePort: UInt16 = 5000

        let response = agent.processSTUN(
            data: encoded,
            sourceAddress: sourceAddress,
            sourcePort: sourcePort
        )

        // Should get a response
        #expect(response != nil)

        // Peer should be validated
        #expect(agent.isPeerValidated(address: sourceAddress, port: sourcePort))

        // State should be connected
        #expect(agent.state == .connected)
    }

    @Test("Reject non-STUN data")
    func rejectNonSTUN() {
        let agent = ICELiteAgent()
        let data = Data(repeating: 0xFF, count: 20)
        let result = agent.processSTUN(data: data, sourceAddress: Data([0, 0, 0, 0]), sourcePort: 0)
        #expect(result == nil)
    }
}
