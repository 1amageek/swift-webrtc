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

        // Set remote credentials (simulating SDP exchange)
        let remoteUfrag = "remoteUfrag123"
        let remotePassword = "remotePassword456789012345"
        agent.setRemoteCredentials(ufrag: remoteUfrag, password: remotePassword)

        // Create a STUN binding request with proper USERNAME and MESSAGE-INTEGRITY
        // USERNAME format: remoteUfrag:localUfrag (from the sender's perspective)
        // The sender uses their ufrag as remoteUfrag and our ufrag as localUfrag
        let username = "\(remoteUfrag):\(agent.credentials.localUfrag)"
        let key = agent.credentials.stunKey

        // Use ICE-CONTROLLING since ICE Lite is always controlled
        let msg = STUNMessage.bindingRequest(
            username: username,
            iceControlling: 12345
        )
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

    // MARK: - Finding 12: remote ufrag is asserted when known

    @Test("Binding request with the wrong remote ufrag is rejected")
    func wrongRemoteUfragRejected() throws {
        let agent = ICELiteAgent()
        let remoteUfrag = "knownRemote"
        let remotePassword = "remotePassword456789012345"
        agent.setRemoteCredentials(ufrag: remoteUfrag, password: remotePassword)

        let key = agent.credentials.stunKey
        // USERNAME = "<peerUfragWeExpectAsRemote>:<ourLocalUfrag>". The sender
        // here uses the WRONG remote half ("wrongRemote") but the correct local
        // half — must be rejected once the remote ufrag is known.
        let username = "wrongRemote:\(agent.credentials.localUfrag)"
        let msg = STUNMessage.bindingRequest(username: username, iceControlling: 1)
        let encoded = msg.encodeWithIntegrity(key: key)

        let response = agent.processSTUN(
            data: encoded, sourceAddress: Data([192, 168, 1, 1]), sourcePort: 5000)

        // An error response is returned (not a success), and the peer is not
        // validated.
        let errorResp = try #require(response)
        let decoded = try STUNMessage.decode(from: errorResp)
        #expect(decoded.messageType == .bindingErrorResponse)
        #expect(!agent.isPeerValidated(address: Data([192, 168, 1, 1]), port: 5000))
    }

    @Test("Binding request with the correct remote ufrag is accepted")
    func correctRemoteUfragAccepted() throws {
        let agent = ICELiteAgent()
        let remoteUfrag = "knownRemote"
        agent.setRemoteCredentials(ufrag: remoteUfrag, password: "remotePassword456789012345")

        let key = agent.credentials.stunKey
        let username = "\(remoteUfrag):\(agent.credentials.localUfrag)"
        let msg = STUNMessage.bindingRequest(username: username, iceControlling: 1)
        let encoded = msg.encodeWithIntegrity(key: key)

        let response = agent.processSTUN(
            data: encoded, sourceAddress: Data([192, 168, 1, 2]), sourcePort: 6000)
        let resp = try #require(response)
        let decoded = try STUNMessage.decode(from: resp)
        #expect(decoded.messageType == .bindingSuccessResponse)
        #expect(agent.isPeerValidated(address: Data([192, 168, 1, 2]), port: 6000))
    }
}
