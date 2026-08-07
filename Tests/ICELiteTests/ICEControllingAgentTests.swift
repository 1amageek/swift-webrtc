import Testing
@testable import WebRTC

@Suite("ICE Controlling Agent Tests")
struct ICEControllingAgentTests {
    @Test("Controlling and Lite agents complete an authenticated nominated check")
    func authenticatedNominatedCheck() throws {
        let controllingCredentials = ICECredentials(
            localUfrag: "clientUfrag",
            localPassword: "clientPassword456789012345",
            remoteUfrag: "serverUfrag",
            remotePassword: "serverPassword456789012345"
        )
        let liteCredentials = ICECredentials(
            localUfrag: "serverUfrag",
            localPassword: "serverPassword456789012345",
            remoteUfrag: "clientUfrag",
            remotePassword: "clientPassword456789012345"
        )
        let controlling = ICEControllingAgent(
            credentials: controllingCredentials
        )
        let lite = ICELiteAgent(credentials: liteCredentials)

        guard case .send(let request) = controlling.connectivityCheck() else {
            Issue.record("Expected an outbound connectivity check")
            return
        }
        let decodedRequest = try STUNMessage.decode(from: request)
        #expect(decodedRequest.messageType == .bindingRequest)
        #expect(decodedRequest.attribute(ofType: .useCandidate) != nil)
        #expect(decodedRequest.attribute(ofType: .iceControlling) != nil)
        #expect(MessageIntegrity.verifyWithResultBytes(
            message: request,
            key: Array(liteCredentials.localPassword.utf8)
        ) == .valid)

        let response = try #require(lite.processSTUNBytes(
            data: request,
            sourceAddress: [192, 0, 2, 10],
            sourcePort: 45_000
        ))
        controlling.processSTUNBytes(response)

        #expect(controlling.state == .connected)
        #expect(lite.state == .connected)
    }

    @Test("A response with invalid integrity fails closed")
    func invalidResponseIntegrityFailsClosed() throws {
        let credentials = ICECredentials(
            localUfrag: "clientUfrag",
            localPassword: "clientPassword456789012345",
            remoteUfrag: "serverUfrag",
            remotePassword: "serverPassword456789012345"
        )
        let controlling = ICEControllingAgent(credentials: credentials)
        guard case .send(let request) = controlling.connectivityCheck() else {
            Issue.record("Expected an outbound connectivity check")
            return
        }
        let decodedRequest = try STUNMessage.decode(from: request)
        let response = STUNMessage.bindingSuccessResponse(
            transactionID: decodedRequest.transactionID,
            address: [192, 0, 2, 10],
            port: 45_000
        ).encodeWithIntegrityBytes(key: Array("wrongPassword456789012345".utf8))

        controlling.processSTUNBytes(response)

        #expect(controlling.state == .failed)
        #expect(controlling.failureReason != nil)
    }

    @Test("Controlling agent answers a controlled peer's reciprocal check")
    func reciprocalControlledCheck() throws {
        let credentials = ICECredentials(
            localUfrag: "clientUfrag",
            localPassword: "clientPassword456789012345",
            remoteUfrag: "serverUfrag",
            remotePassword: "serverPassword456789012345"
        )
        let controlling = ICEControllingAgent(credentials: credentials)
        let request = STUNMessage(
            messageType: .bindingRequest,
            attributes: [
                .username("clientUfrag:serverUfrag"),
                .priority(1_845_501_695),
                .iceControlled(tiebreaker: 42),
            ]
        ).encodeWithIntegrityBytes(key: Array(credentials.localPassword.utf8))

        let response = try #require(controlling.processSTUNBytes(
            request,
            sourceAddress: [192, 0, 2, 20],
            sourcePort: 46_000
        ))
        let decodedResponse = try STUNMessage.decode(from: response)

        #expect(decodedResponse.messageType == .bindingSuccessResponse)
        #expect(MessageIntegrity.verifyWithResultBytes(
            message: response,
            key: Array(credentials.localPassword.utf8)
        ) == .valid)
        #expect(decodedResponse.attribute(ofType: .xorMappedAddress)?
            .parseXorMappedAddress(transactionID: decodedResponse.transactionID)?
            .port == 46_000)
    }

}
