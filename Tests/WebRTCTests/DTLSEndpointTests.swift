import Testing
@testable import WebRTC

@Suite("DTLS Endpoint Tests")
struct DTLSEndpointTests {
    @Test(
        "Data-channel-only endpoints negotiate the mandatory WebRTC SRTP profile",
        .timeLimit(.minutes(1))
    )
    func dataChannelOnlyNegotiatesSRTP() throws {
        let clientCertificate = try WebRTCTestIdentity.make(.primary)
        let serverCertificate = try WebRTCTestIdentity.make(.secondary)
        let client = try DTLSEndpoint.make(
            certificate: clientCertificate,
            isClient: true,
            requireClientCertificate: false,
            mediaConfiguration: nil
        )
        let server = try DTLSEndpoint.make(
            certificate: serverCertificate,
            isClient: false,
            requireClientCertificate: true,
            mediaConfiguration: nil
        )

        var clientToServer = try client.startHandshake()
        var serverToClient = try server.startHandshake()
        let remoteAddress: [UInt8] = [127, 0, 0, 1, 0x13, 0x88]

        for _ in 0..<24 where !(client.isEstablished && server.isEstablished) {
            var nextServerToClient: [[UInt8]] = []
            for datagram in clientToServer {
                let output = try server.receive(
                    datagram,
                    remoteAddress: remoteAddress
                )
                nextServerToClient.append(contentsOf: output.datagramsToSend)
            }
            serverToClient.append(contentsOf: nextServerToClient)
            clientToServer.removeAll(keepingCapacity: true)

            var nextClientToServer: [[UInt8]] = []
            for datagram in serverToClient {
                let output = try client.receive(datagram, remoteAddress: [])
                nextClientToServer.append(contentsOf: output.datagramsToSend)
            }
            clientToServer.append(contentsOf: nextClientToServer)
            serverToClient.removeAll(keepingCapacity: true)
        }

        #expect(client.isEstablished)
        #expect(server.isEstablished)
        let clientMaterial = try client.srtpKeyingMaterial()
        let serverMaterial = try server.srtpKeyingMaterial()
        #expect(clientMaterial.protectionProfile == .aes128CMHMACSHA180)
        #expect(serverMaterial.protectionProfile == .aes128CMHMACSHA180)
    }
}
