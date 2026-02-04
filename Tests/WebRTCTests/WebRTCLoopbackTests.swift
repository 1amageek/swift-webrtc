/// Loopback test for full WebRTC handshake (DTLS + SCTP)
///
/// Tests the complete handshake by manually pumping data between
/// client and server connections without any transport layer (no NIO/UDP).

import Testing
import Foundation
import Synchronization
@testable import WebRTC
@testable import DTLSCore

@Suite("WebRTC Loopback Tests")
struct WebRTCLoopbackTests {

    @Test("Full DTLS + SCTP handshake completes in loopback", .timeLimit(.minutes(1)))
    func fullHandshakeLoopback() throws {
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()

        // Capture sent data
        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])

        let client = WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: serverCert.fingerprint,
            sendHandler: { data in clientOutbox.withLock { $0.append(data) } }
        )
        let server = WebRTCConnection.asServer(
            certificate: serverCert,
            sendHandler: { data in serverOutbox.withLock { $0.append(data) } }
        )

        // Start both
        try server.start()
        try client.start()

        #expect(client.state == .dtlsHandshaking)
        #expect(server.state == .dtlsHandshaking)

        // Pump data between client and server for up to 20 rounds
        for round in 0..<20 {
            // Deliver client → server
            let toServer = clientOutbox.withLock { msgs -> [Data] in
                let copy = msgs
                msgs.removeAll()
                return copy
            }
            for msg in toServer {
                do {
                    try server.receive(msg)
                } catch {
                    Issue.record("Round \(round): Server receive failed: \(error)")
                    return
                }
            }

            // Deliver server → client
            let toClient = serverOutbox.withLock { msgs -> [Data] in
                let copy = msgs
                msgs.removeAll()
                return copy
            }
            for msg in toClient {
                do {
                    try client.receive(msg)
                } catch {
                    Issue.record("Round \(round): Client receive failed: \(error)")
                    return
                }
            }

            // Check if both connected
            let clientState = client.state
            let serverState = server.state

            if clientState == .connected && serverState == .connected {
                // Success!
                return
            }

            // No more data to exchange?
            if toServer.isEmpty && toClient.isEmpty {
                Issue.record("Round \(round): No data exchanged. Client: \(clientState), Server: \(serverState)")
                return
            }
        }

        Issue.record("Handshake did not complete in 20 rounds. Client: \(client.state), Server: \(server.state)")
    }
}
