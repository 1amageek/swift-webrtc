/// Loopback test for the WebRTC DTLS handshake driven over the swift-tls Tier-1
/// `DTLSClient`/`DTLSServer` facade.
///
/// The handshake is pumped manually between client and server connections without
/// any transport layer (no NIO/UDP).
///
/// ## Facade peer-certificate gap (reported)
///
/// WebRTC's DTLS-SRTP peer authentication binds the peer's leaf-certificate
/// fingerprint to the value advertised in signaling. The swift-tls Tier-1 DTLS
/// facade does NOT expose the peer certificate (no peer-cert accessor on
/// `DTLSClient`/`DTLSServer`, no field on `DTLSOutput`, no certificate-validator
/// on `DTLSConfiguration`). Until the facade gains a peer-certificate accessor,
/// the fingerprint verification CANNOT complete and the connection fails CLOSED.
/// This test asserts exactly that fail-closed contract — it is the security
/// regression guard proving we NEVER accept an unverified peer.

import Testing
import Foundation
import Synchronization
@testable import WebRTC

@Suite("WebRTC Loopback Tests")
struct WebRTCLoopbackTests {

    /// The full DTLS handshake flights are exchanged over the facade, and the
    /// client's certificate-fingerprint verification fails CLOSED because the
    /// facade does not expose the server's certificate. The client must NOT reach
    /// `.connected` — accepting an unverified peer would be a security regression.
    @Test("Client fingerprint verification fails closed when peer cert is unavailable", .timeLimit(.minutes(1)))
    func clientFingerprintFailsClosed() throws {
        let clientCert = try WebRTCCertificate.generateSelfSigned()
        let serverCert = try WebRTCCertificate.generateSelfSigned()

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

        try server.start()
        try client.start()
        #expect(client.state == .dtlsHandshaking)
        #expect(server.state == .dtlsHandshaking)

        // Pump datagrams between the two sides until both settle or the budget
        // is exhausted. The client's fingerprint verification fails closed at
        // handshake completion, which surfaces as a throw from `receive` per the
        // connection's terminal contract — caught explicitly below.
        var clientFailedClosed = false
        rounds: for _ in 0..<20 {
            let toServer = clientOutbox.withLock { msgs -> [Data] in
                let copy = msgs; msgs.removeAll(); return copy
            }
            for msg in toServer {
                do {
                    try server.receive(msg)
                } catch let error as WebRTCError {
                    // The server side has no expected fingerprint, so any throw
                    // here is unexpected — record it.
                    Issue.record("Unexpected server receive failure: \(error)")
                    break rounds
                }
            }

            let toClient = serverOutbox.withLock { msgs -> [Data] in
                let copy = msgs; msgs.removeAll(); return copy
            }
            for msg in toClient {
                do {
                    try client.receive(msg)
                } catch let error as WebRTCError {
                    // Expected: the client cannot verify the server fingerprint
                    // (facade gap) and fails closed.
                    guard case .dtlsHandshakeFailed = error else {
                        Issue.record("Unexpected client failure: \(error)")
                        break rounds
                    }
                    clientFailedClosed = true
                    break rounds
                }
            }

            if client.state == .connected {
                break
            }
            if toServer.isEmpty && toClient.isEmpty {
                break
            }
        }

        #expect(clientFailedClosed)

        // Fail-closed: the client never claims a connection it cannot authenticate.
        #expect(client.state != .connected)
        #expect(client.remoteFingerprint == nil)
    }
}
