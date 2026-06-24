/// Loopback test for the WebRTC DTLS handshake driven over the swift-tls Tier-1
/// `DTLSClient`/`DTLSServer` facade.
///
/// The handshake is pumped manually between client and server connections without
/// any transport layer (no NIO/UDP).
///
/// ## DTLS-SRTP peer authentication (now wired)
///
/// WebRTC's DTLS-SRTP peer authentication binds the peer's leaf-certificate
/// fingerprint to the value advertised in signaling. The swift-tls Tier-1 DTLS
/// facade now surfaces the peer's leaf certificate after the handshake
/// (`DTLSClient`/`DTLSServer.remoteCertificateDER`), so `WebRTCConnection`
/// computes the SHA-256 fingerprint and verifies it against the expected value:
///
/// - A MATCHING expected fingerprint → the handshake completes (authenticated).
/// - A MISMATCHED or ABSENT peer certificate → the verifier fails CLOSED; the
///   client never reaches `.connected`. That fail-closed contract is the security
///   regression guard proving we NEVER accept an unverified peer.

import Testing
import Foundation
import Synchronization
@testable import WebRTC

@Suite("WebRTC Loopback Tests")
struct WebRTCLoopbackTests {

    /// Pumps the full DTLS handshake flights between a client and server until
    /// both settle or the round budget is exhausted. Returns whether the client
    /// failed closed with a `dtlsHandshakeFailed` error.
    private func pumpHandshake(
        client: WebRTCConnection,
        server: WebRTCConnection,
        clientOutbox: borrowing Mutex<[Data]>,
        serverOutbox: borrowing Mutex<[Data]>
    ) -> (clientFailedClosed: Bool, serverFailedClosed: Bool) {
        var clientFailedClosed = false
        var serverFailedClosed = false
        rounds: for _ in 0..<20 {
            let toServer = clientOutbox.withLock { msgs -> [Data] in
                let copy = msgs; msgs.removeAll(); return copy
            }
            for msg in toServer {
                do {
                    try server.receive(msg)
                } catch {
                    guard let webrtcError = error as? WebRTCError,
                          case .dtlsHandshakeFailed = webrtcError else {
                        Issue.record("Unexpected server failure: \(error)")
                        break rounds
                    }
                    serverFailedClosed = true
                    break rounds
                }
            }

            let toClient = serverOutbox.withLock { msgs -> [Data] in
                let copy = msgs; msgs.removeAll(); return copy
            }
            for msg in toClient {
                do {
                    try client.receive(msg)
                } catch {
                    guard let webrtcError = error as? WebRTCError,
                          case .dtlsHandshakeFailed = webrtcError else {
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
        return (clientFailedClosed, serverFailedClosed)
    }

    /// With the expected fingerprint set to the server's actual certificate
    /// fingerprint, the authenticated DTLS-SRTP handshake now COMPLETES: the
    /// facade surfaces the server's peer certificate, the client computes the
    /// SHA-256 fingerprint, it matches, and the client reaches `.connected`.
    @Test("Client completes the authenticated DTLS-SRTP handshake when the fingerprint matches", .timeLimit(.minutes(1)))
    func clientVerifiesMatchingFingerprint() throws {
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

        let result = pumpHandshake(
            client: client, server: server,
            clientOutbox: clientOutbox, serverOutbox: serverOutbox
        )
        #expect(result.clientFailedClosed == false)
        #expect(result.serverFailedClosed == false)

        // The authenticated handshake completes and the verified fingerprint is
        // recorded — matching the value advertised in signaling.
        #expect(client.state == .connected)
        #expect(client.remoteFingerprint == serverCert.fingerprint)
    }

    /// With an expected fingerprint that does NOT match the server's certificate,
    /// the verifier fails CLOSED at handshake completion. The client must NOT
    /// reach `.connected` — accepting an unverified peer would be a security
    /// regression.
    @Test("Client fingerprint verification fails closed on a mismatch", .timeLimit(.minutes(1)))
    func clientFingerprintFailsClosedOnMismatch() throws {
        let clientCert = try WebRTCCertificate.generateSelfSigned()
        let serverCert = try WebRTCCertificate.generateSelfSigned()
        // An expected fingerprint that the server's real certificate cannot match.
        let bogusFingerprint = CertificateFingerprint.fromDER(Data(repeating: 0x5A, count: 64))
        #expect(bogusFingerprint != serverCert.fingerprint)

        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])

        let client = WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: bogusFingerprint,
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

        let result = pumpHandshake(
            client: client, server: server,
            clientOutbox: clientOutbox, serverOutbox: serverOutbox
        )

        #expect(result.clientFailedClosed)
        // Fail-closed: the client never claims a connection it cannot authenticate.
        #expect(client.state != .connected)
        #expect(client.remoteFingerprint == nil)
    }
}
