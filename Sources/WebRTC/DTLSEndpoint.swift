/// Uniform driver over the swift-tls Tier-1 DTLS facade.
///
/// The facade exposes two distinct value types — `DTLSClient` and `DTLSServer` —
/// that differ only in the server taking the peer's transport address for the
/// HelloVerifyRequest cookie binding (RFC 6347 §4.2.1). `WebRTCConnection` drives
/// one DTLS role over the ICE/UDP path, so this enum presents a single sans-IO
/// surface: feed received datagrams via `receive`, send the returned datagrams,
/// drive flight retransmission via `handleTimeout`.
///
/// ## Peer-certificate gap (reported integration nuance)
///
/// The facade's `DTLSClient`/`DTLSServer`/`DTLSOutput` do NOT expose the peer's
/// certificate or its fingerprint after the handshake (the engine has it, but the
/// Tier-1 facade does not surface it, and `DTLSConfiguration` has no
/// certificate-validator hook — unlike `TLSConfiguration`). WebRTC's DTLS-SRTP
/// peer authentication binds the peer's leaf-certificate fingerprint to the value
/// advertised in signaling. Because the facade hides the peer certificate,
/// `remoteCertificateDER`/`remoteFingerprint` are unavailable here. The verifier
/// in `WebRTCConnection` therefore fails CLOSED when an expected fingerprint is
/// configured but the peer fingerprint cannot be obtained — it never silently
/// accepts an unverified peer.

import Foundation
import TLS

/// A DTLS role driven over the WebRTC datagram path.
enum DTLSEndpoint: Sendable {
    case client(DTLSClient)
    case server(DTLSServer)

    /// Create a client or server endpoint bound to the local certificate's
    /// identity. `requireClientCertificate` is honored only by the server (the
    /// WebRTC server demands mutual authentication).
    static func make(
        certificate: WebRTCCertificate,
        isClient: Bool,
        requireClientCertificate: Bool
    ) throws(TLSError) -> DTLSEndpoint {
        let configuration = DTLSConfiguration(
            identity: certificate.tlsIdentity,
            requireClientCertificate: requireClientCertificate
        )
        if isClient {
            return .client(try DTLSClient(configuration: configuration))
        } else {
            return .server(try DTLSServer(configuration: configuration))
        }
    }

    /// Start the handshake, returning the initial datagrams to send. A server has
    /// nothing to send until the first ClientHello, so its return is empty.
    func startHandshake() throws(TLSError) -> [[UInt8]] {
        switch self {
        case .client(let c): return try c.startHandshake()
        case .server(let s): return try s.startHandshake()
        }
    }

    /// Feed a received UDP datagram. `remoteAddress` is used only by the server
    /// for the HelloVerifyRequest cookie binding.
    func receive(_ datagram: [UInt8], remoteAddress: [UInt8]) throws(TLSError) -> DTLSOutput {
        switch self {
        case .client(let c):
            return try c.receive(datagram.span)
        case .server(let s):
            return try s.receive(datagram.span, from: remoteAddress.span)
        }
    }

    /// Encrypt application data into a DTLS datagram.
    func send(_ application: [UInt8]) throws(TLSError) -> [UInt8] {
        switch self {
        case .client(let c):
            return try c.send(application.span)
        case .server(let s):
            return try s.send(application.span)
        }
    }

    /// Datagrams to retransmit on a flight timeout.
    func handleTimeout() throws(TLSError) -> [[UInt8]] {
        switch self {
        case .client(let c): return try c.handleTimeout()
        case .server(let s): return try s.handleTimeout()
        }
    }

    /// Whether the handshake has completed and the connection is usable.
    var isEstablished: Bool {
        switch self {
        case .client(let c): return c.isEstablished
        case .server(let s): return s.isEstablished
        }
    }

    /// The peer's DER-encoded leaf certificate, if presented during the handshake.
    /// `nil` while the handshake is incomplete or no certificate was received. The
    /// swift-tls Tier-1 DTLS facade now surfaces this; WebRTC computes the
    /// DTLS-SRTP fingerprint from it (RFC 8122).
    var remoteCertificateDER: [UInt8]? {
        switch self {
        case .client(let c): return c.remoteCertificateDER
        case .server(let s): return s.remoteCertificateDER
        }
    }
}
