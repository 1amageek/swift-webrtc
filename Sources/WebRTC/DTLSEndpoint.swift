/// Uniform driver over the swift-tls Tier-1 DTLS facade.
///
/// The facade exposes two distinct value types — `DTLSClient` and `DTLSServer` —
/// that differ only in the server taking the peer's transport address for the
/// HelloVerifyRequest cookie binding (RFC 6347 §4.2.1). `WebRTCConnection` drives
/// one DTLS role over the ICE/UDP path, so this enum presents a single sans-IO
/// surface: feed received datagrams via `receive`, send the returned datagrams,
/// drive flight retransmission via `handleTimeout`.
///
/// ## DTLS-SRTP peer authentication
///
/// The swift-tls Tier-1 facade surfaces the peer's leaf certificate via
/// `DTLSClient`/`DTLSServer.remoteCertificateDER` (re-exposed here as
/// `remoteCertificateDER`). WebRTC's DTLS-SRTP authentication binds the SHA-256
/// fingerprint of that certificate to the value advertised in signaling
/// (RFC 8122): `WebRTCConnection.onHandshakeComplete()` computes the peer
/// fingerprint from the surfaced DER and, when an expected fingerprint is
/// configured, completes the handshake on match and fails CLOSED on mismatch — or
/// when the peer certificate is genuinely unavailable. It never silently accepts
/// an unverified peer.

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
        requireClientCertificate: Bool,
        mediaConfiguration: WebRTCMediaConfiguration? = nil
    ) throws(TLSError) -> DTLSEndpoint {
        let srtpConfiguration: DTLSSRTPConfiguration?
        if let mediaConfiguration {
            switch mediaConfiguration.protectionProfile {
            case .aes128CMHMACSHA180:
                srtpConfiguration = try DTLSSRTPConfiguration(
                    protectionProfiles: [.aes128CMHMACSHA180]
                )
            }
        } else {
            srtpConfiguration = nil
        }

        let configuration = DTLSConfiguration(
            identity: certificate.tlsIdentity,
            requireClientCertificate: requireClientCertificate,
            srtp: srtpConfiguration
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

    /// Timer token for the current DTLS flight.
    var retransmissionState: DTLSRetransmissionState {
        switch self {
        case .client(let client): return client.retransmissionState
        case .server(let server): return server.retransmissionState
        }
    }

    /// Handles a flight timeout only if `generation` still owns the timer.
    func handleTimeout(
        generation: UInt64
    ) throws(TLSError) -> DTLSTimeoutResult {
        switch self {
        case .client(let client):
            return try client.handleTimeout(generation: generation)
        case .server(let server):
            return try server.handleTimeout(generation: generation)
        }
    }

    /// Stops DTLS state and returns a close_notify datagram when one can be encoded.
    func close() throws(TLSError) -> [UInt8] {
        switch self {
        case .client(let client): return try client.close()
        case .server(let server): return try server.close()
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

    /// Direction-safe SRTP master key and salt material.
    ///
    /// The DTLS facade permits this only after a completed `use_srtp`
    /// negotiation. `WebRTCConnection` additionally gates access on peer
    /// fingerprint authentication before constructing any media context.
    func srtpKeyingMaterial() throws(TLSError) -> DTLSSRTPKeyingMaterial {
        switch self {
        case .client(let client):
            return try client.srtpKeyingMaterial()
        case .server(let server):
            return try server.srtpKeyingMaterial()
        }
    }
}
