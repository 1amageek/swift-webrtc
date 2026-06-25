/// WebRTC Endpoint
///
/// Main entry point for WebRTC Direct connections. Owns the DTLS certificate
/// and provides connection/listener creation.
///
/// Transport-agnostic: callers provide send handlers and feed incoming data
/// to connections. This allows integration with any UDP transport (NIO, etc).

import STUNCore
import ICELite
import SCTPCore
import DataChannel
#if !hasFeature(Embedded)
import Foundation
import Logging
#endif

/// WebRTC Direct endpoint for creating connections and listeners
public final class WebRTCEndpoint: Sendable {
    /// The DTLS certificate for this endpoint
    public let certificate: WebRTCCertificate

    /// The local certificate fingerprint
    public var localFingerprint: CertificateFingerprint {
        certificate.fingerprint
    }

    private let logger: WebRTCLogger
    private let endpointState: FacadeLock<EndpointState>

    private struct EndpointState: Sendable {
        var listeners: [WebRTCListener] = []
        var connections: [WebRTCConnection] = []
        var isClosed: Bool = false
    }

    public init(certificate: WebRTCCertificate, logger: WebRTCLogger = WebRTCLogger(label: "webrtc")) {
        self.certificate = certificate
        self.logger = logger
        self.endpointState = FacadeLock(EndpointState())
    }

    /// Create an endpoint with a new self-signed certificate.
    ///
    /// Host-only: self-signed X.509 generation needs swift-certificates /
    /// swift-asn1, which are unavailable under Embedded. Under Embedded the
    /// embedder must supply a `WebRTCCertificate` (DER + raw key) externally and
    /// construct the endpoint via `init(certificate:)`. There is no silent
    /// fallback: the convenience constructor simply does not exist there.
    #if !hasFeature(Embedded)
    public static func create(logger: WebRTCLogger = WebRTCLogger(label: "webrtc")) throws -> WebRTCEndpoint {
        let cert = try WebRTCCertificate.generateSelfSigned()
        return WebRTCEndpoint(certificate: cert, logger: logger)
    }
    #endif

    // MARK: - Client connections

    /// Create a client-side connection to a remote peer
    ///
    /// - Parameters:
    ///   - remoteFingerprint: Expected certificate fingerprint of the remote peer
    ///   - sendHandler: Closure to send raw bytes to the remote peer
    /// - Returns: A new client-side WebRTC connection
    public func connect(
        remoteFingerprint: CertificateFingerprint,
        sendHandler: @escaping WebRTCConnection.SendHandler
    ) throws -> WebRTCConnection {
        let isClosed = endpointState.withLock { $0.isClosed }
        guard !isClosed else {
            throw WebRTCError.closed
        }

        let connection = WebRTCConnection.asClient(
            certificate: certificate,
            remoteFingerprint: remoteFingerprint,
            sendHandler: sendHandler,
            logger: logger
        )

        endpointState.withLock { $0.connections.append(connection) }
        logger.info("Created client connection")

        return connection
    }

    // MARK: - Server listeners

    /// Create a server-side listener
    ///
    /// - Returns: A new WebRTC listener that accepts incoming connections
    public func listen() throws -> WebRTCListener {
        let isClosed = endpointState.withLock { $0.isClosed }
        guard !isClosed else {
            throw WebRTCError.closed
        }

        let listener = WebRTCListener(
            certificate: certificate,
            logger: logger
        )

        endpointState.withLock { $0.listeners.append(listener) }
        logger.info("Created WebRTC listener")

        return listener
    }

    // MARK: - Lifecycle

    /// Close the endpoint and all connections/listeners
    public func close() {
        let (listeners, connections) = endpointState.withLock { state -> ([WebRTCListener], [WebRTCConnection]) in
            state.isClosed = true
            let l = state.listeners
            let c = state.connections
            state.listeners.removeAll()
            state.connections.removeAll()
            return (l, c)
        }

        for listener in listeners {
            listener.close()
        }
        for connection in connections {
            connection.close()
        }

        logger.info("WebRTC endpoint closed")
    }
}
