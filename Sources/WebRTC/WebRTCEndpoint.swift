/// WebRTC Endpoint
///
/// Main entry point for WebRTC Direct connections. Owns the DTLS certificate
/// and provides connection/listener creation.
///
/// Transport-agnostic: callers provide send handlers and feed incoming data
/// to connections. This allows integration with any UDP transport (NIO, etc).

import Synchronization
#if canImport(Logging)
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
    private let timer: WebRTCTimer
    private let endpointState: FacadeLock<EndpointState>

    private struct EndpointState: Sendable {
        var listeners: [WebRTCListener] = []
        var connections: [WebRTCConnection] = []
        var isClosed: Bool = false
    }

    public init(
        certificate: WebRTCCertificate,
        timer: WebRTCTimer = .platformDefault,
        logger: WebRTCLogger = WebRTCLogger(label: "webrtc")
    ) {
        self.certificate = certificate
        self.timer = timer
        self.logger = logger
        self.endpointState = FacadeLock(EndpointState())
    }

    /// Create an endpoint with a new Pure Swift self-signed certificate.
    ///
    /// Certificate generation is available on Native, WASI, and Embedded. An
    /// externally provisioned certificate remains available through
    /// `init(certificate:)` for deployments that keep identity material outside
    /// the process.
    public static func create<Clock: WebRTCCertificateClock>(
        clock: Clock = SystemWebRTCCertificateClock(),
        timer: WebRTCTimer = .platformDefault,
        logger: WebRTCLogger = WebRTCLogger(label: "webrtc")
    ) throws(WebRTCCertificateError) -> WebRTCEndpoint {
        let cert = try WebRTCCertificate.generateSelfSigned(clock: clock)
        return WebRTCEndpoint(
            certificate: cert,
            timer: timer,
            logger: logger
        )
    }

    // MARK: - Client connections

    /// Create a client-side connection to a remote peer
    ///
    /// - Parameters:
    ///   - remoteFingerprint: Expected certificate fingerprint of the remote peer
    ///   - sendHandler: Consuming bounded-transport admission closure. Success
    ///     means the transport accepted ownership; rejection is returned as a
    ///     typed ``WebRTCDatagramSendFailure``.
    /// - Returns: A new client-side WebRTC connection
    public func connect(
        remoteFingerprint: CertificateFingerprint,
        iceConfiguration: WebRTCICEConfiguration = .prevalidated,
        mediaConfiguration: WebRTCMediaConfiguration? = nil,
        negotiatedDataChannels: [WebRTCNegotiatedDataChannel] = [],
        sendHandler: @escaping WebRTCConnection.SendHandler
    ) throws(WebRTCError) -> WebRTCConnection {
        let connection = try WebRTCConnection.asClient(
            certificate: certificate,
            remoteFingerprint: remoteFingerprint,
            iceConfiguration: iceConfiguration,
            mediaConfiguration: mediaConfiguration,
            negotiatedDataChannels: negotiatedDataChannels,
            sendHandler: sendHandler,
            timer: timer,
            logger: logger
        )

        // Registration is the linearization point against `close()`. Construct
        // outside the lock, then atomically check-and-register. If close won,
        // dispose the unregistered candidate outside the critical section.
        let registered = endpointState.withLock { state -> Bool in
            guard !state.isClosed else { return false }
            state.connections.append(connection)
            return true
        }
        guard registered else {
            connection.close()
            throw WebRTCError.closed
        }

        logger.info("Created client connection")

        return connection
    }

    // MARK: - Server listeners

    /// Create a server-side listener
    ///
    /// - Returns: A new WebRTC listener that accepts incoming connections
    public func listen(
        iceConfiguration: WebRTCICEConfiguration = .prevalidated,
        mediaConfiguration: WebRTCMediaConfiguration? = nil,
        negotiatedDataChannels: [WebRTCNegotiatedDataChannel] = []
    ) throws(WebRTCError) -> WebRTCListener {
        let listener = WebRTCListener(
            certificate: certificate,
            iceConfiguration: iceConfiguration,
            mediaConfiguration: mediaConfiguration,
            negotiatedDataChannels: negotiatedDataChannels,
            timer: timer,
            logger: logger
        )

        // Use the same registration linearization point as `connect()`. A
        // listener that loses to close is shut down before the failure escapes.
        let registered = endpointState.withLock { state -> Bool in
            guard !state.isClosed else { return false }
            state.listeners.append(listener)
            return true
        }
        guard registered else {
            listener.close()
            throw WebRTCError.closed
        }

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
