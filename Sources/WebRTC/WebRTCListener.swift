/// WebRTC Listener
///
/// Server-side listener that accepts incoming WebRTC connections.
/// Transport-agnostic: the transport layer feeds incoming data
/// and provides a send handler per connection.

import Foundation
import Synchronization
import DTLSCore
import ICELite
import Logging

/// A WebRTC listener that accepts incoming connections
public final class WebRTCListener: Sendable {

    // MARK: - Public properties

    /// The local certificate fingerprint
    public let localFingerprint: CertificateFingerprint

    /// Stream of accepted connections
    public var connections: AsyncStream<WebRTCConnection> {
        listenerState.withLock { state in
            if let existing = state.stream { return existing }
            let (stream, continuation) = AsyncStream<WebRTCConnection>.makeStream()
            state.stream = stream
            state.continuation = continuation
            return stream
        }
    }

    // MARK: - Private state

    private let certificate: DTLSCertificate
    private let logger: Logger
    private let listenerState: Mutex<ListenerState>

    private struct ListenerState: Sendable {
        var stream: AsyncStream<WebRTCConnection>?
        var continuation: AsyncStream<WebRTCConnection>.Continuation?
        var activeConnections: [String: WebRTCConnection] = [:]
        var isClosed: Bool = false
    }

    // MARK: - Init

    public init(
        certificate: DTLSCertificate,
        logger: Logger = Logger(label: "webrtc.listener")
    ) {
        self.certificate = certificate
        self.localFingerprint = certificate.fingerprint
        self.logger = logger
        self.listenerState = Mutex(ListenerState())
    }

    // MARK: - Connection acceptance

    /// Accept a new incoming connection from a remote peer
    ///
    /// Call this when the transport layer detects a new peer (e.g., a new
    /// source address on the UDP socket).
    ///
    /// - Parameters:
    ///   - peerID: Unique identifier for this peer (e.g., "ip:port")
    ///   - sendHandler: Closure to send data back to this peer
    /// - Returns: The new server-side connection, or nil if listener is closed
    public func acceptConnection(
        peerID: String,
        sendHandler: @escaping WebRTCConnection.SendHandler
    ) -> WebRTCConnection? {
        let isClosed = listenerState.withLock { $0.isClosed }
        if isClosed { return nil }

        // Check if connection already exists
        let existing = listenerState.withLock { $0.activeConnections[peerID] }
        if let existing { return existing }

        let connection = WebRTCConnection.asServer(
            certificate: certificate,
            sendHandler: sendHandler,
            logger: logger
        )

        let continuation = listenerState.withLock { state -> AsyncStream<WebRTCConnection>.Continuation? in
            state.activeConnections[peerID] = connection
            return state.continuation
        }

        logger.info("Accepted new connection from peer: \(peerID)")
        continuation?.yield(connection)

        return connection
    }

    /// Get an existing connection by peer ID
    public func connection(for peerID: String) -> WebRTCConnection? {
        listenerState.withLock { $0.activeConnections[peerID] }
    }

    /// Remove a connection by peer ID
    public func removeConnection(peerID: String) {
        let conn = listenerState.withLock { state -> WebRTCConnection? in
            state.activeConnections.removeValue(forKey: peerID)
        }
        conn?.close()
    }

    // MARK: - Lifecycle

    /// Close the listener and all active connections
    public func close() {
        let connections = listenerState.withLock { state -> [WebRTCConnection] in
            state.isClosed = true
            let conns = Array(state.activeConnections.values)
            state.activeConnections.removeAll()
            state.continuation?.finish()
            state.continuation = nil
            state.stream = nil
            return conns
        }

        for connection in connections {
            connection.close()
        }

        logger.info("WebRTC listener closed")
    }
}
