/// WebRTC Listener
///
/// Server-side listener that accepts incoming WebRTC connections.
/// Transport-agnostic: the transport layer feeds incoming data
/// and provides a send handler per connection.

import Foundation
import ICELite
#if !hasFeature(Embedded)
import Logging
#endif

/// A WebRTC listener that accepts incoming connections
public final class WebRTCListener: Sendable {

    // MARK: - Public properties

    /// The local certificate fingerprint
    public let localFingerprint: CertificateFingerprint

    /// Stream of accepted connections.
    ///
    /// The stream is created eagerly at init, so connections accepted before
    /// the first subscription are buffered rather than dropped.
    public var connections: AsyncStream<WebRTCConnection> {
        listenerState.withLock { $0.stream }
    }

    // MARK: - Private state

    private let certificate: WebRTCCertificate
    private let logger: WebRTCLogger
    private let listenerState: FacadeLock<ListenerState>

    private struct ListenerState: Sendable {
        var stream: AsyncStream<WebRTCConnection>
        var continuation: AsyncStream<WebRTCConnection>.Continuation?
        var activeConnections: [String: WebRTCConnection] = [:]
        var isClosed: Bool = false
    }

    // MARK: - Init

    public init(
        certificate: WebRTCCertificate,
        logger: WebRTCLogger = WebRTCLogger(label: "webrtc.listener")
    ) {
        self.certificate = certificate
        self.localFingerprint = certificate.fingerprint
        self.logger = logger
        // Create the stream eagerly so connections accepted before the first
        // subscription are buffered rather than dropped
        let (stream, continuation) = AsyncStream<WebRTCConnection>.makeStream()
        self.listenerState = FacadeLock(ListenerState(stream: stream, continuation: continuation))
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
        // Check-and-claim is ONE critical section: a concurrent accept for the
        // same peerID must not let two callers both pass the nil-check and create
        // two connections (the second would orphan the first's retransmitTask /
        // DTLS state). Under the single lock we either return the live existing
        // connection, or atomically claim the slot with a freshly-created
        // connection (evicting a terminal one first). The connection is created
        // inside the lock — only object construction, no I/O — so the claim is
        // inseparable from the check.
        enum ClaimOutcome {
            case closed
            case existing(WebRTCConnection)
            case claimed(WebRTCConnection, terminalToClose: WebRTCConnection?, AsyncStream<WebRTCConnection>.Continuation?)
        }

        let outcome = listenerState.withLock { state -> ClaimOutcome in
            if state.isClosed { return .closed }

            if let existing = state.activeConnections[peerID] {
                if !existing.state.isTerminal {
                    return .existing(existing)
                }
                // A terminal (failed/closed) connection is replaced by a fresh
                // one so the peer can reconnect from the same address.
                state.activeConnections.removeValue(forKey: peerID)
                // Claim the slot atomically with the eviction.
                let connection = WebRTCConnection.asServer(
                    certificate: certificate,
                    sendHandler: sendHandler,
                    logger: logger
                )
                state.activeConnections[peerID] = connection
                return .claimed(connection, terminalToClose: existing, state.continuation)
            }

            let connection = WebRTCConnection.asServer(
                certificate: certificate,
                sendHandler: sendHandler,
                logger: logger
            )
            state.activeConnections[peerID] = connection
            return .claimed(connection, terminalToClose: nil, state.continuation)
        }

        switch outcome {
        case .closed:
            return nil
        case .existing(let existing):
            return existing
        case .claimed(let connection, let terminalToClose, let continuation):
            if let terminalToClose {
                logger.info("Replacing terminal connection for peer: \(peerID)")
                terminalToClose.close()
            }

            // Initialize the server-side DTLS handshake state machine.
            // This transitions to .dtlsHandshaking so incoming ClientHello
            // packets pass the shouldProcessDTLS() gate. The slot is already
            // claimed, so a concurrent accept observes this connection rather
            // than creating a competing one. If start() fails, relinquish the
            // claim (only if we still own it) so the peer can retry.
            do {
                try connection.start()
            } catch {
                logger.error("Failed to start server connection: \(error)")
                listenerState.withLock { state in
                    if state.activeConnections[peerID] === connection {
                        state.activeConnections.removeValue(forKey: peerID)
                    }
                }
                return nil
            }

            logger.info("Accepted new connection from peer: \(peerID)")
            continuation?.yield(connection)

            return connection
        }
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
            return conns
        }

        for connection in connections {
            connection.close()
        }

        logger.info("WebRTC listener closed")
    }
}
