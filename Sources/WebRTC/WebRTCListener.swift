/// WebRTC Listener
///
/// Server-side listener that accepts incoming WebRTC connections.
/// Transport-agnostic: the transport layer feeds incoming data
/// and provides a send handler per connection.

import Synchronization
#if canImport(Logging)
import Logging
#endif
// REQUIRED under Embedded for `AsyncStream` (probe P10); the host build picks it
// up from the implicit stdlib import, but the Embedded build needs the explicit
// `_Concurrency` import to bring `AsyncStream` into scope.
import _Concurrency

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
    private let iceConfiguration: WebRTCICEConfiguration
    private let mediaConfiguration: WebRTCMediaConfiguration?
    private let negotiatedDataChannels: [WebRTCNegotiatedDataChannel]
    private let timer: WebRTCTimer
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
        iceConfiguration: WebRTCICEConfiguration = .prevalidated,
        mediaConfiguration: WebRTCMediaConfiguration? = nil,
        negotiatedDataChannels: [WebRTCNegotiatedDataChannel] = [],
        timer: WebRTCTimer = .platformDefault,
        logger: WebRTCLogger = WebRTCLogger(label: "webrtc.listener")
    ) {
        self.certificate = certificate
        self.iceConfiguration = iceConfiguration
        self.mediaConfiguration = mediaConfiguration
        self.negotiatedDataChannels = negotiatedDataChannels
        self.timer = timer
        self.localFingerprint = certificate.fingerprint
        self.logger = logger
        // Create the stream eagerly so connections accepted before the first
        // subscription are buffered rather than dropped
        let (stream, continuation) = AsyncStream<WebRTCConnection>.makeStream()
        self.listenerState = FacadeLock(ListenerState(stream: stream, continuation: continuation))
    }

    // MARK: - Connection acceptance

    private func serverConnection(
        remoteFingerprint: CertificateFingerprint?,
        iceConfiguration: WebRTCICEConfiguration?,
        sendHandler: @escaping WebRTCConnection.SendHandler
    ) -> Result<WebRTCConnection, WebRTCError> {
        do {
            return .success(try WebRTCConnection.asServer(
                certificate: certificate,
                remoteFingerprint: remoteFingerprint,
                iceConfiguration: iceConfiguration ?? self.iceConfiguration,
                mediaConfiguration: mediaConfiguration,
                negotiatedDataChannels: negotiatedDataChannels,
                sendHandler: sendHandler,
                timer: timer,
                logger: logger
            ))
        } catch {
            return .failure(error)
        }
    }

    private func startConnection(
        _ connection: WebRTCConnection
    ) -> Result<Void, WebRTCError> {
        do {
            try connection.start()
            return .success(())
        } catch {
            return .failure(error)
        }
    }

    /// Accept a new incoming connection from a remote peer
    ///
    /// Call this when the transport layer detects a new peer (e.g., a new
    /// source address on the UDP socket).
    ///
    /// - Parameters:
    ///   - peerID: Unique identifier for this peer (e.g., "ip:port")
    ///   - remoteFingerprint: Signaling-bound peer identity. Required when the
    ///     listener was created with media enabled.
    ///   - sendHandler: Consuming bounded-transport admission closure. Success
    ///     means the transport accepted ownership; rejection is returned as a
    ///     typed ``WebRTCDatagramSendFailure``.
    /// - Returns: The new server-side connection, or nil if listener is closed
    public func acceptConnection(
        peerID: String,
        remoteFingerprint: CertificateFingerprint? = nil,
        iceConfiguration: WebRTCICEConfiguration? = nil,
        sendHandler: @escaping WebRTCConnection.SendHandler
    ) throws(WebRTCError) -> WebRTCConnection? {
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
            case constructionFailed(WebRTCError)
            case existing(WebRTCConnection)
            case claimed(WebRTCConnection, terminalToClose: WebRTCConnection?)
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
                let connection: WebRTCConnection
                switch serverConnection(
                    remoteFingerprint: remoteFingerprint,
                    iceConfiguration: iceConfiguration,
                    sendHandler: sendHandler
                ) {
                case .success(let created):
                    connection = created
                case .failure(let error):
                    return .constructionFailed(error)
                }
                state.activeConnections[peerID] = connection
                return .claimed(connection, terminalToClose: existing)
            }

            let connection: WebRTCConnection
            switch serverConnection(
                remoteFingerprint: remoteFingerprint,
                iceConfiguration: iceConfiguration,
                sendHandler: sendHandler
            ) {
            case .success(let created):
                connection = created
            case .failure(let error):
                return .constructionFailed(error)
            }
            state.activeConnections[peerID] = connection
            return .claimed(connection, terminalToClose: nil)
        }

        switch outcome {
        case .closed:
            return nil
        case .constructionFailed(let error):
            throw error
        case .existing(let existing):
            return existing
        case .claimed(let connection, let terminalToClose):
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
            switch startConnection(connection) {
            case .success:
                break
            case .failure(let error):
                // `String(describing:)` is unavailable under Embedded, so the
                // caught error is not interpolated here; the static log line
                // records the failure without reconstructing the error text.
                logger.error("Failed to start server connection")
                listenerState.withLock { state in
                    if state.activeConnections[peerID] === connection {
                        state.activeConnections.removeValue(forKey: peerID)
                    }
                }
                connection.close()
                throw error
            }

            // Starting the connection is intentionally outside `listenerState`.
            // Re-enter once to publish only if this listener is still open and
            // this accept operation still owns the peer slot. `close()` detaches
            // and finishes the continuation before closing its connection
            // snapshot, so a close that wins this race makes `yield` terminate
            // instead of publishing a closed connection.
            let continuation = listenerState.withLock { state -> AsyncStream<WebRTCConnection>.Continuation? in
                guard !state.isClosed,
                      state.activeConnections[peerID] === connection else {
                    return nil
                }
                return state.continuation
            }
            guard let continuation else {
                connection.close()
                return nil
            }

            if case .terminated = continuation.yield(connection) {
                listenerState.withLock { state in
                    if state.activeConnections[peerID] === connection {
                        state.activeConnections.removeValue(forKey: peerID)
                    }
                }
                connection.close()
                return nil
            }

            logger.info("Accepted new connection from peer: \(peerID)")
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

    /// Finish the public connection stream and close every active connection.
    ///
    /// This is the explicit lifecycle endpoint for consumers of ``connections``.
    /// It delegates to the existing authoritative close path, so calling
    /// `shutdown()` or `close()` repeatedly has the same idempotent behavior.
    public func shutdown() {
        close()
    }

    /// Close the listener and all active connections
    public func close() {
        let shutdown = listenerState.withLock { state -> (
            continuation: AsyncStream<WebRTCConnection>.Continuation?,
            connections: [WebRTCConnection]
        ) in
            state.isClosed = true
            let conns = Array(state.activeConnections.values)
            state.activeConnections.removeAll()
            let continuation = state.continuation
            state.continuation = nil
            return (continuation, conns)
        }

        // Event delivery must never run while `listenerState` is locked. Finish
        // first: an in-flight accept that has captured this continuation will
        // observe `.terminated` before the corresponding connection is closed.
        shutdown.continuation?.finish()

        for connection in shutdown.connections {
            connection.close()
        }

        logger.info("WebRTC listener closed")
    }
}
