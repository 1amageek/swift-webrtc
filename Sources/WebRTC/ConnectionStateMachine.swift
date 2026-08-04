/// Connection State Machine
///
/// Unified state management for ICE/DTLS/SCTP protocol layers.
/// Coordinates state transitions and ensures consistent error propagation.


/// Sub-protocol states tracked by the state machine
struct ProtocolStates: Sendable, Equatable {
    var ice: ICEState
    var dtls: DTLSState
    var sctp: SCTPAssociationState

    init(
        ice: ICEState = .new,
        dtls: DTLSState = .new,
        sctp: SCTPAssociationState = .closed
    ) {
        self.ice = ice
        self.dtls = dtls
        self.sctp = sctp
    }
}

/// DTLS connection state (simplified view for state machine)
enum DTLSState: Sendable, Equatable {
    case new
    case handshaking
    case connected
    case failed(String)
    case closed
}

/// Events that can trigger state transitions
enum ConnectionEvent: Sendable {
    // ICE events
    case iceConnected
    case iceFailed
    case iceClosed

    // DTLS events
    case dtlsHandshakeStarted
    case dtlsHandshakeComplete
    case dtlsHandshakeFailed(String)
    case dtlsClosed

    // SCTP events
    case sctpAssociating
    case sctpEstablished
    case sctpShutdownStarted(SCTPAssociationState)
    @available(
        *,
        deprecated,
        message: "The connection owner must preserve SCTPError as WebRTCError.sctpProtocolFailed."
    )
    case sctpFailed(String)
    case sctpClosed

    // User events
    case userClose
    case error(String)
}

/// Unified connection state machine
///
/// Manages the WebRTC connection lifecycle by coordinating state transitions
/// across ICE, DTLS, and SCTP protocol layers. Any failure in a sub-protocol
/// causes the entire connection to transition to the failed state.
struct ConnectionStateMachine: Sendable {

    /// Current unified connection state
    private(set) var state: WebRTCConnectionState

    /// Current sub-protocol states
    private(set) var protocolStates: ProtocolStates

    /// Failure reason if in failed state
    var failureReason: String? {
        if case .failed(let reason) = state {
            return reason
        }
        return nil
    }

    init() {
        self.state = .new
        self.protocolStates = ProtocolStates()
    }

    /// Process an event and transition to the appropriate state
    /// - Parameter event: The event to process
    /// - Returns: The resulting state after processing the event
    @discardableResult
    mutating func process(_ event: ConnectionEvent) -> WebRTCConnectionState {
        // Terminal states don't transition
        guard !isTerminal else { return state }

        switch event {
        // ICE events
        case .iceConnected:
            protocolStates.ice = .connected
            if state == .new || state == .connecting {
                state = .connecting
            }

        case .iceFailed:
            protocolStates.ice = .failed
            transitionToFailed("ICE connection failed")

        case .iceClosed:
            protocolStates.ice = .closed

        // DTLS events
        case .dtlsHandshakeStarted:
            protocolStates.dtls = .handshaking
            // Transition from new/connecting to dtlsHandshaking
            if state == .new || state == .connecting {
                state = .dtlsHandshaking
            }

        case .dtlsHandshakeComplete:
            protocolStates.dtls = .connected
            if state == .dtlsHandshaking {
                state = .sctpConnecting
            }

        case .dtlsHandshakeFailed(let reason):
            protocolStates.dtls = .failed(reason)
            transitionToFailed("DTLS handshake failed: \(reason)")

        case .dtlsClosed:
            protocolStates.dtls = .closed

        // SCTP events
        case .sctpAssociating:
            protocolStates.sctp = .cookieWait
            if state == .sctpConnecting {
                // Already in sctpConnecting, no change needed
            }

        case .sctpEstablished:
            protocolStates.sctp = .established
            if state == .sctpConnecting {
                state = .connected
            }

        case .sctpShutdownStarted(let sctpState):
            switch sctpState {
            case .shutdownPending, .shutdownSent, .shutdownReceived,
                 .shutdownAckSent:
                protocolStates.sctp = sctpState
                if state == .connected {
                    state = .closing
                }
            case .closed, .cookieWait, .cookieEchoed, .established:
                break
            }

        case .sctpFailed(let reason):
            protocolStates.sctp = .closed
            transitionToFailed("SCTP failed: \(reason)")

        case .sctpClosed:
            transitionToClosed()

        // User events
        case .userClose:
            transitionToClosed()

        case .error(let reason):
            transitionToFailed(reason)
        }

        return state
    }

    /// Whether the state machine is in a terminal state (closed or failed)
    var isTerminal: Bool {
        switch state {
        case .closed, .failed:
            return true
        default:
            return false
        }
    }

    /// Whether the connection is ready for application data
    var isConnected: Bool {
        state == .connected
    }

    /// Whether ICE connectivity has been established
    var isICEConnected: Bool {
        switch protocolStates.ice {
        case .connected, .completed:
            return true
        default:
            return false
        }
    }

    /// Whether DTLS handshake is complete
    var isDTLSConnected: Bool {
        protocolStates.dtls == .connected
    }

    /// Whether SCTP association is established
    var isSCTPEstablished: Bool {
        protocolStates.sctp == .established
    }

    // MARK: - Private helpers

    private mutating func transitionToFailed(_ reason: String) {
        state = .failed(reason)
        protocolStates.ice = .failed
        protocolStates.dtls = .failed(reason)
        protocolStates.sctp = .closed
    }

    private mutating func transitionToClosed() {
        state = .closed
        protocolStates.ice = .closed
        protocolStates.dtls = .closed
        protocolStates.sctp = .closed
    }
}

// MARK: - State predicates

extension ConnectionStateMachine {
    /// Check if DTLS processing should be allowed
    ///
    /// DTLS packets must be processed during the handshake and after it
    /// completes (for encrypted application data like SCTP).
    ///
    /// WebRTC Direct skips ICE, so we cannot gate on ICE state alone.
    func shouldProcessDTLS() -> Bool {
        // Don't process in terminal states
        guard !isTerminal else { return false }

        // Allow DTLS processing if DTLS is active (handshaking or established)
        switch protocolStates.dtls {
        case .handshaking, .connected:
            return true
        default:
            break
        }

        // Allow DTLS processing if ICE is connected/completed
        switch protocolStates.ice {
        case .connected, .completed:
            return true
        case .checking:
            // During ICE checking, we may receive DTLS packets
            // Allow processing to support aggressive nomination
            return true
        default:
            // ICE not yet connected, but check if we're already in DTLS handshake state
            return state == .dtlsHandshaking
        }
    }

    /// Check if SCTP processing should be allowed
    func shouldProcessSCTP() -> Bool {
        guard !isTerminal else { return false }
        return protocolStates.dtls == .connected
    }
}
