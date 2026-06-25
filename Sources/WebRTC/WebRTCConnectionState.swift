/// WebRTC Connection State

/// WebRTC connection lifecycle state
public enum WebRTCConnectionState: Sendable, Equatable {
    /// Initial state
    case new
    /// ICE connectivity check in progress
    case connecting
    /// DTLS handshake in progress
    case dtlsHandshaking
    /// SCTP association in progress
    case sctpConnecting
    /// Fully connected, data channels available
    case connected
    /// Connection disconnected (may recover)
    case disconnected
    /// Connection failed
    case failed(String)
    /// Connection closed
    case closed
}

extension WebRTCConnectionState {
    /// Whether the connection can never become usable again.
    ///
    /// `disconnected` is not terminal — it may recover.
    public var isTerminal: Bool {
        switch self {
        case .failed, .closed:
            return true
        case .new, .connecting, .dtlsHandshaking, .sctpConnecting, .connected, .disconnected:
            return false
        }
    }

    /// A stable, Embedded-legal label for the state case.
    ///
    /// `String(describing:)` / reflection-based interpolation is unavailable under
    /// Embedded Swift, so diagnostic messages render the state through this manual
    /// `switch` over string literals (the `.failed` reason is intentionally not
    /// interpolated, as that reason is itself an Embedded-static string).
    public var label: String {
        switch self {
        case .new: return "new"
        case .connecting: return "connecting"
        case .dtlsHandshaking: return "dtlsHandshaking"
        case .sctpConnecting: return "sctpConnecting"
        case .connected: return "connected"
        case .disconnected: return "disconnected"
        case .failed: return "failed"
        case .closed: return "closed"
        }
    }
}
