/// WebRTC Connection State

import Foundation

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
}
