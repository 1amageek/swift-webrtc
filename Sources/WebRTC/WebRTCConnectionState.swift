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
