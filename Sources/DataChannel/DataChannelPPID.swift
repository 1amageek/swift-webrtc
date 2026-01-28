/// WebRTC Data Channel Payload Protocol Identifiers (RFC 8831)
///
/// PPID values for SCTP DATA chunks in WebRTC context.

import Foundation

/// Payload Protocol Identifiers for WebRTC Data Channels
public enum DataChannelPPID: UInt32, Sendable {
    /// WebRTC DCEP (Data Channel Establishment Protocol)
    case dcep = 50

    /// WebRTC String (UTF-8)
    case string = 51

    /// WebRTC Binary
    case binary = 53

    /// WebRTC String (empty)
    case stringEmpty = 56

    /// WebRTC Binary (empty)
    case binaryEmpty = 57
}
