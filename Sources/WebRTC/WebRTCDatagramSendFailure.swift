/// A synchronous transport rejection for one outbound WebRTC datagram.
///
/// The send handler returns success only after the transport has accepted
/// ownership of the datagram into its bounded send path. Success does not imply
/// remote delivery. On failure, the handler must not retain the datagram.
public enum WebRTCDatagramSendFailure: Error, Equatable, Sendable {
    /// The transport has shut down and cannot accept more datagrams.
    case closed

    /// The bounded transport queue cannot accept the datagram now.
    case backpressured

    /// The datagram exceeds the transport's configured payload limit.
    case datagramTooLarge(actualByteCount: Int, maximumByteCount: Int)

    /// The selected destination is currently unreachable.
    case destinationUnreachable

    /// A platform transport operation failed with its native integer code.
    case systemError(code: Int32)

    /// The platform transport failed without a stable native error code.
    case transportUnavailable
}
