/// Per-message persistence policy negotiated by a WebRTC data channel.
public enum DataChannelReliability: Sendable, Equatable {
    /// Retransmit until SCTP either acknowledges the message or the association
    /// reaches its terminal path-failure policy.
    case reliable

    /// Abandon the complete message before attempting a retransmission beyond
    /// this count. The initial transmission is not a retransmission, so zero
    /// means that a lost message is never retransmitted.
    case maximumRetransmissions(UInt32)

    /// Abandon the complete message once this many monotonic milliseconds have
    /// elapsed since the application handed it to SCTP.
    case maximumLifetimeMilliseconds(UInt32)
}
