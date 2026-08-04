/// The protected packet family associated with an SRTP failure.
public enum SRTPPacketKind: Sendable, Equatable {
    case rtp
    case rtcp
}
