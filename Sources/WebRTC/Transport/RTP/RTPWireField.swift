/// A bounded field inspected while decoding RTP or RTCP wire data.
public enum RTPWireField: Sendable, Equatable {
    case rtpFixedHeader
    case rtpContributingSources
    case rtpHeaderExtensionHeader
    case rtpHeaderExtensionData
    case rtpPadding
    case rtcpCommonHeader
    case rtcpPacket
    case rtcpSenderReport
    case rtcpReceiverReport
    case rtcpSourceDescription
}
