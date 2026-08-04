/// The inner RTP/RTCP kind selected after the outer WebRTC datagram demux.
enum RTPRTCPPacketKind: Sendable, Equatable {
    case rtp
    case rtcp
}
