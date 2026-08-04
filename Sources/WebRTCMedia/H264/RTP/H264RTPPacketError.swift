import WebRTC
/// Typed failures while assembling one plaintext H.264 RTP packet.
public enum H264RTPPacketError: Error, Sendable, Equatable {
    case invalidMaximumDatagramByteCount(actual: Int)
    case invalidProtectionTrailerByteCount(actual: Int)
    case packetExceedsMaximum(actual: Int, maximum: Int)
    case rtpHeader(RTPWireError)
    case h264Payload(H264RTPPayloadError)
    case assembledByteCountMismatch(expected: Int, actual: Int)
    case integerOverflow
}
