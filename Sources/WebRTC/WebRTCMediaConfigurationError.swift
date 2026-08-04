/// Typed failures raised while validating WebRTC media negotiation policy.
public enum WebRTCMediaConfigurationError: Error, Sendable, Equatable {
    /// At least one negotiated RTP payload type is required for an RTP media path.
    case emptyRTPPayloadTypes

    /// An RTP payload type appeared more than once.
    case duplicateRTPPayloadType(UInt8)

    /// RFC 5761 reserves this payload-type interval when RTP and RTCP share a port.
    case rtpRTCPMuxConflict(UInt8)
}
