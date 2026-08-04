/// Invalid RTP payload-type configuration for an RTP/RTCP-multiplexed session.
enum RTPMuxConfigurationError: Error, Sendable, Equatable {
    case payloadTypeOutOfRange(UInt8)
    case payloadTypeConflictsWithRTCP(UInt8)
}
