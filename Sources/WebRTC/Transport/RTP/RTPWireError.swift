/// Typed failures produced while decoding or encoding RTP and RTCP wire data.
public enum RTPWireError: Error, Sendable, Equatable {
    case insufficientBytes(field: RTPWireField, required: Int, available: Int)
    case invalidVersion(actual: UInt8)
    case invalidPayloadType(actual: UInt8)
    case tooManyContributingSources(actual: Int)
    case missingHeaderExtensionProfile
    case unexpectedHeaderExtensionData(byteCount: Int)
    case invalidHeaderExtensionAlignment(byteCount: Int)
    case headerExtensionTooLarge(byteCount: Int)
    case invalidHeaderExtensionLength(declaredWords: UInt16, availableBytes: Int)
    case invalidRTPPadding(count: UInt8, availableBytes: Int)
    case invalidRTCPPacketLength(packetIndex: Int, declaredBytes: Int, availableBytes: Int)
    case invalidRTCPPadding(packetIndex: Int, count: UInt8)
    case rtcpPaddingBeforeLast(packetIndex: Int)
    case compoundRequiresMultiplePackets(actual: Int)
    case compoundMustStartWithReport(actual: UInt8)
    case compoundMissingSourceDescriptionCNAME
    case malformedSourceDescription(packetIndex: Int)
    case packetLimitExceeded(limit: Int)
    case trailingRTCPBytes(count: Int)
    case integerOverflow
}
