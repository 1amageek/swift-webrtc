import WebRTC
/// Typed sender-policy and packet-construction failures.
public enum H264RTPSenderError: Error, Equatable, Sendable {
    case invalidPayloadType(actual: UInt8)
    case invalidMaximumDatagramByteCount(actual: Int)
    case invalidProtectionTrailerByteCount(actual: Int)
    case invalidMaximumPacketsPerAccessUnit(actual: Int)
    case unsupportedPacketizationMode(H264PacketizationMode)
    case tooManyContributingSources(actual: Int)
    case insufficientDatagramCapacity(
        headerAndTrailerByteCount: Int,
        maximumDatagramByteCount: Int
    )
    case sendInProgress
    case accessUnitPacketLimitExceeded(minimumActual: Int, maximum: Int)
    case decreasingCaptureTime(previous: UInt64, current: UInt64)
    case packetCountMismatch(expected: Int, actual: Int)
    case byteCountOverflow
    case rtpHeader(RTPWireError)
    case h264Payload(H264RTPPayloadError)
    case packetAssembly(H264RTPPacketError)
}

/// Failure from either sender construction or the downstream packet sink.
public enum H264RTPSendError<SinkFailure>: Error, Sendable
where SinkFailure: Error & Sendable {
    case sender(H264RTPSenderError)
    case senderAfterPartialDelivery(
        H264RTPSenderError,
        sentPacketCount: Int
    )
    case sink(SinkFailure, sentPacketCount: Int)
}

extension H264RTPSendError: Equatable where SinkFailure: Equatable {}
