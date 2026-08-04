import WebRTC
/// Typed configuration, packet, ordering, and reassembly failures.
public enum H264RTPReceiverError: Error, Sendable, Equatable {
    case invalidPayloadType(actual: UInt8)
    case unsupportedPacketizationMode(H264PacketizationMode)
    case invalidMaximumPacketByteCount(actual: Int)
    case invalidMaximumAccessUnitByteCount(actual: Int)
    case invalidMaximumAccessUnitInputByteCount(actual: Int, minimum: Int)
    case invalidMaximumAccessUnitDurationNanoseconds(actual: UInt64)
    case invalidMaximumPacketsPerAccessUnit(actual: Int)
    case invalidMaximumNALUnitsPerAccessUnit(actual: Int)
    case invalidMaximumReorderPacketCount(actual: Int)
    case invalidMaximumReorderByteCount(actual: Int, minimum: Int)
    case invalidMaximumReorderDelayNanoseconds(actual: UInt64)
    case invalidAnnexBStartCodeByteCount(actual: Int)
    case invalidAVCCLengthFieldByteCount(actual: Int)
    case packetOwnerByteCountMismatch(expected: Int, actual: Int)
    case packetLayoutOwnerMismatch
    case packetExceedsMaximum(actual: Int, maximum: Int)
    case unexpectedPayloadType(expected: UInt8, actual: UInt8)
    case unexpectedSynchronizationSource(expected: UInt32, actual: UInt32)
    case invalidPayloadRange
    case decreasingArrivalTime(previous: UInt64, current: UInt64)
    case receiveInProgress
    case accessUnitPacketLimitExceeded(actual: Int, maximum: Int)
    case accessUnitNALUnitLimitExceeded(actual: Int, maximum: Int)
    case accessUnitByteLimitExceeded(minimumActual: Int, maximum: Int)
    case accessUnitInputByteLimitExceeded(minimumActual: Int, maximum: Int)
    case accessUnitAssemblyTimedOut(elapsed: UInt64, maximum: UInt64)
    case packetAfterMarkerForCompletedTimestamp(timestamp: UInt32)
    case fragmentationUnitWithoutStart
    case fragmentationUnitHeaderMismatch(expected: UInt8, actual: UInt8)
    case fragmentationUnitInterrupted
    case markerBeforeFragmentationUnitEnd
    case nalUnitLengthExceedsOutputFormat(actual: Int, maximum: Int)
    case h264Payload(H264RTPPayloadError)
    case rtpWire(RTPWireError)
    case integerOverflow
}

/// Failure from receiver processing or the decoder-bound access-unit sink.
public enum H264RTPReceiveError<SinkFailure>: Error, Sendable
where SinkFailure: Error & Sendable {
    case receiver(H264RTPReceiverError)
    case receiverAfterProgress(
        H264RTPReceiverError,
        effects: H264RTPReceiveReport
    )
    case sink(
        SinkFailure,
        effects: H264RTPReceiveReport
    )
}

extension H264RTPReceiveError: Equatable where SinkFailure: Equatable {}
