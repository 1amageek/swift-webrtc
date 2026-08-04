/// Typed failures produced by RFC 6184 payload validation and encoding.
public enum H264RTPPayloadError: Error, Sendable, Equatable {
    case emptyAccessUnit
    case emptyPayload
    case unsupportedPacketizationMode(H264PacketizationMode)
    case invalidMaximumPayloadByteCount(actual: Int)
    case nalUnitRangeOutOfBounds(
        index: Int,
        lowerBound: Int,
        upperBound: Int,
        ownerByteCount: Int
    )
    case unorderedOrOverlappingNALUnitRange(index: Int)
    case emptyNALUnit(index: Int)
    case forbiddenBitSet
    case reservedNALUnitType(UInt8)
    case packetizationUnitProvidedAsNALUnit(index: Int, type: UInt8)
    case packetTypeNotAllowed(mode: H264PacketizationMode, type: UInt8)
    case nalUnitExceedsSingleNALMode(index: Int, byteCount: Int, limit: Int)
    case fragmentationPayloadTooSmall(maximumPayloadByteCount: Int)
    case aggregationUnitTooLarge(index: Int, byteCount: Int)
    case truncatedAggregationUnitHeader(offset: Int, availableBytes: Int)
    case invalidAggregationUnitLength(index: Int, declaredBytes: Int, availableBytes: Int)
    case emptyAggregationUnit(index: Int)
    case emptySingleTimeAggregationPacketA
    case inconsistentSingleTimeAggregationPacketAIndicator
    case truncatedFragmentationUnitA(availableBytes: Int)
    case invalidFragmentationUnitAType(UInt8)
    case fragmentationUnitAStartAndEndSet
    case payloadOwnerByteCountMismatch(expected: Int, actual: Int)
    case invalidPacketizationLayout
    case integerOverflow
}
