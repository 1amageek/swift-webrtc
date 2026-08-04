/// Source metadata needed to materialize one outbound RFC 6184 RTP payload.
///
/// Every range refers to the access-unit owner passed to the packetizer. No
/// media bytes are stored or copied by this value.
public enum H264RTPPacketizationPayload: Sendable, Equatable {
    case singleNALUnit(nalUnitRange: Range<Int>)
    case singleTimeAggregationPacketA(
        indicator: UInt8,
        nalUnitIndices: Range<Int>
    )
    case fragmentationUnitA(
        indicator: UInt8,
        header: UInt8,
        nalUnitRange: Range<Int>,
        fragmentRange: Range<Int>
    )
}
