/// The RFC 6184 structure selected by the first payload octet.
public enum H264RTPPayloadStructure: Sendable, Equatable {
    case singleNALUnit(H264NALUnitLayout)
    case singleTimeAggregationPacketA(H264STAPALayout)
    case fragmentationUnitA(H264FUALayout)
}
