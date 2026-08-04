import P2PCoreBytes

/// Validated metadata for one inbound STAP-A payload.
///
/// The aggregation-unit range refers to the payload owner passed to the parser.
/// Use ``forEachNALUnit(in:_:)`` while retaining that exact owner.
public struct H264STAPALayout: Sendable, Equatable {
    public let indicator: H264NALUnitHeader
    public let aggregationUnitsRange: Range<Int>
    public let unitCount: Int
    public let payloadByteCount: Int

    init(
        indicator: H264NALUnitHeader,
        aggregationUnitsRange: Range<Int>,
        unitCount: Int,
        payloadByteCount: Int
    ) {
        self.indicator = indicator
        self.aggregationUnitsRange = aggregationUnitsRange
        self.unitCount = unitCount
        self.payloadByteCount = payloadByteCount
    }

    /// Synchronously emits NAL layouts without allocating an array of ranges.
    public func forEachNALUnit(
        in payload: Span<UInt8>,
        _ body: (H264NALUnitLayout) -> Void
    ) throws(H264RTPPayloadError) {
        guard payload.count == payloadByteCount else {
            throw .payloadOwnerByteCountMismatch(
                expected: payloadByteCount,
                actual: payload.count
            )
        }

        var cursor = aggregationUnitsRange.lowerBound
        var index = 0
        while cursor < aggregationUnitsRange.upperBound {
            let availableHeaderBytes = aggregationUnitsRange.upperBound - cursor
            guard availableHeaderBytes >= 2 else {
                throw .truncatedAggregationUnitHeader(
                    offset: cursor,
                    availableBytes: availableHeaderBytes
                )
            }
            let declaredByteCount = Int(payload[cursor]) << 8
                | Int(payload[cursor + 1])
            cursor += 2
            guard declaredByteCount > 0 else {
                throw .emptyAggregationUnit(index: index)
            }
            let availableBytes = aggregationUnitsRange.upperBound - cursor
            guard declaredByteCount <= availableBytes else {
                throw .invalidAggregationUnitLength(
                    index: index,
                    declaredBytes: declaredByteCount,
                    availableBytes: availableBytes
                )
            }

            let range = cursor..<(cursor + declaredByteCount)
            let header = H264NALUnitHeader(rawValue: payload[cursor])
            body(H264NALUnitLayout(header: header, range: range))
            cursor = range.upperBound
            index += 1
        }

        guard index == unitCount else {
            throw .invalidPacketizationLayout
        }
    }
}
