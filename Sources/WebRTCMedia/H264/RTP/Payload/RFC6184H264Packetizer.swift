import P2PCoreBytes

/// RFC 6184 Single NAL, STAP-A, and FU-A packetization planner.
public struct RFC6184H264Packetizer: H264RTPPacketizing, Sendable {
    public init() {}

    public func forEachPacket(
        in accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>,
        mode: H264PacketizationMode,
        maximumPayloadByteCount: Int,
        _ body: (H264RTPPacketizationLayout) -> Void
    ) throws(H264RTPPayloadError) {
        _ = try traversePackets(
            in: accessUnit,
            nalUnitRanges: nalUnitRanges,
            mode: mode,
            maximumPayloadByteCount: maximumPayloadByteCount
        ) { layout in
            body(layout)
            return .proceed
        }
    }

    public func traversePackets(
        in accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>,
        mode: H264PacketizationMode,
        maximumPayloadByteCount: Int,
        _ body: (H264RTPPacketizationLayout) -> H264RTPPacketTraversalDecision
    ) throws(H264RTPPayloadError) -> H264RTPPacketTraversalOutcome {
        guard mode != .interleaved else {
            throw .unsupportedPacketizationMode(mode)
        }
        guard maximumPayloadByteCount > 0 else {
            throw .invalidMaximumPayloadByteCount(actual: maximumPayloadByteCount)
        }
        guard !nalUnitRanges.isEmpty else {
            throw .emptyAccessUnit
        }

        try validateNALUnits(in: accessUnit, ranges: nalUnitRanges)

        switch mode {
        case .singleNALUnit:
            try validateSingleNALMode(
                ranges: nalUnitRanges,
                maximumPayloadByteCount: maximumPayloadByteCount
            )
            return emitSingleNALMode(
                ranges: nalUnitRanges,
                body
            )
        case .nonInterleaved:
            try validateNonInterleavedMode(
                ranges: nalUnitRanges,
                maximumPayloadByteCount: maximumPayloadByteCount
            )
            return emitNonInterleavedMode(
                in: accessUnit,
                ranges: nalUnitRanges,
                maximumPayloadByteCount: maximumPayloadByteCount,
                body
            )
        case .interleaved:
            throw .unsupportedPacketizationMode(mode)
        }
    }

    private func validateSingleNALMode(
        ranges: Span<Range<Int>>,
        maximumPayloadByteCount: Int
    ) throws(H264RTPPayloadError) {
        for index in 0..<ranges.count {
            let range = ranges[index]
            guard range.count <= maximumPayloadByteCount else {
                throw .nalUnitExceedsSingleNALMode(
                    index: index,
                    byteCount: range.count,
                    limit: maximumPayloadByteCount
                )
            }
        }
    }

    private func validateNonInterleavedMode(
        ranges: Span<Range<Int>>,
        maximumPayloadByteCount: Int
    ) throws(H264RTPPayloadError) {
        guard maximumPayloadByteCount < 3 else { return }
        for index in 0..<ranges.count where ranges[index].count > maximumPayloadByteCount {
            throw .fragmentationPayloadTooSmall(
                maximumPayloadByteCount: maximumPayloadByteCount
            )
        }
    }

    private func validateNALUnits(
        in accessUnit: Span<UInt8>,
        ranges: Span<Range<Int>>
    ) throws(H264RTPPayloadError) {
        var previousUpperBound = 0
        for index in 0..<ranges.count {
            let range = ranges[index]
            guard range.lowerBound >= 0,
                  range.upperBound <= accessUnit.count else {
                throw .nalUnitRangeOutOfBounds(
                    index: index,
                    lowerBound: range.lowerBound,
                    upperBound: range.upperBound,
                    ownerByteCount: accessUnit.count
                )
            }
            guard !range.isEmpty else {
                throw .emptyNALUnit(index: index)
            }
            guard index == 0 || range.lowerBound >= previousUpperBound else {
                throw .unorderedOrOverlappingNALUnitRange(index: index)
            }

            let header = H264NALUnitHeader(rawValue: accessUnit[range.lowerBound])
            guard !header.hasForbiddenBit else {
                throw .forbiddenBitSet
            }
            guard header.unitType != 0, header.unitType < 30 else {
                throw .reservedNALUnitType(header.unitType)
            }
            guard (1...23).contains(header.unitType) else {
                throw .packetizationUnitProvidedAsNALUnit(
                    index: index,
                    type: header.unitType
                )
            }
            previousUpperBound = range.upperBound
        }
    }

    private func emitSingleNALMode(
        ranges: Span<Range<Int>>,
        _ body: (H264RTPPacketizationLayout) -> H264RTPPacketTraversalDecision
    ) -> H264RTPPacketTraversalOutcome {
        for index in 0..<ranges.count {
            let range = ranges[index]
            let decision = body(H264RTPPacketizationLayout(
                payload: .singleNALUnit(nalUnitRange: range),
                payloadByteCount: range.count,
                isLastPacketOfAccessUnit: index == ranges.count - 1
            ))
            if decision == .stop {
                return .stopped
            }
        }
        return .completed
    }

    private func emitNonInterleavedMode(
        in accessUnit: Span<UInt8>,
        ranges: Span<Range<Int>>,
        maximumPayloadByteCount: Int,
        _ body: (H264RTPPacketizationLayout) -> H264RTPPacketTraversalDecision
    ) -> H264RTPPacketTraversalOutcome {
        var index = 0
        while index < ranges.count {
            let range = ranges[index]
            if range.count > maximumPayloadByteCount {
                let outcome = emitFragmentationUnits(
                    for: range,
                    nalUnitIndex: index,
                    nalUnitCount: ranges.count,
                    in: accessUnit,
                    maximumPayloadByteCount: maximumPayloadByteCount,
                    body
                )
                if outcome == .stopped {
                    return .stopped
                }
                index += 1
                continue
            }

            let aggregationEnd = aggregationEndIndex(
                from: index,
                ranges: ranges,
                maximumPayloadByteCount: maximumPayloadByteCount
            )
            if aggregationEnd - index >= 2 {
                var maximumReferenceIndicator: UInt8 = 0
                var payloadByteCount = 1
                for unitIndex in index..<aggregationEnd {
                    let unitRange = ranges[unitIndex]
                    let header = H264NALUnitHeader(rawValue: accessUnit[unitRange.lowerBound])
                    maximumReferenceIndicator = max(
                        maximumReferenceIndicator,
                        header.referenceIndicator
                    )
                    payloadByteCount += 2 + unitRange.count
                }
                let indicator = (maximumReferenceIndicator << 5) | 24
                let decision = body(H264RTPPacketizationLayout(
                    payload: .singleTimeAggregationPacketA(
                        indicator: indicator,
                        nalUnitIndices: index..<aggregationEnd
                    ),
                    payloadByteCount: payloadByteCount,
                    isLastPacketOfAccessUnit: aggregationEnd == ranges.count
                ))
                if decision == .stop {
                    return .stopped
                }
                index = aggregationEnd
            } else {
                let decision = body(H264RTPPacketizationLayout(
                    payload: .singleNALUnit(nalUnitRange: range),
                    payloadByteCount: range.count,
                    isLastPacketOfAccessUnit: index == ranges.count - 1
                ))
                if decision == .stop {
                    return .stopped
                }
                index += 1
            }
        }
        return .completed
    }

    private func aggregationEndIndex(
        from startIndex: Int,
        ranges: Span<Range<Int>>,
        maximumPayloadByteCount: Int
    ) -> Int {
        var byteCount = 1
        var endIndex = startIndex

        while endIndex < ranges.count {
            let range = ranges[endIndex]
            guard range.count <= Int(UInt16.max) else {
                break
            }
            let unitByteCount = range.count + 2
            guard unitByteCount <= maximumPayloadByteCount,
                  byteCount <= maximumPayloadByteCount - unitByteCount else {
                break
            }
            byteCount += unitByteCount
            endIndex += 1
        }
        return endIndex
    }

    private func emitFragmentationUnits(
        for nalUnitRange: Range<Int>,
        nalUnitIndex: Int,
        nalUnitCount: Int,
        in accessUnit: Span<UInt8>,
        maximumPayloadByteCount: Int,
        _ body: (H264RTPPacketizationLayout) -> H264RTPPacketTraversalDecision
    ) -> H264RTPPacketTraversalOutcome {
        let originalHeader = H264NALUnitHeader(
            rawValue: accessUnit[nalUnitRange.lowerBound]
        )
        let indicator = (originalHeader.referenceIndicator << 5) | 28
        let maximumFragmentByteCount = maximumPayloadByteCount - 2
        var fragmentStart = nalUnitRange.lowerBound + 1
        let fragmentEnd = nalUnitRange.upperBound
        var isFirst = true

        while fragmentStart < fragmentEnd {
            let remaining = fragmentEnd - fragmentStart
            let fragmentByteCount = min(maximumFragmentByteCount, remaining)
            let currentEnd = fragmentStart + fragmentByteCount
            let isLast = currentEnd == fragmentEnd
            let header = (isFirst ? UInt8(0x80) : 0)
                | (isLast ? UInt8(0x40) : 0)
                | originalHeader.unitType

            let decision = body(H264RTPPacketizationLayout(
                payload: .fragmentationUnitA(
                    indicator: indicator,
                    header: header,
                    nalUnitRange: nalUnitRange,
                    fragmentRange: fragmentStart..<currentEnd
                ),
                payloadByteCount: 2 + fragmentByteCount,
                isLastPacketOfAccessUnit: isLast && nalUnitIndex == nalUnitCount - 1
            ))
            if decision == .stop {
                return .stopped
            }
            fragmentStart = currentEnd
            isFirst = false
        }
        return .completed
    }
}
