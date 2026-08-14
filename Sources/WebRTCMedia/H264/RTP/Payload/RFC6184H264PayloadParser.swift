import NetworkingCore

/// Bounds-checked RFC 6184 Single NAL, STAP-A, and FU-A payload parser.
public struct RFC6184H264PayloadParser: H264RTPPayloadParsing, Sendable {
    public init() {}

    public func layout(
        in payload: Span<UInt8>,
        mode: H264PacketizationMode
    ) throws(H264RTPPayloadError) -> H264RTPPayloadLayout {
        guard mode != .interleaved else {
            throw .unsupportedPacketizationMode(mode)
        }
        guard !payload.isEmpty else {
            throw .emptyPayload
        }

        let header = H264NALUnitHeader(rawValue: payload[0])
        guard !header.hasForbiddenBit else {
            throw .forbiddenBitSet
        }

        switch header.unitType {
        case 1...23:
            return H264RTPPayloadLayout(
                structure: .singleNALUnit(H264NALUnitLayout(
                    header: header,
                    range: 0..<payload.count
                )),
                payloadByteCount: payload.count
            )
        case 24:
            try requireNonInterleaved(mode, packetType: header.unitType)
            return try parseSingleTimeAggregationPacketA(
                in: payload,
                indicator: header
            )
        case 28:
            try requireNonInterleaved(mode, packetType: header.unitType)
            return try parseFragmentationUnitA(in: payload, indicator: header)
        case 0, 30, 31:
            throw .reservedNALUnitType(header.unitType)
        default:
            throw .packetTypeNotAllowed(mode: mode, type: header.unitType)
        }
    }

    private func requireNonInterleaved(
        _ mode: H264PacketizationMode,
        packetType: UInt8
    ) throws(H264RTPPayloadError) {
        guard mode == .nonInterleaved else {
            throw .packetTypeNotAllowed(mode: mode, type: packetType)
        }
    }

    private func parseSingleTimeAggregationPacketA(
        in payload: Span<UInt8>,
        indicator: H264NALUnitHeader
    ) throws(H264RTPPayloadError) -> H264RTPPayloadLayout {
        var cursor = 1
        var unitCount = 0
        var maximumReferenceIndicator: UInt8 = 0

        while cursor < payload.count {
            let availableHeaderBytes = payload.count - cursor
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
                throw .emptyAggregationUnit(index: unitCount)
            }
            let availableBytes = payload.count - cursor
            guard declaredByteCount <= availableBytes else {
                throw .invalidAggregationUnitLength(
                    index: unitCount,
                    declaredBytes: declaredByteCount,
                    availableBytes: availableBytes
                )
            }

            let unitHeader = H264NALUnitHeader(rawValue: payload[cursor])
            guard !unitHeader.hasForbiddenBit else {
                throw .forbiddenBitSet
            }
            guard unitHeader.unitType != 0, unitHeader.unitType < 30 else {
                throw .reservedNALUnitType(unitHeader.unitType)
            }
            guard (1...23).contains(unitHeader.unitType) else {
                throw .packetizationUnitProvidedAsNALUnit(
                    index: unitCount,
                    type: unitHeader.unitType
                )
            }
            maximumReferenceIndicator = max(
                maximumReferenceIndicator,
                unitHeader.referenceIndicator
            )
            cursor += declaredByteCount
            unitCount += 1
        }

        guard unitCount > 0 else {
            throw .emptySingleTimeAggregationPacketA
        }
        guard indicator.referenceIndicator == maximumReferenceIndicator else {
            throw .inconsistentSingleTimeAggregationPacketAIndicator
        }

        return H264RTPPayloadLayout(
            structure: .singleTimeAggregationPacketA(H264STAPALayout(
                indicator: indicator,
                aggregationUnitsRange: 1..<payload.count,
                unitCount: unitCount,
                payloadByteCount: payload.count
            )),
            payloadByteCount: payload.count
        )
    }

    private func parseFragmentationUnitA(
        in payload: Span<UInt8>,
        indicator: H264NALUnitHeader
    ) throws(H264RTPPayloadError) -> H264RTPPayloadLayout {
        guard payload.count >= 2 else {
            throw .truncatedFragmentationUnitA(availableBytes: payload.count)
        }

        let fragmentationHeader = payload[1]
        let isStart = fragmentationHeader & 0x80 != 0
        let isEnd = fragmentationHeader & 0x40 != 0
        guard !(isStart && isEnd) else {
            throw .fragmentationUnitAStartAndEndSet
        }
        let originalType = fragmentationHeader & 0x1F
        guard (1...23).contains(originalType) else {
            throw .invalidFragmentationUnitAType(originalType)
        }

        let originalHeader = H264NALUnitHeader(
            rawValue: (indicator.referenceIndicator << 5) | originalType
        )
        return H264RTPPayloadLayout(
            structure: .fragmentationUnitA(H264FUALayout(
                indicator: indicator,
                originalNALUnitHeader: originalHeader,
                fragmentRange: 2..<payload.count,
                isStart: isStart,
                isEnd: isEnd
            )),
            payloadByteCount: payload.count
        )
    }
}
