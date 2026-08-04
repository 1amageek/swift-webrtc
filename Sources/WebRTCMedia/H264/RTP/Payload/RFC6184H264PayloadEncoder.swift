import P2PCoreBytes

/// RFC 6184 payload encoder that writes directly into caller-owned storage.
public struct RFC6184H264PayloadEncoder: H264RTPPayloadEncoding, Sendable {
    public init() {}

    public func appendPayload(
        _ layout: H264RTPPacketizationLayout,
        from accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>,
        to destination: inout [UInt8]
    ) throws(H264RTPPayloadError) {
        let (requiredCapacity, capacityOverflow) = destination.count.addingReportingOverflow(
            layout.payloadByteCount
        )
        guard !capacityOverflow else {
            throw .integerOverflow
        }
        let expectedPayloadByteCount = try payloadByteCount(
            for: layout.payload,
            in: accessUnit,
            nalUnitRanges: nalUnitRanges
        )
        guard layout.payloadByteCount == expectedPayloadByteCount else {
            throw .invalidPacketizationLayout
        }

        // Validation completes before reserving or mutating caller storage. This
        // keeps malformed internal layouts from turning an impossible claimed
        // size into an allocation trap or leaving a partially encoded packet.
        destination.reserveCapacity(requiredCapacity)

        switch layout.payload {
        case .singleNALUnit(let nalUnitRange):
            append(accessUnit, range: nalUnitRange, to: &destination)

        case .singleTimeAggregationPacketA(let indicator, let nalUnitIndices):
            appendSingleTimeAggregationPacketA(
                indicator: indicator,
                nalUnitIndices: nalUnitIndices,
                from: accessUnit,
                nalUnitRanges: nalUnitRanges,
                to: &destination
            )

        case .fragmentationUnitA(
            let indicator,
            let header,
            let nalUnitRange,
            let fragmentRange
        ):
            _ = nalUnitRange
            appendFragmentationUnitA(
                indicator: indicator,
                header: header,
                fragmentRange: fragmentRange,
                from: accessUnit,
                to: &destination
            )
        }
    }

    private func payloadByteCount(
        for payload: H264RTPPacketizationPayload,
        in accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>
    ) throws(H264RTPPayloadError) -> Int {
        switch payload {
        case .singleNALUnit(let nalUnitRange):
            try validateRange(nalUnitRange, ownerByteCount: accessUnit.count)
            _ = try validateSourceNALUnit(in: accessUnit, range: nalUnitRange)
            return nalUnitRange.count

        case .singleTimeAggregationPacketA(let indicator, let nalUnitIndices):
            return try singleTimeAggregationPacketAByteCount(
                indicator: indicator,
                nalUnitIndices: nalUnitIndices,
                in: accessUnit,
                nalUnitRanges: nalUnitRanges
            )

        case .fragmentationUnitA(
            let indicator,
            let header,
            let nalUnitRange,
            let fragmentRange
        ):
            return try fragmentationUnitAByteCount(
                indicator: indicator,
                header: header,
                nalUnitRange: nalUnitRange,
                fragmentRange: fragmentRange,
                in: accessUnit
            )
        }
    }

    private func singleTimeAggregationPacketAByteCount(
        indicator: UInt8,
        nalUnitIndices: Range<Int>,
        in accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>
    ) throws(H264RTPPayloadError) -> Int {
        guard nalUnitIndices.lowerBound >= 0,
              nalUnitIndices.upperBound <= nalUnitRanges.count,
              nalUnitIndices.count >= 2 else {
            throw .invalidPacketizationLayout
        }

        var maximumReferenceIndicator: UInt8 = 0
        var payloadByteCount = 1
        for index in nalUnitIndices {
            let range = nalUnitRanges[index]
            try validateRange(range, ownerByteCount: accessUnit.count)
            let sourceHeader = try validateSourceNALUnit(in: accessUnit, range: range)
            maximumReferenceIndicator = max(
                maximumReferenceIndicator,
                sourceHeader.referenceIndicator
            )
            guard range.count <= Int(UInt16.max) else {
                throw .aggregationUnitTooLarge(index: index, byteCount: range.count)
            }
            let (unitByteCount, unitOverflow) = range.count.addingReportingOverflow(2)
            guard !unitOverflow else {
                throw .integerOverflow
            }
            let (nextPayloadByteCount, payloadOverflow) = payloadByteCount.addingReportingOverflow(
                unitByteCount
            )
            guard !payloadOverflow else {
                throw .integerOverflow
            }
            payloadByteCount = nextPayloadByteCount
        }
        let expectedIndicator = (maximumReferenceIndicator << 5) | 24
        guard indicator == expectedIndicator else {
            throw .invalidPacketizationLayout
        }
        return payloadByteCount
    }

    private func appendSingleTimeAggregationPacketA(
        indicator: UInt8,
        nalUnitIndices: Range<Int>,
        from accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>,
        to destination: inout [UInt8]
    ) {
        destination.append(indicator)
        for index in nalUnitIndices {
            let range = nalUnitRanges[index]
            destination.append(UInt8(range.count >> 8))
            destination.append(UInt8(truncatingIfNeeded: range.count))
            append(accessUnit, range: range, to: &destination)
        }
    }

    private func fragmentationUnitAByteCount(
        indicator: UInt8,
        header: UInt8,
        nalUnitRange: Range<Int>,
        fragmentRange: Range<Int>,
        in accessUnit: Span<UInt8>
    ) throws(H264RTPPayloadError) -> Int {
        try validateRange(nalUnitRange, ownerByteCount: accessUnit.count)
        try validateRange(fragmentRange, ownerByteCount: accessUnit.count)
        let sourceHeader = try validateSourceNALUnit(
            in: accessUnit,
            range: nalUnitRange
        )
        guard fragmentRange.lowerBound >= nalUnitRange.lowerBound + 1,
              fragmentRange.upperBound <= nalUnitRange.upperBound,
              !fragmentRange.isEmpty else {
            throw .invalidPacketizationLayout
        }

        let expectedIndicator = (sourceHeader.referenceIndicator << 5) | 28
        let headerType = header & 0x1F
        guard indicator == expectedIndicator,
              headerType == sourceHeader.unitType,
              header & 0x20 == 0,
              header & 0xC0 != 0xC0 else {
            throw .invalidPacketizationLayout
        }
        let (payloadByteCount, overflow) = fragmentRange.count.addingReportingOverflow(2)
        guard !overflow else {
            throw .integerOverflow
        }
        return payloadByteCount
    }

    private func appendFragmentationUnitA(
        indicator: UInt8,
        header: UInt8,
        fragmentRange: Range<Int>,
        from accessUnit: Span<UInt8>,
        to destination: inout [UInt8]
    ) {
        destination.append(indicator)
        destination.append(header)
        append(accessUnit, range: fragmentRange, to: &destination)
    }

    private func validateSourceNALUnit(
        in accessUnit: Span<UInt8>,
        range: Range<Int>
    ) throws(H264RTPPayloadError) -> H264NALUnitHeader {
        guard !range.isEmpty else {
            throw .invalidPacketizationLayout
        }
        let header = H264NALUnitHeader(rawValue: accessUnit[range.lowerBound])
        guard !header.hasForbiddenBit else {
            throw .forbiddenBitSet
        }
        guard (1...23).contains(header.unitType) else {
            throw .invalidPacketizationLayout
        }
        return header
    }

    private func validateRange(
        _ range: Range<Int>,
        ownerByteCount: Int
    ) throws(H264RTPPayloadError) {
        guard range.lowerBound >= 0,
              range.upperBound <= ownerByteCount else {
            throw .invalidPacketizationLayout
        }
    }

    private func append(
        _ source: Span<UInt8>,
        range: Range<Int>,
        to destination: inout [UInt8]
    ) {
        // The final packet must own its payload, so one copy is required at this
        // network boundary. Keep the pointer scoped to the borrowed Span and
        // perform that copy as one contiguous bulk append instead of one checked
        // Array append per byte.
        source.extracting(range).withUnsafeBufferPointer { bytes in
            destination.append(contentsOf: bytes)
        }
    }
}
