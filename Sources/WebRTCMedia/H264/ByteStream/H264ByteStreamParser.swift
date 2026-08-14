import NetworkingCore

/// Zero-copy Annex B and AVCC framing parser for one H.264 access unit.
public struct H264ByteStreamParser: H264ByteStreamParsing, Sendable {
    public init() {}

    public func appendNALUnitRanges(
        in encodedAccessUnit: Span<UInt8>,
        format: H264ByteStreamFormat,
        to destination: inout [Range<Int>]
    ) throws(H264ByteStreamError) {
        guard !encodedAccessUnit.isEmpty else {
            throw .emptyAccessUnit
        }

        let originalCount = destination.count
        do {
            switch format {
            case .annexB:
                try appendAnnexBRanges(
                    in: encodedAccessUnit,
                    to: &destination
                )
            case .avcc(let lengthFieldByteCount):
                try appendAVCCRanges(
                    in: encodedAccessUnit,
                    lengthFieldByteCount: lengthFieldByteCount,
                    to: &destination
                )
            }
        } catch {
            destination.removeSubrange(originalCount..<destination.count)
            throw error
        }
    }

    private func appendAnnexBRanges(
        in bytes: Span<UInt8>,
        to destination: inout [Range<Int>]
    ) throws(H264ByteStreamError) {
        var zeroRunStart: Int?
        var firstNonzeroPrefixOffset: Int?
        var nalUnitStart: Int?
        var nalUnitIndex = 0

        for offset in 0..<bytes.count {
            let byte = bytes[offset]
            if byte == 0 {
                if zeroRunStart == nil {
                    zeroRunStart = offset
                }
                continue
            }

            if byte == 1,
               let runStart = zeroRunStart,
               offset - runStart >= 2 {
                if nalUnitStart == nil {
                    if let firstNonzeroPrefixOffset {
                        throw .nonzeroBytesBeforeFirstStartCode(
                            offset: firstNonzeroPrefixOffset
                        )
                    }
                } else {
                    try appendNonemptyRange(
                        nalUnitStart!..<runStart,
                        index: nalUnitIndex,
                        to: &destination
                    )
                    nalUnitIndex += 1
                }
                nalUnitStart = offset + 1
                zeroRunStart = nil
                continue
            }

            if nalUnitStart == nil, firstNonzeroPrefixOffset == nil {
                firstNonzeroPrefixOffset = offset
            }
            zeroRunStart = nil
        }

        guard let nalUnitStart else {
            throw .missingAnnexBStartCode
        }
        let finalEnd = zeroRunStart ?? bytes.count
        try appendNonemptyRange(
            nalUnitStart..<finalEnd,
            index: nalUnitIndex,
            to: &destination
        )
    }

    private func appendAVCCRanges(
        in bytes: Span<UInt8>,
        lengthFieldByteCount: Int,
        to destination: inout [Range<Int>]
    ) throws(H264ByteStreamError) {
        guard (1...4).contains(lengthFieldByteCount) else {
            throw .invalidAVCCLengthFieldByteCount(actual: lengthFieldByteCount)
        }

        var offset = 0
        var nalUnitIndex = 0
        while offset < bytes.count {
            let availableLengthBytes = bytes.count - offset
            guard availableLengthBytes >= lengthFieldByteCount else {
                throw .truncatedAVCCLengthField(
                    offset: offset,
                    expected: lengthFieldByteCount,
                    actual: availableLengthBytes
                )
            }

            var declaredByteCount = 0
            for lengthOffset in 0..<lengthFieldByteCount {
                declaredByteCount = (declaredByteCount << 8)
                    | Int(bytes[offset + lengthOffset])
            }
            offset += lengthFieldByteCount

            guard declaredByteCount > 0 else {
                throw .emptyNALUnit(index: nalUnitIndex)
            }
            let availableNALUnitBytes = bytes.count - offset
            guard declaredByteCount <= availableNALUnitBytes else {
                throw .avccNALUnitOutOfBounds(
                    index: nalUnitIndex,
                    declaredByteCount: declaredByteCount,
                    availableByteCount: availableNALUnitBytes
                )
            }

            let end = offset + declaredByteCount
            destination.append(offset..<end)
            offset = end
            nalUnitIndex += 1
        }
    }

    private func appendNonemptyRange(
        _ range: Range<Int>,
        index: Int,
        to destination: inout [Range<Int>]
    ) throws(H264ByteStreamError) {
        guard !range.isEmpty else {
            throw .emptyNALUnit(index: index)
        }
        destination.append(range)
    }
}
