/// RFC 9260 Unrecognized Parameters error cause (cause code 8).
struct SCTPUnrecognizedParametersErrorCause: Sendable, Equatable {
    static let causeCode: UInt16 = 8

    /// Complete unrecognized parameter TLVs without alignment padding.
    let unrecognizedParameters: [[UInt8]]

    init(
        unrecognizedParameters: [[UInt8]]
    ) throws(SCTPWireError) {
        guard !unrecognizedParameters.isEmpty else {
            throw .decode(.invalidFormat(
                "Unrecognized Parameters cause requires at least one parameter"
            ))
        }
        for parameter in unrecognizedParameters {
            try Self.validate(parameter)
        }
        self.unrecognizedParameters = unrecognizedParameters
    }

    /// Encode this cause as an SCTP ERROR chunk.
    func toChunk() throws(SCTPWireError) -> SCTPChunk {
        var causeLength = 4
        for (index, parameter) in unrecognizedParameters.enumerated() {
            let parameterByteCount = index == unrecognizedParameters.count - 1
                ? parameter.count
                : (parameter.count + 3) & ~3
            let (nextLength, overflow) = causeLength.addingReportingOverflow(
                parameterByteCount
            )
            guard !overflow,
                  nextLength <= Int(UInt16.max) - 4 else {
                throw .chunkValueTooLarge(
                    actual: overflow ? Int.max : nextLength,
                    maximum: Int(UInt16.max) - 4
                )
            }
            causeLength = nextLength
        }

        var value: [UInt8] = []
        value.reserveCapacity(causeLength)
        sctpAppendUInt16(&value, Self.causeCode)
        sctpAppendUInt16(&value, UInt16(causeLength))
        for (index, parameter) in unrecognizedParameters.enumerated() {
            value.append(contentsOf: parameter)
            if index != unrecognizedParameters.count - 1 {
                while (value.count & 3) != 0 {
                    value.append(0)
                }
            }
        }
        return try SCTPChunk(
            chunkType: SCTPChunkType.error.rawValue,
            value: value
        )
    }

    /// Decode the first cause from an SCTP ERROR chunk.
    static func decode(
        from errorChunk: SCTPChunk
    ) throws(SCTPWireError) -> Self {
        guard errorChunk.chunkType == SCTPChunkType.error.rawValue else {
            throw .decode(.invalidFormat("Expected an SCTP ERROR chunk"))
        }
        let value = errorChunk.value
        guard value.count >= 8 else {
            throw .decode(.insufficientData(expected: 8, actual: value.count))
        }
        let code = sctpReadUInt16(value, offset: 0)
        guard code == Self.causeCode else {
            throw .decode(.invalidFormat(
                "Expected Unrecognized Parameters cause"
            ))
        }
        let causeLength = Int(sctpReadUInt16(value, offset: 2))
        guard causeLength >= 8, causeLength <= value.count else {
            throw .decode(.invalidFormat(
                "Invalid Unrecognized Parameters cause length"
            ))
        }

        var parameters: [[UInt8]] = []
        var offset = 4
        while offset < causeLength {
            guard causeLength - offset >= 4 else {
                throw .decode(.invalidFormat(
                    "Truncated parameter in Unrecognized Parameters cause"
                ))
            }
            let parameterLength = Int(sctpReadUInt16(value, offset: offset + 2))
            guard parameterLength >= 4,
                  parameterLength <= causeLength - offset else {
                throw .decode(.invalidFormat(
                    "Invalid parameter length in Unrecognized Parameters cause"
                ))
            }
            parameters.append(Array(value[offset..<(offset + parameterLength)]))
            let end = offset + parameterLength
            if end == causeLength {
                offset = end
            } else {
                let paddedLength = (parameterLength + 3) & ~3
                guard paddedLength <= causeLength - offset else {
                    throw .decode(.invalidFormat(
                        "Truncated parameter padding in Unrecognized Parameters cause"
                    ))
                }
                offset += paddedLength
            }
        }
        return try Self(unrecognizedParameters: parameters)
    }

    private static func validate(
        _ parameter: [UInt8]
    ) throws(SCTPWireError) {
        guard parameter.count >= 4 else {
            throw .decode(.invalidFormat(
                "Reported parameter is shorter than its TLV header"
            ))
        }
        let declaredLength = Int(sctpReadUInt16(parameter, offset: 2))
        guard declaredLength >= 4 else {
            throw .decode(.invalidFormat(
                "Reported parameter length is below four"
            ))
        }
        guard declaredLength == parameter.count else {
            throw .decode(.invalidFormat(
                "Reported parameter length does not match its TLV bytes"
            ))
        }
    }
}
