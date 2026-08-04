/// RFC 9260 Unrecognized Parameter INIT-ACK parameter (parameter type 8).
struct SCTPUnrecognizedParameter: Sendable, Equatable {
    static let parameterType: UInt16 = 8

    /// The complete unrecognized parameter without its alignment padding.
    let unrecognizedParameter: [UInt8]

    init(
        unrecognizedParameter: [UInt8]
    ) throws(SCTPWireError) {
        try Self.validate(unrecognizedParameter)
        self.unrecognizedParameter = unrecognizedParameter
    }

    /// Encode the enclosing type-8 parameter, including alignment padding.
    func encodeParameterBytes() throws(SCTPWireError) -> [UInt8] {
        let (parameterLength, overflow) = 4.addingReportingOverflow(
            unrecognizedParameter.count
        )
        guard !overflow, parameterLength <= Int(UInt16.max) else {
            throw .decode(.invalidFormat(
                "Unrecognized Parameter exceeds the parameter length field"
            ))
        }

        let paddedLength = (parameterLength + 3) & ~3
        var bytes: [UInt8] = []
        bytes.reserveCapacity(paddedLength)
        sctpAppendUInt16(&bytes, Self.parameterType)
        sctpAppendUInt16(&bytes, UInt16(parameterLength))
        bytes.append(contentsOf: unrecognizedParameter)
        while bytes.count < paddedLength {
            bytes.append(0)
        }
        return bytes
    }

    static func decode(
        from bytes: [UInt8],
        offset: Int,
        length: Int
    ) throws(SCTPWireError) -> Self {
        guard length >= 8 else {
            throw .decode(.invalidFormat(
                "Unrecognized Parameter length is below eight"
            ))
        }
        guard offset >= 0,
              offset <= bytes.count,
              length <= bytes.count - offset else {
            throw .decode(.insufficientData(
                expected: offset + length,
                actual: bytes.count
            ))
        }
        let type = sctpReadUInt16(bytes, offset: offset)
        guard type == Self.parameterType else {
            throw .decode(.invalidFormat(
                "Expected an Unrecognized Parameter"
            ))
        }
        let inner = Array(bytes[(offset + 4)..<(offset + length)])
        return try Self(unrecognizedParameter: inner)
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
