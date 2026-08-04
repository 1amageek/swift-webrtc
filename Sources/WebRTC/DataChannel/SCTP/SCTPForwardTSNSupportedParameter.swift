/// RFC 3758 Forward-TSN-Supported INIT/INIT-ACK parameter.
struct SCTPForwardTSNSupportedParameter: Sendable, Equatable {
    static let parameterType: UInt16 = 0xC000
    static let encodedByteCount = 4

    func encodeParameterBytes() -> [UInt8] {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(Self.encodedByteCount)
        sctpAppendUInt16(&bytes, Self.parameterType)
        sctpAppendUInt16(&bytes, UInt16(Self.encodedByteCount))
        return bytes
    }

    static func decode(
        from bytes: [UInt8],
        offset: Int,
        length: Int
    ) throws(SCTPWireError) -> Self {
        guard length == Self.encodedByteCount else {
            throw .decode(.invalidFormat(
                "Forward-TSN-Supported parameter length must be four"
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
        return Self()
    }
}
