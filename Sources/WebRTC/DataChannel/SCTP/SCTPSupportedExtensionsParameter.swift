/// The Supported Extensions INIT/INIT-ACK parameter (RFC 5061 §4.2.7).
struct SCTPSupportedExtensionsParameter: Sendable, Equatable {
    static let parameterType: UInt16 = 0x8008

    let chunkTypes: [UInt8]

    init(chunkTypes: [UInt8]) {
        self.chunkTypes = chunkTypes
    }

    func encodeParameterBytes() throws(SCTPWireError) -> [UInt8] {
        let (length, overflow) = 4.addingReportingOverflow(chunkTypes.count)
        guard !overflow, length <= Int(UInt16.max) else {
            throw .decode(.invalidFormat("Supported Extensions list exceeds the parameter length field"))
        }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(length)
        sctpAppendUInt16(&bytes, Self.parameterType)
        sctpAppendUInt16(&bytes, UInt16(length))
        bytes.append(contentsOf: chunkTypes)
        return bytes
    }

    static func decode(
        from bytes: [UInt8],
        offset: Int,
        length: Int
    ) throws(SCTPWireError) -> Self {
        guard length >= 4 else {
            throw .decode(.invalidFormat("Supported Extensions parameter length is below four"))
        }
        guard offset >= 0, offset <= bytes.count, length <= bytes.count - offset else {
            throw .decode(.insufficientData(expected: offset + length, actual: bytes.count))
        }
        return Self(chunkTypes: Array(bytes[(offset + 4)..<(offset + length)]))
    }
}
