/// RFC 9260 Unrecognized Chunk Type error cause (cause code 6).
struct SCTPUnrecognizedChunkErrorCause: Sendable {
    static let causeCode: UInt16 = 6

    /// The complete unknown chunk retained as its immutable wire-value owner.
    let unrecognizedChunk: SCTPChunk

    init(unrecognizedChunk: SCTPChunk) {
        self.unrecognizedChunk = unrecognizedChunk
    }

    /// Encode this cause as an SCTP ERROR chunk.
    func toChunk() throws(SCTPWireError) -> SCTPChunk {
        let unrecognizedBytes = unrecognizedChunk.encodeBytes()
        let causeLength = 4 + Int(unrecognizedChunk.length)
        guard causeLength <= Int(UInt16.max) else {
            throw .chunkValueTooLarge(
                actual: causeLength,
                maximum: Int(UInt16.max) - 4
            )
        }

        var value: [UInt8] = []
        value.reserveCapacity(causeLength)
        sctpAppendUInt16(&value, Self.causeCode)
        sctpAppendUInt16(&value, UInt16(causeLength))
        value.append(contentsOf: unrecognizedBytes.prefix(Int(unrecognizedChunk.length)))
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
            throw .decode(.invalidFormat("Expected Unrecognized Chunk Type cause"))
        }
        let causeLength = Int(sctpReadUInt16(value, offset: 2))
        guard causeLength >= 8, causeLength <= value.count else {
            throw .decode(.invalidFormat("Invalid Unrecognized Chunk Type cause length"))
        }
        let chunkBytes = Array(value[4..<causeLength])
        return try Self(unrecognizedChunk: SCTPChunk.decode(from: chunkBytes))
    }
}
