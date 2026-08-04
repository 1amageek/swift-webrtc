/// RFC 9260 Stale Cookie error cause (cause code 3).
struct SCTPStaleCookieErrorCause: Sendable, Equatable {
    static let causeCode: UInt16 = 3

    /// Cookie staleness beyond its lifetime, in microseconds.
    let stalenessMicroseconds: UInt32

    init(stalenessMicroseconds: UInt32) {
        self.stalenessMicroseconds = stalenessMicroseconds
    }

    /// Encode this cause as an SCTP ERROR chunk.
    func toChunk() -> SCTPChunk {
        SCTPChunk(
            validatedChunkType: SCTPChunkType.error.rawValue,
            value: [
                UInt8(Self.causeCode >> 8),
                UInt8(Self.causeCode & 0xFF),
                0,
                8,
                UInt8(stalenessMicroseconds >> 24),
                UInt8((stalenessMicroseconds >> 16) & 0xFF),
                UInt8((stalenessMicroseconds >> 8) & 0xFF),
                UInt8(stalenessMicroseconds & 0xFF),
            ]
        )
    }

    /// Decode the first cause in an SCTP ERROR chunk.
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
        let code = UInt16(value[0]) << 8 | UInt16(value[1])
        guard code == Self.causeCode else {
            throw .decode(.invalidFormat("Expected Stale Cookie cause"))
        }
        let length = UInt16(value[2]) << 8 | UInt16(value[3])
        guard length == 8 else {
            throw .decode(.invalidFormat("Invalid Stale Cookie cause length"))
        }
        let staleness = UInt32(value[4]) << 24
            | UInt32(value[5]) << 16
            | UInt32(value[6]) << 8
            | UInt32(value[7])
        return Self(stalenessMicroseconds: staleness)
    }
}
