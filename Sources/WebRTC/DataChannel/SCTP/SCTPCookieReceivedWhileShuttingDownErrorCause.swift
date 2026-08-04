/// RFC 9260 Cookie Received While Shutting Down error cause (cause code 10).
struct SCTPCookieReceivedWhileShuttingDownErrorCause: Sendable {
    static let causeCode: UInt16 = 10

    init() {}

    /// Encode this cause as an SCTP ERROR chunk.
    func toChunk() -> SCTPChunk {
        SCTPChunk(
            validatedChunkType: SCTPChunkType.error.rawValue,
            value: [
                UInt8(Self.causeCode >> 8),
                UInt8(Self.causeCode & 0xFF),
                0,
                4,
            ]
        )
    }

    /// Validate the first cause in an SCTP ERROR chunk.
    static func decode(
        from errorChunk: SCTPChunk
    ) throws(SCTPWireError) -> Self {
        guard errorChunk.chunkType == SCTPChunkType.error.rawValue else {
            throw .decode(.invalidFormat("Expected an SCTP ERROR chunk"))
        }
        let value = errorChunk.value
        guard value.count >= 4 else {
            throw .decode(.insufficientData(expected: 4, actual: value.count))
        }
        let code = UInt16(value[0]) << 8 | UInt16(value[1])
        guard code == Self.causeCode else {
            throw .decode(.invalidFormat(
                "Expected Cookie Received While Shutting Down cause"
            ))
        }
        let length = UInt16(value[2]) << 8 | UInt16(value[3])
        guard length == 4 else {
            throw .decode(.invalidFormat(
                "Invalid Cookie Received While Shutting Down cause length"
            ))
        }
        return Self()
    }
}
