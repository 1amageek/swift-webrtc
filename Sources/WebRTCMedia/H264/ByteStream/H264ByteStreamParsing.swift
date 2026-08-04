import P2PCoreBytes

/// Extracts H.264 NAL-unit ranges while borrowing the encoded byte owner.
public protocol H264ByteStreamParsing: Sendable {
    /// Appends ranges into reusable caller-owned metadata storage.
    ///
    /// Media bytes are never copied. On any typed failure, `destination` has
    /// the same elements it had when the operation began.
    func appendNALUnitRanges(
        in encodedAccessUnit: Span<UInt8>,
        format: H264ByteStreamFormat,
        to destination: inout [Range<Int>]
    ) throws(H264ByteStreamError)
}

extension H264ByteStreamParsing {
    /// Convenience boundary that allocates range metadata, never media bytes.
    public func nalUnitRanges(
        in encodedAccessUnit: Span<UInt8>,
        format: H264ByteStreamFormat
    ) throws(H264ByteStreamError) -> [Range<Int>] {
        var ranges: [Range<Int>] = []
        try appendNALUnitRanges(
            in: encodedAccessUnit,
            format: format,
            to: &ranges
        )
        return ranges
    }
}
