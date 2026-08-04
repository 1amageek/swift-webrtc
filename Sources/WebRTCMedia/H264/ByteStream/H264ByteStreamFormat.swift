/// Framing used by one encoded H.264 access unit.
public enum H264ByteStreamFormat: Sendable, Hashable {
    /// Start-code framing using `00 00 01` or `00 00 00 01` delimiters.
    case annexB

    /// Big-endian length-prefixed framing, commonly carried by AVCC samples.
    /// The parser accepts length fields from one through four bytes.
    case avcc(lengthFieldByteCount: Int)
}
