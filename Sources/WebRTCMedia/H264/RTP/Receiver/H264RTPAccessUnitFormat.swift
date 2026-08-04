/// Decoder-bound framing for one reconstructed H.264 access unit.
public enum H264RTPAccessUnitFormat: Sendable, Equatable {
    /// Each NAL unit is prefixed by a three- or four-byte Annex B start code.
    case annexB(startCodeByteCount: Int)

    /// Each NAL unit is prefixed by a one- through four-byte big-endian length.
    case avcc(lengthFieldByteCount: Int)
}
