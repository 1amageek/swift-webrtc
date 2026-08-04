/// RFC 6184 packetization modes negotiated by signaling.
public enum H264PacketizationMode: UInt8, Sendable, Equatable {
    case singleNALUnit = 0
    case nonInterleaved = 1
    case interleaved = 2
}
