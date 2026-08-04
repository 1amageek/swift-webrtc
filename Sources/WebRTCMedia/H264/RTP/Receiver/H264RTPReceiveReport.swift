/// How the input packet or explicit clock advance affected ordering state.
public enum H264RTPPacketDisposition: Sendable, Equatable {
    case processed
    case buffered
    case duplicateOrLate
    case resynchronized
    case clockAdvanced
    case accessUnitTimedOut
}

/// Observable bounded-receiver effects from one operation.
public struct H264RTPReceiveReport: Sendable, Equatable {
    public let disposition: H264RTPPacketDisposition
    public let deliveredAccessUnitCount: Int
    public let declaredLostPacketCount: Int
    public let discardedAccessUnitCount: Int
    public let discardedPacketCount: Int
    public let discardedPacketByteCount: UInt64
    public let reconstructedByteCount: UInt64
    public let bufferedPacketCount: Int
    public let bufferedByteCount: UInt64

    init(
        disposition: H264RTPPacketDisposition,
        deliveredAccessUnitCount: Int,
        declaredLostPacketCount: Int,
        discardedAccessUnitCount: Int,
        discardedPacketCount: Int,
        discardedPacketByteCount: UInt64,
        reconstructedByteCount: UInt64,
        bufferedPacketCount: Int,
        bufferedByteCount: UInt64
    ) {
        self.disposition = disposition
        self.deliveredAccessUnitCount = deliveredAccessUnitCount
        self.declaredLostPacketCount = declaredLostPacketCount
        self.discardedAccessUnitCount = discardedAccessUnitCount
        self.discardedPacketCount = discardedPacketCount
        self.discardedPacketByteCount = discardedPacketByteCount
        self.reconstructedByteCount = reconstructedByteCount
        self.bufferedPacketCount = bufferedPacketCount
        self.bufferedByteCount = bufferedByteCount
    }
}
