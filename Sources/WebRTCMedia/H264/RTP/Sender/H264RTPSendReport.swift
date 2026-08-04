/// Successful transmission metadata for one encoded H.264 access unit.
public struct H264RTPSendReport: Sendable, Equatable {
    public let packetCount: Int
    public let plaintextByteCount: Int
    public let firstSequenceNumber: UInt16
    public let lastSequenceNumber: UInt16
    public let timestamp: UInt32

    public init(
        packetCount: Int,
        plaintextByteCount: Int,
        firstSequenceNumber: UInt16,
        lastSequenceNumber: UInt16,
        timestamp: UInt32
    ) {
        self.packetCount = packetCount
        self.plaintextByteCount = plaintextByteCount
        self.firstSequenceNumber = firstSequenceNumber
        self.lastSequenceNumber = lastSequenceNumber
        self.timestamp = timestamp
    }
}
