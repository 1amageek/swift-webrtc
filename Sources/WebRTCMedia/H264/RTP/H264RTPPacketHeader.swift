/// RTP source fields for one H.264 packet.
///
/// The assembler derives the RTP marker bit from the RFC 6184 packet layout so
/// callers cannot accidentally mark an intermediate fragment as the end of an
/// access unit.
public struct H264RTPPacketHeader: Sendable, Equatable {
    public let payloadType: UInt8
    public let sequenceNumber: UInt16
    public let timestamp: UInt32
    public let synchronizationSource: UInt32
    public let contributingSources: [UInt32]

    public init(
        payloadType: UInt8,
        sequenceNumber: UInt16,
        timestamp: UInt32,
        synchronizationSource: UInt32,
        contributingSources: [UInt32] = []
    ) {
        self.payloadType = payloadType
        self.sequenceNumber = sequenceNumber
        self.timestamp = timestamp
        self.synchronizationSource = synchronizationSource
        self.contributingSources = contributingSources
    }
}
