/// One complete decoder-bound H.264 access unit.
///
/// `bytes` owns the only contiguous reconstruction buffer. `nalUnitRanges`
/// contains ranges into that exact owner and excludes Annex B start codes or
/// AVCC length fields. Copying this value retains Array COW storage; it does not
/// duplicate encoded media until one copy is mutated.
public struct H264RTPAccessUnit: Sendable {
    public let bytes: [UInt8]
    public let nalUnitRanges: [Range<Int>]
    public let rtpTimestamp: UInt32
    public let synchronizationSource: UInt32
    public let firstSequenceNumber: UInt16
    public let lastSequenceNumber: UInt16
    public let packetCount: Int
    public let containsInstantaneousDecoderRefresh: Bool

    init(
        bytes: consuming [UInt8],
        nalUnitRanges: consuming [Range<Int>],
        rtpTimestamp: UInt32,
        synchronizationSource: UInt32,
        firstSequenceNumber: UInt16,
        lastSequenceNumber: UInt16,
        packetCount: Int,
        containsInstantaneousDecoderRefresh: Bool
    ) {
        self.bytes = bytes
        self.nalUnitRanges = nalUnitRanges
        self.rtpTimestamp = rtpTimestamp
        self.synchronizationSource = synchronizationSource
        self.firstSequenceNumber = firstSequenceNumber
        self.lastSequenceNumber = lastSequenceNumber
        self.packetCount = packetCount
        self.containsInstantaneousDecoderRefresh = containsInstantaneousDecoderRefresh
    }
}
