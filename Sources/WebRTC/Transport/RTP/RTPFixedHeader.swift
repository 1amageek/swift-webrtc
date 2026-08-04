/// Scalar values from the fixed 12-byte RTP header.
public struct RTPFixedHeader: Sendable, Equatable {
    public let hasPadding: Bool
    public let hasExtension: Bool
    public let contributingSourceCount: UInt8
    public let marker: Bool
    public let payloadType: UInt8
    public let sequenceNumber: UInt16
    public let timestamp: UInt32
    public let synchronizationSource: UInt32

    init(
        hasPadding: Bool,
        hasExtension: Bool,
        contributingSourceCount: UInt8,
        marker: Bool,
        payloadType: UInt8,
        sequenceNumber: UInt16,
        timestamp: UInt32,
        synchronizationSource: UInt32
    ) {
        self.hasPadding = hasPadding
        self.hasExtension = hasExtension
        self.contributingSourceCount = contributingSourceCount
        self.marker = marker
        self.payloadType = payloadType
        self.sequenceNumber = sequenceNumber
        self.timestamp = timestamp
        self.synchronizationSource = synchronizationSource
    }
}
