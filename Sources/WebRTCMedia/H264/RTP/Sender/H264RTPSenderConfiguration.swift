
/// Immutable RTP and packetization policy for one H.264 sender stream.
public struct H264RTPSenderConfiguration: Sendable, Equatable {
    /// Largest reservation that stays below RTP's half-sequence-space
    /// ambiguity after a sink rejects the first packet of an access unit.
    public static let largestSequenceSafePacketCount = 32_766

    public let payloadType: UInt8
    public let synchronizationSource: UInt32
    public let contributingSources: [UInt32]
    public let packetizationMode: H264PacketizationMode
    public let maximumDatagramByteCount: Int
    public let protectionTrailerByteCount: Int
    public let maximumPacketsPerAccessUnit: Int
    public let initialSequenceNumber: UInt16
    public let initialTimestamp: UInt32

    public init(
        payloadType: UInt8,
        synchronizationSource: UInt32,
        contributingSources: [UInt32] = [],
        packetizationMode: H264PacketizationMode = .nonInterleaved,
        maximumDatagramByteCount: Int = 1_200,
        protectionTrailerByteCount: Int,
        maximumPacketsPerAccessUnit: Int = 2_048,
        initialSequenceNumber: UInt16,
        initialTimestamp: UInt32
    ) throws(H264RTPSenderError) {
        guard payloadType <= 127 else {
            throw .invalidPayloadType(actual: payloadType)
        }
        guard packetizationMode != .interleaved else {
            throw .unsupportedPacketizationMode(packetizationMode)
        }
        guard (1...65_535).contains(maximumDatagramByteCount) else {
            throw .invalidMaximumDatagramByteCount(
                actual: maximumDatagramByteCount
            )
        }
        guard protectionTrailerByteCount >= 0,
              protectionTrailerByteCount <= maximumDatagramByteCount else {
            throw .invalidProtectionTrailerByteCount(
                actual: protectionTrailerByteCount
            )
        }
        guard contributingSources.count <= 15 else {
            throw .tooManyContributingSources(actual: contributingSources.count)
        }
        guard (1...Self.largestSequenceSafePacketCount).contains(
            maximumPacketsPerAccessUnit
        ) else {
            throw .invalidMaximumPacketsPerAccessUnit(
                actual: maximumPacketsPerAccessUnit
            )
        }

        self.payloadType = payloadType
        self.synchronizationSource = synchronizationSource
        self.contributingSources = contributingSources
        self.packetizationMode = packetizationMode
        self.maximumDatagramByteCount = maximumDatagramByteCount
        self.protectionTrailerByteCount = protectionTrailerByteCount
        self.maximumPacketsPerAccessUnit = maximumPacketsPerAccessUnit
        self.initialSequenceNumber = initialSequenceNumber
        self.initialTimestamp = initialTimestamp
    }
}
