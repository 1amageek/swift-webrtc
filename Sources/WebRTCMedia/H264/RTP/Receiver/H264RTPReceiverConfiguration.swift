
/// Immutable stream identity, packetization, latency, and memory limits.
public struct H264RTPReceiverConfiguration: Sendable, Equatable {
    public let payloadType: UInt8
    public let synchronizationSource: UInt32
    public let packetizationMode: H264PacketizationMode
    public let accessUnitFormat: H264RTPAccessUnitFormat
    public let maximumPacketByteCount: Int
    public let maximumAccessUnitByteCount: Int
    public let maximumAccessUnitInputByteCount: Int
    public let maximumAccessUnitDurationNanoseconds: UInt64
    public let maximumPacketsPerAccessUnit: Int
    public let maximumNALUnitsPerAccessUnit: Int
    public let maximumReorderPacketCount: Int
    public let maximumReorderByteCount: Int
    public let maximumReorderDelayNanoseconds: UInt64

    public init(
        payloadType: UInt8,
        synchronizationSource: UInt32,
        packetizationMode: H264PacketizationMode = .nonInterleaved,
        accessUnitFormat: H264RTPAccessUnitFormat = .annexB(startCodeByteCount: 4),
        maximumPacketByteCount: Int = 65_535,
        maximumAccessUnitByteCount: Int = 16 * 1_024 * 1_024,
        maximumAccessUnitInputByteCount: Int = 32 * 1_024 * 1_024,
        maximumAccessUnitDurationNanoseconds: UInt64 = 500_000_000,
        maximumPacketsPerAccessUnit: Int = 2_048,
        maximumNALUnitsPerAccessUnit: Int = 512,
        maximumReorderPacketCount: Int = 64,
        maximumReorderByteCount: Int = 4 * 1_024 * 1_024,
        maximumReorderDelayNanoseconds: UInt64 = 50_000_000
    ) throws(H264RTPReceiverError) {
        guard payloadType <= 127 else {
            throw .invalidPayloadType(actual: payloadType)
        }
        guard packetizationMode != .interleaved else {
            throw .unsupportedPacketizationMode(packetizationMode)
        }
        guard (1...65_535).contains(maximumPacketByteCount) else {
            throw .invalidMaximumPacketByteCount(actual: maximumPacketByteCount)
        }
        guard maximumAccessUnitByteCount > 0 else {
            throw .invalidMaximumAccessUnitByteCount(
                actual: maximumAccessUnitByteCount
            )
        }
        guard maximumAccessUnitInputByteCount >= maximumPacketByteCount else {
            throw .invalidMaximumAccessUnitInputByteCount(
                actual: maximumAccessUnitInputByteCount,
                minimum: maximumPacketByteCount
            )
        }
        guard maximumAccessUnitDurationNanoseconds > 0 else {
            throw .invalidMaximumAccessUnitDurationNanoseconds(
                actual: maximumAccessUnitDurationNanoseconds
            )
        }
        guard (1...32_767).contains(maximumPacketsPerAccessUnit) else {
            throw .invalidMaximumPacketsPerAccessUnit(
                actual: maximumPacketsPerAccessUnit
            )
        }
        guard (1...32_767).contains(maximumNALUnitsPerAccessUnit) else {
            throw .invalidMaximumNALUnitsPerAccessUnit(
                actual: maximumNALUnitsPerAccessUnit
            )
        }
        guard (1...32_767).contains(maximumReorderPacketCount) else {
            throw .invalidMaximumReorderPacketCount(
                actual: maximumReorderPacketCount
            )
        }
        guard maximumReorderByteCount >= maximumPacketByteCount else {
            throw .invalidMaximumReorderByteCount(
                actual: maximumReorderByteCount,
                minimum: maximumPacketByteCount
            )
        }
        guard maximumReorderDelayNanoseconds > 0 else {
            throw .invalidMaximumReorderDelayNanoseconds(
                actual: maximumReorderDelayNanoseconds
            )
        }
        switch accessUnitFormat {
        case .annexB(let startCodeByteCount):
            guard startCodeByteCount == 3 || startCodeByteCount == 4 else {
                throw .invalidAnnexBStartCodeByteCount(
                    actual: startCodeByteCount
                )
            }
        case .avcc(let lengthFieldByteCount):
            guard (1...4).contains(lengthFieldByteCount) else {
                throw .invalidAVCCLengthFieldByteCount(
                    actual: lengthFieldByteCount
                )
            }
        }

        self.payloadType = payloadType
        self.synchronizationSource = synchronizationSource
        self.packetizationMode = packetizationMode
        self.accessUnitFormat = accessUnitFormat
        self.maximumPacketByteCount = maximumPacketByteCount
        self.maximumAccessUnitByteCount = maximumAccessUnitByteCount
        self.maximumAccessUnitInputByteCount = maximumAccessUnitInputByteCount
        self.maximumAccessUnitDurationNanoseconds =
            maximumAccessUnitDurationNanoseconds
        self.maximumPacketsPerAccessUnit = maximumPacketsPerAccessUnit
        self.maximumNALUnitsPerAccessUnit = maximumNALUnitsPerAccessUnit
        self.maximumReorderPacketCount = maximumReorderPacketCount
        self.maximumReorderByteCount = maximumReorderByteCount
        self.maximumReorderDelayNanoseconds = maximumReorderDelayNanoseconds
    }
}
