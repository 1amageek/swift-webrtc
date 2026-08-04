
/// Bounded packet-owner and range metadata for one in-progress access unit.
struct H264RTPAccessUnitAssembly: Sendable {
    let timestamp: UInt32
    let synchronizationSource: UInt32
    let firstSequenceNumber: UInt16
    let startedAtNanoseconds: UInt64

    private(set) var lastSequenceNumber: UInt16
    private(set) var packetCount = 0
    private(set) var retainedInputByteCount = 0
    private(set) var outputByteCount = 0
    private(set) var packetOwners: [[UInt8]] = []
    private(set) var nalUnits: [H264RTPNALUnitPlan] = []
    private(set) var activeFragment: ActiveFragment?
    private(set) var containsInstantaneousDecoderRefresh = false

    var hasNALUnits: Bool { !nalUnits.isEmpty }

    init(
        timestamp: UInt32,
        synchronizationSource: UInt32,
        firstSequenceNumber: UInt16,
        startedAtNanoseconds: UInt64
    ) {
        self.timestamp = timestamp
        self.synchronizationSource = synchronizationSource
        self.firstSequenceNumber = firstSequenceNumber
        self.lastSequenceNumber = firstSequenceNumber
        self.startedAtNanoseconds = startedAtNanoseconds
    }

    mutating func beginPacket(
        sequenceNumber: UInt16,
        owner: [UInt8],
        maximumPacketCount: Int,
        maximumRetainedInputByteCount: Int
    ) throws(H264RTPReceiverError) -> Int {
        let nextPacketCount = packetCount + 1
        guard nextPacketCount <= maximumPacketCount else {
            throw .accessUnitPacketLimitExceeded(
                actual: nextPacketCount,
                maximum: maximumPacketCount
            )
        }
        let (nextInputByteCount, overflow) =
            retainedInputByteCount.addingReportingOverflow(owner.count)
        guard !overflow else { throw .integerOverflow }
        guard nextInputByteCount <= maximumRetainedInputByteCount else {
            throw .accessUnitInputByteLimitExceeded(
                minimumActual: nextInputByteCount,
                maximum: maximumRetainedInputByteCount
            )
        }

        packetCount = nextPacketCount
        lastSequenceNumber = sequenceNumber
        retainedInputByteCount = nextInputByteCount
        packetOwners.append(owner)
        return packetOwners.count - 1
    }

    mutating func appendCompleteNALUnit(
        header: H264NALUnitHeader,
        ownerIndex: Int,
        range: Range<Int>,
        format: H264RTPAccessUnitFormat,
        maximumByteCount: Int,
        maximumNALUnitCount: Int
    ) throws(H264RTPReceiverError) {
        try requireNALUnitCapacity(maximum: maximumNALUnitCount)
        try validate(range: range, ownerIndex: ownerIndex)
        try Self.validateNALUnitLength(range.count, format: format)
        try addOutputBytes(
            format.prefixByteCount + range.count,
            maximumByteCount: maximumByteCount
        )
        nalUnits.append(H264RTPNALUnitPlan(
            header: header,
            reconstructedHeader: nil,
            chunks: [H264RTPPayloadChunk(ownerIndex: ownerIndex, range: range)],
            byteCount: range.count
        ))
        if header.unitType == 5 {
            containsInstantaneousDecoderRefresh = true
        }
    }

    mutating func startFragmentedNALUnit(
        header: H264NALUnitHeader,
        ownerIndex: Int,
        range: Range<Int>,
        format: H264RTPAccessUnitFormat,
        maximumByteCount: Int,
        maximumNALUnitCount: Int
    ) throws(H264RTPReceiverError) {
        try requireNALUnitCapacity(maximum: maximumNALUnitCount)
        try validate(range: range, ownerIndex: ownerIndex)
        let (nalByteCount, overflow) = range.count.addingReportingOverflow(1)
        guard !overflow else { throw .integerOverflow }
        try Self.validateNALUnitLength(nalByteCount, format: format)
        try addOutputBytes(
            format.prefixByteCount + nalByteCount,
            maximumByteCount: maximumByteCount
        )

        nalUnits.append(H264RTPNALUnitPlan(
            header: header,
            reconstructedHeader: header.rawValue,
            chunks: [H264RTPPayloadChunk(ownerIndex: ownerIndex, range: range)],
            byteCount: nalByteCount
        ))
        activeFragment = ActiveFragment(
            header: header,
            nalUnitIndex: nalUnits.count - 1
        )
    }

    mutating func appendFragment(
        header: H264NALUnitHeader,
        ownerIndex: Int,
        range: Range<Int>,
        isEnd: Bool,
        format: H264RTPAccessUnitFormat,
        maximumByteCount: Int
    ) throws(H264RTPReceiverError) {
        guard let activeFragment else {
            throw .fragmentationUnitWithoutStart
        }
        guard activeFragment.header.rawValue == header.rawValue else {
            throw .fragmentationUnitHeaderMismatch(
                expected: activeFragment.header.rawValue,
                actual: header.rawValue
            )
        }
        try validate(range: range, ownerIndex: ownerIndex)

        let index = activeFragment.nalUnitIndex
        let (nextNALByteCount, nalOverflow) =
            nalUnits[index].byteCount.addingReportingOverflow(range.count)
        guard !nalOverflow else { throw .integerOverflow }
        try Self.validateNALUnitLength(nextNALByteCount, format: format)
        try addOutputBytes(range.count, maximumByteCount: maximumByteCount)

        nalUnits[index].chunks.append(H264RTPPayloadChunk(
            ownerIndex: ownerIndex,
            range: range
        ))
        nalUnits[index].byteCount = nextNALByteCount
        if isEnd {
            self.activeFragment = nil
            if header.unitType == 5 {
                containsInstantaneousDecoderRefresh = true
            }
        }
    }

    consuming func completedPlan() -> H264RTPAccessUnitPlan {
        H264RTPAccessUnitPlan(
            packetOwners: packetOwners,
            nalUnits: nalUnits,
            outputByteCount: outputByteCount,
            rtpTimestamp: timestamp,
            synchronizationSource: synchronizationSource,
            firstSequenceNumber: firstSequenceNumber,
            lastSequenceNumber: lastSequenceNumber,
            packetCount: packetCount,
            containsInstantaneousDecoderRefresh:
                containsInstantaneousDecoderRefresh
        )
    }

    private mutating func addOutputBytes(
        _ additionalByteCount: Int,
        maximumByteCount: Int
    ) throws(H264RTPReceiverError) {
        let (minimumActual, overflow) =
            outputByteCount.addingReportingOverflow(additionalByteCount)
        guard !overflow else { throw .integerOverflow }
        guard minimumActual <= maximumByteCount else {
            throw .accessUnitByteLimitExceeded(
                minimumActual: minimumActual,
                maximum: maximumByteCount
            )
        }
        outputByteCount = minimumActual
    }

    private func requireNALUnitCapacity(
        maximum: Int
    ) throws(H264RTPReceiverError) {
        let nextCount = nalUnits.count + 1
        guard nextCount <= maximum else {
            throw .accessUnitNALUnitLimitExceeded(
                actual: nextCount,
                maximum: maximum
            )
        }
    }

    private func validate(
        range: Range<Int>,
        ownerIndex: Int
    ) throws(H264RTPReceiverError) {
        guard packetOwners.indices.contains(ownerIndex),
              range.lowerBound >= 0,
              range.upperBound <= packetOwners[ownerIndex].count else {
            throw .invalidPayloadRange
        }
    }

    static func validateNALUnitLength(
        _ byteCount: Int,
        format: H264RTPAccessUnitFormat
    ) throws(H264RTPReceiverError) {
        guard case .avcc(let lengthFieldByteCount) = format else { return }
        let maximum = (UInt64(1) << (lengthFieldByteCount * 8)) - 1
        guard UInt64(byteCount) <= maximum else {
            throw .nalUnitLengthExceedsOutputFormat(
                actual: byteCount,
                // On 32-bit targets the four-byte AVCC maximum exceeds Int,
                // but the failing branch is unreachable because byteCount is
                // itself Int. Clamping keeps the diagnostic representable.
                maximum: Int(clamping: maximum)
            )
        }
    }
}

struct ActiveFragment: Sendable {
    let header: H264NALUnitHeader
    let nalUnitIndex: Int
}
