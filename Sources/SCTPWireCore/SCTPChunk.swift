/// SCTP Chunk Types (RFC 4960)
///
/// Each SCTP chunk has: type (1) + flags (1) + length (2) + value

import P2PCoreBytes

/// SCTP chunk type identifiers
public enum SCTPChunkType: UInt8, Sendable {
    case data = 0
    case initChunk = 1
    case initAck = 2
    case sack = 3
    case heartbeat = 4
    case heartbeatAck = 5
    case abort = 6
    case shutdown = 7
    case shutdownAck = 8
    case error = 9
    case cookieEcho = 10
    case cookieAck = 11
    case forwardTSN = 0xC0
    case reConfig = 130
}

/// An SCTP chunk.
///
/// The Embedded-clean core stores the value as `[UInt8]`. The `SCTPCore` adapter
/// adds the `Data`-based init/property and `encode()->Data`/`decode(from:Data)`.
public struct SCTPChunk: Sendable {
    /// Chunk type
    public let chunkType: UInt8

    /// Chunk flags
    public let flags: UInt8

    /// Total chunk length (including header)
    public let length: UInt16

    /// Chunk value
    public let value: [UInt8]

    public init(chunkType: UInt8, flags: UInt8 = 0, value: [UInt8]) {
        self.chunkType = chunkType
        self.flags = flags
        self.length = UInt16(4 + value.count)
        self.value = value
    }

    /// Encode the chunk
    public func encodeBytes() -> [UInt8] {
        var data = [UInt8]()
        data.reserveCapacity(Int(length))
        data.append(chunkType)
        data.append(flags)
        data.append(UInt8(length >> 8))
        data.append(UInt8(length & 0xFF))
        data.append(contentsOf: value)

        // Pad to 4-byte boundary (avoid allocating temporary buffer)
        let padding = (4 - (Int(length) % 4)) % 4
        for _ in 0..<padding {
            data.append(0)
        }

        return data
    }

    /// Decode a chunk from bytes
    public static func decode(from data: [UInt8]) throws(SCTPWireError) -> SCTPChunk {
        try decode(from: data, at: 0)
    }

    /// Decode a chunk from bytes at a specific offset
    public static func decode(from data: [UInt8], at offset: Int) throws(SCTPWireError) -> SCTPChunk {
        guard data.count >= offset + 4 else {
            throw .decode(.insufficientData(expected: offset + 4, actual: data.count))
        }

        let chunkType = data[offset]
        let flags = data[offset + 1]
        let length = UInt16(data[offset + 2]) << 8 | UInt16(data[offset + 3])

        // RFC 4960 §3.2: the Chunk Length includes the 4-byte chunk header, so
        // it must be at least 4. A declared length below 4 is malformed and, if
        // accepted, would cause the packet-level chunk loop to never advance
        // (padded length 0) — an unbounded loop / OOM on a single packet.
        guard length >= 4 else {
            throw .decode(.invalidFormat("Chunk length \(length) below minimum of 4"))
        }

        guard data.count >= offset + Int(length) else {
            throw .decode(.insufficientData(expected: offset + Int(length), actual: data.count))
        }

        let value = Array(data[(offset + 4)..<(offset + Int(length))])
        return SCTPChunk(chunkType: chunkType, flags: flags, value: value)
    }
}

// MARK: - INIT Chunk

/// SCTP INIT chunk parameters
public struct SCTPInitChunk: Sendable {
    public let initiateTag: UInt32
    public let advertisedReceiverWindowCredit: UInt32
    public let numberOfOutboundStreams: UInt16
    public let numberOfInboundStreams: UInt16
    public let initialTSN: UInt32

    public init(
        initiateTag: UInt32,
        advertisedReceiverWindowCredit: UInt32 = 65535,
        numberOfOutboundStreams: UInt16 = 1,
        numberOfInboundStreams: UInt16 = 1,
        initialTSN: UInt32 = 0
    ) {
        self.initiateTag = initiateTag
        self.advertisedReceiverWindowCredit = advertisedReceiverWindowCredit
        self.numberOfOutboundStreams = numberOfOutboundStreams
        self.numberOfInboundStreams = numberOfInboundStreams
        self.initialTSN = initialTSN
    }

    /// Encode to chunk value
    public func encodeBytes() -> [UInt8] {
        var data = [UInt8]()
        data.reserveCapacity(16)
        sctpAppendUInt32(&data, initiateTag)
        sctpAppendUInt32(&data, advertisedReceiverWindowCredit)
        sctpAppendUInt16(&data, numberOfOutboundStreams)
        sctpAppendUInt16(&data, numberOfInboundStreams)
        sctpAppendUInt32(&data, initialTSN)
        return data
    }

    /// Decode from chunk value
    public static func decode(from data: [UInt8]) throws(SCTPWireError) -> SCTPInitChunk {
        guard data.count >= 16 else {
            throw .decode(.insufficientData(expected: 16, actual: data.count))
        }
        return SCTPInitChunk(
            initiateTag: sctpReadUInt32(data, offset: 0),
            advertisedReceiverWindowCredit: sctpReadUInt32(data, offset: 4),
            numberOfOutboundStreams: sctpReadUInt16(data, offset: 8),
            numberOfInboundStreams: sctpReadUInt16(data, offset: 10),
            initialTSN: sctpReadUInt32(data, offset: 12)
        )
    }

    /// Create an SCTP chunk from this INIT
    public func toChunk(type: SCTPChunkType = .initChunk) -> SCTPChunk {
        SCTPChunk(chunkType: type.rawValue, value: encodeBytes())
    }
}

// MARK: - DATA Chunk

/// SCTP DATA chunk
public struct SCTPDataChunk: Sendable {
    /// Transmission Sequence Number
    public let tsn: UInt32

    /// Stream identifier
    public let streamIdentifier: UInt16

    /// Stream sequence number
    public let streamSequenceNumber: UInt16

    /// Payload protocol identifier (PPID)
    public let payloadProtocolIdentifier: UInt32

    /// User data
    public let userData: [UInt8]

    /// Chunk flags
    public let flags: UInt8

    public init(
        tsn: UInt32,
        streamIdentifier: UInt16,
        streamSequenceNumber: UInt16,
        payloadProtocolIdentifier: UInt32,
        userData: [UInt8],
        beginningFragment: Bool = true,
        endingFragment: Bool = true,
        unordered: Bool = false
    ) {
        self.tsn = tsn
        self.streamIdentifier = streamIdentifier
        self.streamSequenceNumber = streamSequenceNumber
        self.payloadProtocolIdentifier = payloadProtocolIdentifier
        self.userData = userData

        var f: UInt8 = 0
        if endingFragment { f |= 0x01 }
        if beginningFragment { f |= 0x02 }
        if unordered { f |= 0x04 }
        self.flags = f
    }

    /// Encode to chunk value
    public func encodeBytes() -> [UInt8] {
        var data = [UInt8]()
        data.reserveCapacity(12 + userData.count)
        sctpAppendUInt32(&data, tsn)
        sctpAppendUInt16(&data, streamIdentifier)
        sctpAppendUInt16(&data, streamSequenceNumber)
        sctpAppendUInt32(&data, payloadProtocolIdentifier)
        data.append(contentsOf: userData)
        return data
    }

    /// Decode from chunk value
    public static func decode(from data: [UInt8], flags: UInt8) throws(SCTPWireError) -> SCTPDataChunk {
        guard data.count >= 12 else {
            throw .decode(.insufficientData(expected: 12, actual: data.count))
        }
        return SCTPDataChunk(
            tsn: sctpReadUInt32(data, offset: 0),
            streamIdentifier: sctpReadUInt16(data, offset: 4),
            streamSequenceNumber: sctpReadUInt16(data, offset: 6),
            payloadProtocolIdentifier: sctpReadUInt32(data, offset: 8),
            userData: Array(data[12...]),
            beginningFragment: flags & 0x02 != 0,
            endingFragment: flags & 0x01 != 0,
            unordered: flags & 0x04 != 0
        )
    }

    /// Create an SCTP chunk from this DATA
    public func toChunk() -> SCTPChunk {
        SCTPChunk(chunkType: SCTPChunkType.data.rawValue, flags: flags, value: encodeBytes())
    }
}

// MARK: - SACK Chunk

/// SCTP SACK (Selective Acknowledgment) chunk
public struct SCTPSackChunk: Sendable {
    public let cumulativeTSNAck: UInt32
    public let advertisedReceiverWindowCredit: UInt32
    public let gapAckBlocks: [(start: UInt16, end: UInt16)]
    public let duplicateTSNs: [UInt32]

    public init(
        cumulativeTSNAck: UInt32,
        advertisedReceiverWindowCredit: UInt32 = 65535,
        gapAckBlocks: [(start: UInt16, end: UInt16)] = [],
        duplicateTSNs: [UInt32] = []
    ) {
        self.cumulativeTSNAck = cumulativeTSNAck
        self.advertisedReceiverWindowCredit = advertisedReceiverWindowCredit
        self.gapAckBlocks = gapAckBlocks
        self.duplicateTSNs = duplicateTSNs
    }

    /// Encode to chunk value
    public func encodeBytes() -> [UInt8] {
        var data = [UInt8]()
        data.reserveCapacity(12 + 4 * gapAckBlocks.count + 4 * duplicateTSNs.count)
        sctpAppendUInt32(&data, cumulativeTSNAck)
        sctpAppendUInt32(&data, advertisedReceiverWindowCredit)
        sctpAppendUInt16(&data, UInt16(gapAckBlocks.count))
        sctpAppendUInt16(&data, UInt16(duplicateTSNs.count))
        for gap in gapAckBlocks {
            sctpAppendUInt16(&data, gap.start)
            sctpAppendUInt16(&data, gap.end)
        }
        for tsn in duplicateTSNs {
            sctpAppendUInt32(&data, tsn)
        }
        return data
    }

    /// Decode from chunk value
    public static func decode(from data: [UInt8]) throws(SCTPWireError) -> SCTPSackChunk {
        guard data.count >= 12 else {
            throw .decode(.insufficientData(expected: 12, actual: data.count))
        }
        let cumulativeTSNAck = sctpReadUInt32(data, offset: 0)
        let arwc = sctpReadUInt32(data, offset: 4)
        let numGaps = Int(sctpReadUInt16(data, offset: 8))
        let numDups = Int(sctpReadUInt16(data, offset: 10))

        // A SACK whose declared block counts exceed the available bytes is
        // malformed — reject it instead of silently accepting a partial chunk.
        let requiredCount = 12 + 4 * numGaps + 4 * numDups
        guard data.count >= requiredCount else {
            throw .decode(.insufficientData(expected: requiredCount, actual: data.count))
        }

        var gaps: [(start: UInt16, end: UInt16)] = []
        gaps.reserveCapacity(numGaps)
        var offset = 12
        for _ in 0..<numGaps {
            gaps.append((sctpReadUInt16(data, offset: offset), sctpReadUInt16(data, offset: offset + 2)))
            offset += 4
        }

        var dups: [UInt32] = []
        dups.reserveCapacity(numDups)
        for _ in 0..<numDups {
            dups.append(sctpReadUInt32(data, offset: offset))
            offset += 4
        }

        return SCTPSackChunk(
            cumulativeTSNAck: cumulativeTSNAck,
            advertisedReceiverWindowCredit: arwc,
            gapAckBlocks: gaps,
            duplicateTSNs: dups
        )
    }

    /// Create an SCTP chunk from this SACK
    public func toChunk() -> SCTPChunk {
        SCTPChunk(chunkType: SCTPChunkType.sack.rawValue, value: encodeBytes())
    }
}

// MARK: - Byte helpers (Embedded-clean, [UInt8])

func sctpAppendUInt16(_ data: inout [UInt8], _ value: UInt16) {
    data.append(UInt8(value >> 8))
    data.append(UInt8(value & 0xFF))
}

func sctpAppendUInt32(_ data: inout [UInt8], _ value: UInt32) {
    data.append(UInt8(value >> 24))
    data.append(UInt8((value >> 16) & 0xFF))
    data.append(UInt8((value >> 8) & 0xFF))
    data.append(UInt8(value & 0xFF))
}

func sctpReadUInt16(_ data: [UInt8], offset: Int) -> UInt16 {
    UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
}

func sctpReadUInt32(_ data: [UInt8], offset: Int) -> UInt32 {
    UInt32(data[offset]) << 24 |
    UInt32(data[offset + 1]) << 16 |
    UInt32(data[offset + 2]) << 8 |
    UInt32(data[offset + 3])
}
