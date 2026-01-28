/// SCTP Chunk Types (RFC 4960)
///
/// Each SCTP chunk has: type (1) + flags (1) + length (2) + value

import Foundation

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

/// An SCTP chunk
public struct SCTPChunk: Sendable {
    /// Chunk type
    public let chunkType: UInt8

    /// Chunk flags
    public let flags: UInt8

    /// Total chunk length (including header)
    public let length: UInt16

    /// Chunk value
    public let value: Data

    public init(chunkType: UInt8, flags: UInt8 = 0, value: Data) {
        self.chunkType = chunkType
        self.flags = flags
        self.length = UInt16(4 + value.count)
        self.value = value
    }

    /// Encode the chunk
    public func encode() -> Data {
        var data = Data(capacity: Int(length))
        data.append(chunkType)
        data.append(flags)
        data.append(UInt8(length >> 8))
        data.append(UInt8(length & 0xFF))
        data.append(value)

        // Pad to 4-byte boundary
        let padding = (4 - (Int(length) % 4)) % 4
        if padding > 0 {
            data.append(Data(repeating: 0, count: padding))
        }

        return data
    }

    /// Decode a chunk from data
    public static func decode(from data: Data) throws -> SCTPChunk {
        guard data.count >= 4 else {
            throw SCTPError.insufficientData(expected: 4, actual: data.count)
        }

        let chunkType = data[0]
        let flags = data[1]
        let length = UInt16(data[2]) << 8 | UInt16(data[3])

        guard data.count >= Int(length) else {
            throw SCTPError.insufficientData(expected: Int(length), actual: data.count)
        }

        let value = Data(data[4..<Int(length)])
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
    public func encode() -> Data {
        var data = Data(capacity: 16)
        appendUInt32(&data, initiateTag)
        appendUInt32(&data, advertisedReceiverWindowCredit)
        appendUInt16(&data, numberOfOutboundStreams)
        appendUInt16(&data, numberOfInboundStreams)
        appendUInt32(&data, initialTSN)
        return data
    }

    /// Decode from chunk value
    public static func decode(from data: Data) throws -> SCTPInitChunk {
        guard data.count >= 16 else {
            throw SCTPError.insufficientData(expected: 16, actual: data.count)
        }
        return SCTPInitChunk(
            initiateTag: readUInt32(data, offset: 0),
            advertisedReceiverWindowCredit: readUInt32(data, offset: 4),
            numberOfOutboundStreams: readUInt16(data, offset: 8),
            numberOfInboundStreams: readUInt16(data, offset: 10),
            initialTSN: readUInt32(data, offset: 12)
        )
    }

    /// Create an SCTP chunk from this INIT
    public func toChunk(type: SCTPChunkType = .initChunk) -> SCTPChunk {
        SCTPChunk(chunkType: type.rawValue, value: encode())
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
    public let userData: Data

    /// Chunk flags
    public let flags: UInt8

    public init(
        tsn: UInt32,
        streamIdentifier: UInt16,
        streamSequenceNumber: UInt16,
        payloadProtocolIdentifier: UInt32,
        userData: Data,
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
    public func encode() -> Data {
        var data = Data(capacity: 12 + userData.count)
        appendUInt32(&data, tsn)
        appendUInt16(&data, streamIdentifier)
        appendUInt16(&data, streamSequenceNumber)
        appendUInt32(&data, payloadProtocolIdentifier)
        data.append(userData)
        return data
    }

    /// Decode from chunk value
    public static func decode(from data: Data, flags: UInt8) throws -> SCTPDataChunk {
        guard data.count >= 12 else {
            throw SCTPError.insufficientData(expected: 12, actual: data.count)
        }
        return SCTPDataChunk(
            tsn: readUInt32(data, offset: 0),
            streamIdentifier: readUInt16(data, offset: 4),
            streamSequenceNumber: readUInt16(data, offset: 6),
            payloadProtocolIdentifier: readUInt32(data, offset: 8),
            userData: Data(data[12...]),
            beginningFragment: flags & 0x02 != 0,
            endingFragment: flags & 0x01 != 0,
            unordered: flags & 0x04 != 0
        )
    }

    /// Create an SCTP chunk from this DATA
    public func toChunk() -> SCTPChunk {
        SCTPChunk(chunkType: SCTPChunkType.data.rawValue, flags: flags, value: encode())
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
    public func encode() -> Data {
        var data = Data()
        appendUInt32(&data, cumulativeTSNAck)
        appendUInt32(&data, advertisedReceiverWindowCredit)
        appendUInt16(&data, UInt16(gapAckBlocks.count))
        appendUInt16(&data, UInt16(duplicateTSNs.count))
        for gap in gapAckBlocks {
            appendUInt16(&data, gap.start)
            appendUInt16(&data, gap.end)
        }
        for tsn in duplicateTSNs {
            appendUInt32(&data, tsn)
        }
        return data
    }

    /// Decode from chunk value
    public static func decode(from data: Data) throws -> SCTPSackChunk {
        guard data.count >= 12 else {
            throw SCTPError.insufficientData(expected: 12, actual: data.count)
        }
        let cumulativeTSNAck = readUInt32(data, offset: 0)
        let arwc = readUInt32(data, offset: 4)
        let numGaps = Int(readUInt16(data, offset: 8))
        let numDups = Int(readUInt16(data, offset: 10))

        var gaps: [(UInt16, UInt16)] = []
        var offset = 12
        for _ in 0..<numGaps {
            guard offset + 4 <= data.count else { break }
            gaps.append((readUInt16(data, offset: offset), readUInt16(data, offset: offset + 2)))
            offset += 4
        }

        var dups: [UInt32] = []
        for _ in 0..<numDups {
            guard offset + 4 <= data.count else { break }
            dups.append(readUInt32(data, offset: offset))
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
        SCTPChunk(chunkType: SCTPChunkType.sack.rawValue, value: encode())
    }
}

// MARK: - Helpers

private func appendUInt16(_ data: inout Data, _ value: UInt16) {
    data.append(UInt8(value >> 8))
    data.append(UInt8(value & 0xFF))
}

private func appendUInt32(_ data: inout Data, _ value: UInt32) {
    data.append(UInt8(value >> 24))
    data.append(UInt8((value >> 16) & 0xFF))
    data.append(UInt8((value >> 8) & 0xFF))
    data.append(UInt8(value & 0xFF))
}

func readUInt16(_ data: Data, offset: Int) -> UInt16 {
    UInt16(data[data.startIndex + offset]) << 8 | UInt16(data[data.startIndex + offset + 1])
}

func readUInt32(_ data: Data, offset: Int) -> UInt32 {
    UInt32(data[data.startIndex + offset]) << 24 |
    UInt32(data[data.startIndex + offset + 1]) << 16 |
    UInt32(data[data.startIndex + offset + 2]) << 8 |
    UInt32(data[data.startIndex + offset + 3])
}
