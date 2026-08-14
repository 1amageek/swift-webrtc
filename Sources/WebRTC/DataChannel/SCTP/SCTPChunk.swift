/// SCTP Chunk Types (RFC 4960)
///
/// Each SCTP chunk has: type (1) + flags (1) + length (2) + value

import NetworkingCore

/// SCTP chunk type identifiers
enum SCTPChunkType: UInt8, Sendable {
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
    case shutdownComplete = 14
    case forwardTSN = 0xC0
    case reConfig = 130
}

/// An SCTP chunk.
///
/// The Embedded-clean public surface exposes `[UInt8]`. Internally, DATA chunks
/// retain an immutable owner/range view so fragmentation and decoding do not
/// copy payload bytes. Host compatibility extensions add the `Data`-based
/// init/property and `encode()->Data`/`decode(from:Data)`.
struct SCTPChunk: Sendable {
    /// Chunk type
    let chunkType: UInt8

    /// Chunk flags
    let flags: UInt8

    /// Total chunk length (including header)
    let length: UInt16

    /// Chunk value.
    ///
    /// DATA chunks keep their payload as an owner/range view internally. This
    /// compatibility property materializes only when a caller explicitly asks
    /// for the complete generic chunk value.
    var value: [UInt8] { valueStorage.materialized() }

    private let valueStorage: SCTPChunkValueStorage

    /// Encoded byte count including RFC 4960 four-byte alignment padding.
    var encodedByteCount: Int {
        (Int(length) + 3) & ~3
    }

    init(
        chunkType: UInt8,
        flags: UInt8 = 0,
        value: [UInt8]
    ) throws(SCTPWireError) {
        let maximumValueByteCount = Int(UInt16.max) - 4
        guard value.count <= maximumValueByteCount else {
            throw .chunkValueTooLarge(
                actual: value.count,
                maximum: maximumValueByteCount
            )
        }
        self.init(
            validatedChunkType: chunkType,
            flags: flags,
            value: value
        )
    }

    /// Construct a chunk after the caller has proved the 16-bit length bound.
    ///
    /// This package-only boundary exists for fixed-size protocol chunks and
    /// values decoded from an already validated wire Chunk Length. Dynamic
    /// public input must use the throwing initializer above.
    package init(
        validatedChunkType chunkType: UInt8,
        flags: UInt8 = 0,
        value: [UInt8]
    ) {
        self.chunkType = chunkType
        self.flags = flags
        self.length = UInt16(4 + value.count)
        self.valueStorage = .bytes(SCTPByteView(
            owner: value,
            range: 0..<value.count
        ))
    }

    private init(
        chunkType: UInt8,
        flags: UInt8,
        length: UInt16,
        valueView: SCTPByteView
    ) {
        self.chunkType = chunkType
        self.flags = flags
        self.length = length
        self.valueStorage = .bytes(valueView)
    }

    package init(validatedDataChunk dataChunk: SCTPDataChunk) {
        self.chunkType = SCTPChunkType.data.rawValue
        self.flags = dataChunk.flags
        self.length = UInt16(16 + dataChunk.userDataByteCount)
        self.valueStorage = .data(dataChunk)
    }

    /// Encode the chunk
    func encodeBytes() -> [UInt8] {
        var data = [UInt8]()
        data.reserveCapacity(encodedByteCount)
        appendEncoded(to: &data)
        return data
    }

    /// Append one encoded chunk directly into its destination packet.
    ///
    /// Keeping this operation scoped to the wire package avoids allocating an
    /// intermediate chunk buffer for every DATA fragment.
    package func appendEncoded(to data: inout [UInt8]) {
        data.append(chunkType)
        data.append(flags)
        data.append(UInt8(length >> 8))
        data.append(UInt8(length & 0xFF))
        valueStorage.append(to: &data)

        // Pad to 4-byte boundary (avoid allocating temporary buffer)
        let padding = (4 - (Int(length) % 4)) % 4
        for _ in 0..<padding {
            data.append(0)
        }
    }

    /// Decode a chunk from bytes
    static func decode(from data: [UInt8]) throws(SCTPWireError) -> SCTPChunk {
        try decode(from: data, at: 0)
    }

    /// Decode a chunk from bytes at a specific offset
    static func decode(from data: [UInt8], at offset: Int) throws(SCTPWireError) -> SCTPChunk {
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

        return SCTPChunk(
            chunkType: chunkType,
            flags: flags,
            length: length,
            valueView: SCTPByteView(
                owner: data,
                range: (offset + 4)..<(offset + Int(length))
            )
        )
    }

    /// Decode a DATA chunk without materializing its generic chunk value.
    package func decodedDataChunk() throws(SCTPWireError) -> SCTPDataChunk {
        switch valueStorage {
        case .bytes(let view):
            return try SCTPDataChunk.decode(from: view, flags: flags)
        case .data(let dataChunk):
            return dataChunk
        }
    }
}

private enum SCTPChunkValueStorage: Sendable {
    case bytes(SCTPByteView)
    case data(SCTPDataChunk)

    func materialized() -> [UInt8] {
        switch self {
        case .bytes(let view):
            return view.materialized()
        case .data(let dataChunk):
            return dataChunk.encodeBytes()
        }
    }

    func append(to destination: inout [UInt8]) {
        switch self {
        case .bytes(let view):
            view.append(to: &destination)
        case .data(let dataChunk):
            dataChunk.appendEncodedValue(to: &destination)
        }
    }
}

// MARK: - INIT Chunk

/// SCTP INIT chunk parameters
struct SCTPInitChunk: Sendable {
    let initiateTag: UInt32
    let advertisedReceiverWindowCredit: UInt32
    let numberOfOutboundStreams: UInt16
    let numberOfInboundStreams: UInt16
    let initialTSN: UInt32

    init(
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
    func encodeBytes() -> [UInt8] {
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
    static func decode(from data: [UInt8]) throws(SCTPWireError) -> SCTPInitChunk {
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
    func toChunk(type: SCTPChunkType = .initChunk) -> SCTPChunk {
        SCTPChunk(validatedChunkType: type.rawValue, value: encodeBytes())
    }
}

// MARK: - DATA Chunk

/// An immutable range into an owned payload.
///
/// Every fragment retains the same Array owner and a distinct range. Array's
/// copy-on-write storage keeps this split O(1); materialization happens only at
/// the encoded-packet or delivered-message boundary.
struct SCTPByteView: Sendable {
    let owner: [UInt8]
    let range: Range<Int>

    var count: Int { range.count }

    func materialized() -> [UInt8] {
        if range.lowerBound == 0, range.upperBound == owner.count {
            return owner
        }
        return Array(owner[range])
    }

    func append(to destination: inout [UInt8]) {
        destination.append(contentsOf: owner[range])
    }
}

/// SCTP DATA chunk
struct SCTPDataChunk: Sendable {
    /// Transmission Sequence Number
    let tsn: UInt32

    /// Stream identifier
    let streamIdentifier: UInt16

    /// Stream sequence number
    let streamSequenceNumber: UInt16

    /// Payload protocol identifier (PPID)
    let payloadProtocolIdentifier: UInt32

    /// User data.
    ///
    /// Fragmented outbound chunks share one immutable owner internally. Reading
    /// this compatibility property materializes only the selected fragment.
    var userData: [UInt8] { userDataView.materialized() }

    /// Number of payload bytes without materializing a fragmented view.
    var userDataByteCount: Int { userDataView.count }

    let userDataView: SCTPByteView

    /// Chunk flags
    let flags: UInt8

    var unordered: Bool { flags & 0x04 != 0 }

    init(
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
        self.userDataView = SCTPByteView(
            owner: userData,
            range: 0..<userData.count
        )

        var f: UInt8 = 0
        if endingFragment { f |= 0x01 }
        if beginningFragment { f |= 0x02 }
        if unordered { f |= 0x04 }
        self.flags = f
    }

    /// Creates one fragment as a range over a shared immutable payload owner.
    ///
    /// The caller must validate the range before entering this initializer. It
    /// is package-scoped so untrusted wire input cannot bypass the decoder's
    /// bounds checks.
    package init(
        tsn: UInt32,
        streamIdentifier: UInt16,
        streamSequenceNumber: UInt16,
        payloadProtocolIdentifier: UInt32,
        userDataOwner: [UInt8],
        userDataRange: Range<Int>,
        beginningFragment: Bool,
        endingFragment: Bool,
        unordered: Bool
    ) {
        self.tsn = tsn
        self.streamIdentifier = streamIdentifier
        self.streamSequenceNumber = streamSequenceNumber
        self.payloadProtocolIdentifier = payloadProtocolIdentifier
        self.userDataView = SCTPByteView(
            owner: userDataOwner,
            range: userDataRange
        )

        var f: UInt8 = 0
        if endingFragment { f |= 0x01 }
        if beginningFragment { f |= 0x02 }
        if unordered { f |= 0x04 }
        self.flags = f
    }

    /// Encode to chunk value
    func encodeBytes() -> [UInt8] {
        var data = [UInt8]()
        data.reserveCapacity(12 + userDataByteCount)
        appendEncodedValue(to: &data)
        return data
    }

    func appendEncodedValue(to data: inout [UInt8]) {
        sctpAppendUInt32(&data, tsn)
        sctpAppendUInt16(&data, streamIdentifier)
        sctpAppendUInt16(&data, streamSequenceNumber)
        sctpAppendUInt32(&data, payloadProtocolIdentifier)
        userDataView.append(to: &data)
    }

    /// Decode from chunk value
    static func decode(from data: [UInt8], flags: UInt8) throws(SCTPWireError) -> SCTPDataChunk {
        try decode(
            from: SCTPByteView(owner: data, range: 0..<data.count),
            flags: flags
        )
    }

    static func decode(
        from view: SCTPByteView,
        flags: UInt8
    ) throws(SCTPWireError) -> SCTPDataChunk {
        guard view.count >= 12 else {
            throw .decode(.insufficientData(expected: 12, actual: view.count))
        }
        let offset = view.range.lowerBound
        return SCTPDataChunk(
            tsn: sctpReadUInt32(view.owner, offset: offset),
            streamIdentifier: sctpReadUInt16(view.owner, offset: offset + 4),
            streamSequenceNumber: sctpReadUInt16(view.owner, offset: offset + 6),
            payloadProtocolIdentifier: sctpReadUInt32(view.owner, offset: offset + 8),
            userDataOwner: view.owner,
            userDataRange: (offset + 12)..<view.range.upperBound,
            beginningFragment: flags & 0x02 != 0,
            endingFragment: flags & 0x01 != 0,
            unordered: flags & 0x04 != 0
        )
    }

    /// Create an SCTP chunk from this DATA
    func toChunk() throws(SCTPWireError) -> SCTPChunk {
        let maximumUserDataByteCount = Int(UInt16.max) - 16
        guard userDataByteCount <= maximumUserDataByteCount else {
            throw .chunkValueTooLarge(
                actual: 12 + userDataByteCount,
                maximum: Int(UInt16.max) - 4
            )
        }
        return SCTPChunk(validatedDataChunk: self)
    }
}

// MARK: - SACK Chunk

/// SCTP SACK (Selective Acknowledgment) chunk
struct SCTPSackChunk: Sendable {
    let cumulativeTSNAck: UInt32
    let advertisedReceiverWindowCredit: UInt32
    let gapAckBlocks: [(start: UInt16, end: UInt16)]
    let duplicateTSNs: [UInt32]

    init(
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
    func encodeBytes() throws(SCTPWireError) -> [UInt8] {
        let maximumValueByteCount = Int(UInt16.max) - 4
        let (entryCount, entryCountOverflow) = gapAckBlocks.count
            .addingReportingOverflow(duplicateTSNs.count)
        let (entryByteCount, entryByteCountOverflow) = entryCount
            .multipliedReportingOverflow(by: 4)
        let (encodedByteCount, encodedByteCountOverflow) = entryByteCount
            .addingReportingOverflow(12)
        let sizeOverflow = entryCountOverflow
            || entryByteCountOverflow
            || encodedByteCountOverflow
        guard !sizeOverflow,
              encodedByteCount <= maximumValueByteCount else {
            let actual = sizeOverflow
                ? Int.max
                : encodedByteCount
            throw .chunkValueTooLarge(
                actual: actual,
                maximum: maximumValueByteCount
            )
        }

        var data = [UInt8]()
        data.reserveCapacity(encodedByteCount)
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
    static func decode(from data: [UInt8]) throws(SCTPWireError) -> SCTPSackChunk {
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
    func toChunk() throws(SCTPWireError) -> SCTPChunk {
        try SCTPChunk(
            validatedChunkType: SCTPChunkType.sack.rawValue,
            value: encodeBytes()
        )
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
