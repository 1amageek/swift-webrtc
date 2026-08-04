/// Foundation `Data` compatibility layer over the Embedded-clean `SCTPWireCore`.
///
/// `SCTPWireCore` expresses the SCTP wire codec over `[UInt8]`/`P2PCoreBytes` so
/// it can build under Embedded Swift. This adapter restores the historical
/// `Data`-based public surface that the SCTP state machine (`SCTPAssociation`,
/// `FragmentAssembler`, `SCTPCookie`, …), `WebRTC`, and the existing test suite
/// bind to. It is pure bridging plus the package-internal `Data`-based byte
/// helpers the state machine still uses.
///
/// Host-only: the `Data`-based bridges below exist for the historical public API
/// and the test suite and are gated out of the Embedded build. The Embedded-clean
/// error bridges (`SCTPStateError.asSCTPError`, `SCTPWireError.rethrowUnwrapped`),
/// which the cored ``SCTPAssociationEngine`` also uses, live in
/// `SCTPErrorBridge.swift` (no Foundation).

#if !hasFeature(Embedded) && !os(WASI)
import Foundation

// Optional `[UInt8]?` <-> `Data` bridges. `AssembledMessage.data` is `[UInt8]`
// in the Embedded-clean core, so `someMessage?.data` is `[UInt8]?`; these let
// existing call sites (and tests) compare it directly to `Data`.
func == (lhs: [UInt8]?, rhs: Data) -> Bool { lhs.map { $0 == rhs } ?? false }
func == (lhs: Data, rhs: [UInt8]?) -> Bool { rhs.map { lhs == $0 } ?? false }
func != (lhs: [UInt8]?, rhs: Data) -> Bool { !(lhs == rhs) }
func != (lhs: Data, rhs: [UInt8]?) -> Bool { !(lhs == rhs) }

// MARK: - SCTPChunk (Data surface)

extension SCTPChunk {
    /// Create a chunk from a `Data` value.
    init(
        chunkType: UInt8,
        flags: UInt8 = 0,
        value: Data
    ) throws(SCTPError) {
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
            value: [UInt8](value)
        )
    }

    /// Encode the chunk to `Data`.
    func encode() -> Data {
        Data(encodeBytes())
    }

    /// Decode a chunk from `Data`.
    static func decode(from data: Data) throws -> SCTPChunk {
        do {
            return try decode(from: [UInt8](data))
        } catch {
            try error.rethrowUnwrapped()
        }
    }

    /// Decode a chunk from `Data` at a specific offset.
    static func decode(from data: Data, at offset: Int) throws -> SCTPChunk {
        do {
            return try decode(from: [UInt8](data), at: offset)
        } catch {
            try error.rethrowUnwrapped()
        }
    }
}

// MARK: - SCTPPacket (Data surface)

extension SCTPPacket {
    /// Encode the SCTP packet to `Data`.
    func encode() -> Data {
        Data(encodeBytes())
    }

    /// Decode an SCTP packet from `Data`.
    static func decode(from data: Data, validateChecksum: Bool = true) throws -> SCTPPacket {
        do {
            return try decode(from: [UInt8](data), validateChecksum: validateChecksum)
        } catch {
            try error.rethrowUnwrapped()
        }
    }
}

// MARK: - SCTPInitChunk (Data surface)

extension SCTPInitChunk {
    /// Encode to a `Data` chunk value.
    func encode() -> Data {
        Data(encodeBytes())
    }

    /// Decode from a `Data` chunk value.
    static func decode(from data: Data) throws -> SCTPInitChunk {
        do {
            return try decode(from: [UInt8](data))
        } catch {
            try error.rethrowUnwrapped()
        }
    }
}

// MARK: - SCTPDataChunk (Data surface)

extension SCTPDataChunk {
    /// Create a DATA chunk from a `Data` payload.
    init(
        tsn: UInt32,
        streamIdentifier: UInt16,
        streamSequenceNumber: UInt16,
        payloadProtocolIdentifier: UInt32,
        userData: Data,
        beginningFragment: Bool = true,
        endingFragment: Bool = true,
        unordered: Bool = false
    ) {
        self.init(
            tsn: tsn,
            streamIdentifier: streamIdentifier,
            streamSequenceNumber: streamSequenceNumber,
            payloadProtocolIdentifier: payloadProtocolIdentifier,
            userData: [UInt8](userData),
            beginningFragment: beginningFragment,
            endingFragment: endingFragment,
            unordered: unordered
        )
    }

    /// The user data as `Data`.
    var userDataValue: Data { Data(userData) }

    /// Encode to a `Data` chunk value.
    func encode() -> Data {
        Data(encodeBytes())
    }

    /// Decode from a `Data` chunk value.
    static func decode(from data: Data, flags: UInt8) throws -> SCTPDataChunk {
        do {
            return try decode(from: [UInt8](data), flags: flags)
        } catch {
            try error.rethrowUnwrapped()
        }
    }
}

// MARK: - SCTPSackChunk (Data surface)

extension SCTPSackChunk {
    /// Encode to a `Data` chunk value.
    func encode() throws(SCTPError) -> Data {
        do {
            return try Data(encodeBytes())
        } catch {
            try error.rethrowUnwrapped()
        }
    }

    /// Decode from a `Data` chunk value.
    static func decode(from data: Data) throws -> SCTPSackChunk {
        do {
            return try decode(from: [UInt8](data))
        } catch {
            try error.rethrowUnwrapped()
        }
    }
}

// MARK: - Package-internal Data byte helpers (state-machine use)

// SCTPCookie and SCTPAssociation parse fixed-width fields from `Data`/`[UInt8]`
// buffers. The Embedded-clean core keeps its own `[UInt8]` helpers private; these
// adapter-internal overloads serve the Foundation state-machine files.

func readUInt16(_ data: Data, offset: Int) -> UInt16 {
    UInt16(data[data.startIndex + offset]) << 8 | UInt16(data[data.startIndex + offset + 1])
}

func readUInt32(_ data: Data, offset: Int) -> UInt32 {
    UInt32(data[data.startIndex + offset]) << 24 |
    UInt32(data[data.startIndex + offset + 1]) << 16 |
    UInt32(data[data.startIndex + offset + 2]) << 8 |
    UInt32(data[data.startIndex + offset + 3])
}

func readUInt16(_ data: [UInt8], offset: Int) -> UInt16 {
    UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
}

func readUInt32(_ data: [UInt8], offset: Int) -> UInt32 {
    UInt32(data[offset]) << 24 |
    UInt32(data[offset + 1]) << 16 |
    UInt32(data[offset + 2]) << 8 |
    UInt32(data[offset + 3])
}

// MARK: - CRC-32C Data bridge (package-internal; used by benchmarks)

/// CRC-32C over `Data`, bridging to the Embedded-clean core implementation.
func crc32c(_ data: Data) -> UInt32 {
    crc32c([UInt8](data))
}

#endif
