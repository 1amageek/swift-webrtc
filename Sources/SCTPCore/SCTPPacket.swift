/// SCTP Packet (RFC 4960)
///
/// SCTP common header and chunk format for SCTP-over-DTLS.

import Foundation

/// SCTP packet header (12 bytes)
public struct SCTPPacket: Sendable {
    /// Source port
    public let sourcePort: UInt16

    /// Destination port
    public let destinationPort: UInt16

    /// Verification tag
    public let verificationTag: UInt32

    /// Checksum
    public let checksum: UInt32

    /// Chunks
    public let chunks: [SCTPChunk]

    public init(
        sourcePort: UInt16,
        destinationPort: UInt16,
        verificationTag: UInt32,
        chunks: [SCTPChunk]
    ) {
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.verificationTag = verificationTag
        self.checksum = 0
        self.chunks = chunks
    }

    /// Encode the SCTP packet
    public func encode() -> Data {
        var data = Data(capacity: 12)

        data.append(UInt8(sourcePort >> 8))
        data.append(UInt8(sourcePort & 0xFF))
        data.append(UInt8(destinationPort >> 8))
        data.append(UInt8(destinationPort & 0xFF))

        // Verification tag (4 bytes)
        data.append(UInt8(verificationTag >> 24))
        data.append(UInt8((verificationTag >> 16) & 0xFF))
        data.append(UInt8((verificationTag >> 8) & 0xFF))
        data.append(UInt8(verificationTag & 0xFF))

        // Placeholder for checksum (filled after encoding all chunks)
        let checksumOffset = data.count
        data.append(contentsOf: [0, 0, 0, 0])

        // Encode chunks
        for chunk in chunks {
            data.append(chunk.encode())
        }

        // Compute CRC-32C checksum
        let crc = crc32c(Data(data[0..<checksumOffset]) + Data([0, 0, 0, 0]) + Data(data[(checksumOffset + 4)...]))
        data[checksumOffset] = UInt8(crc & 0xFF)
        data[checksumOffset + 1] = UInt8((crc >> 8) & 0xFF)
        data[checksumOffset + 2] = UInt8((crc >> 16) & 0xFF)
        data[checksumOffset + 3] = UInt8((crc >> 24) & 0xFF)

        return data
    }

    /// Decode an SCTP packet
    public static func decode(from data: Data) throws -> SCTPPacket {
        guard data.count >= 12 else {
            throw SCTPError.insufficientData(expected: 12, actual: data.count)
        }

        let sourcePort = UInt16(data[0]) << 8 | UInt16(data[1])
        let destinationPort = UInt16(data[2]) << 8 | UInt16(data[3])
        let verificationTag = UInt32(data[4]) << 24 | UInt32(data[5]) << 16 | UInt32(data[6]) << 8 | UInt32(data[7])

        // Parse chunks
        var offset = 12
        var chunks: [SCTPChunk] = []
        while offset + 4 <= data.count {
            let chunk = try SCTPChunk.decode(from: Data(data[offset...]))
            chunks.append(chunk)
            let paddedLength = (Int(chunk.length) + 3) & ~3
            offset += paddedLength
        }

        return SCTPPacket(
            sourcePort: sourcePort,
            destinationPort: destinationPort,
            verificationTag: verificationTag,
            chunks: chunks
        )
    }
}

/// CRC-32C implementation for SCTP checksum
func crc32c(_ data: Data) -> UInt32 {
    var crc: UInt32 = 0xFFFFFFFF
    for byte in data {
        let index = Int((crc ^ UInt32(byte)) & 0xFF)
        crc = (crc >> 8) ^ crc32cTable[index]
    }
    return crc ^ 0xFFFFFFFF
}

private let crc32cTable: [UInt32] = {
    var table = [UInt32](repeating: 0, count: 256)
    for i in 0..<256 {
        var crc = UInt32(i)
        for _ in 0..<8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F63B78 // CRC-32C polynomial
            } else {
                crc >>= 1
            }
        }
        table[i] = crc
    }
    return table
}()

/// SCTP errors
public enum SCTPError: Error, Sendable {
    case insufficientData(expected: Int, actual: Int)
    case invalidFormat(String)
    case associationFailed(String)
    case streamReset(String)
    case timeout
}
