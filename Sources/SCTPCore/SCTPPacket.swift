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
        // Checksum field is already zeroed (from line 54), so compute directly
        let crc = crc32c(data)
        data[checksumOffset] = UInt8(crc & 0xFF)
        data[checksumOffset + 1] = UInt8((crc >> 8) & 0xFF)
        data[checksumOffset + 2] = UInt8((crc >> 16) & 0xFF)
        data[checksumOffset + 3] = UInt8((crc >> 24) & 0xFF)

        return data
    }

    /// Decode an SCTP packet
    /// - Parameter data: Raw packet data
    /// - Parameter validateChecksum: Whether to validate CRC-32C checksum (default: true)
    /// - Throws: SCTPError if packet is malformed or checksum is invalid
    public static func decode(from data: Data, validateChecksum: Bool = true) throws -> SCTPPacket {
        guard data.count >= 12 else {
            throw SCTPError.insufficientData(expected: 12, actual: data.count)
        }

        let sourcePort = UInt16(data[0]) << 8 | UInt16(data[1])
        let destinationPort = UInt16(data[2]) << 8 | UInt16(data[3])
        let verificationTag = UInt32(data[4]) << 24 | UInt32(data[5]) << 16 | UInt32(data[6]) << 8 | UInt32(data[7])

        // Validate CRC-32C checksum
        if validateChecksum {
            // Extract received checksum (bytes 8-11, little-endian)
            let receivedChecksum = UInt32(data[8]) |
                                   UInt32(data[9]) << 8 |
                                   UInt32(data[10]) << 16 |
                                   UInt32(data[11]) << 24

            // Compute checksum with checksum field zeroed
            var checksumData = Data(data)
            checksumData[8] = 0
            checksumData[9] = 0
            checksumData[10] = 0
            checksumData[11] = 0
            let computedChecksum = crc32c(checksumData)

            guard receivedChecksum == computedChecksum else {
                throw SCTPError.checksumMismatch(expected: computedChecksum, actual: receivedChecksum)
            }
        }

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

/// CRC-32C implementation for SCTP checksum using slicing-by-4
func crc32c(_ data: Data) -> UInt32 {
    data.withUnsafeBytes { buffer in
        guard let baseAddress = buffer.baseAddress else {
            return 0
        }
        let ptr = baseAddress.assumingMemoryBound(to: UInt8.self)
        var crc: UInt32 = 0xFFFFFFFF
        var i = 0
        let count = buffer.count

        // Process 4 bytes at a time using slicing-by-4
        while i + 4 <= count {
            // XOR current CRC with 4 bytes (little-endian)
            let word = crc ^
                       (UInt32(ptr[i]) |
                        (UInt32(ptr[i + 1]) << 8) |
                        (UInt32(ptr[i + 2]) << 16) |
                        (UInt32(ptr[i + 3]) << 24))

            crc = crc32cTable3[Int(word & 0xFF)] ^
                  crc32cTable2[Int((word >> 8) & 0xFF)] ^
                  crc32cTable1[Int((word >> 16) & 0xFF)] ^
                  crc32cTable0[Int((word >> 24) & 0xFF)]
            i += 4
        }

        // Process remaining bytes using the base table
        while i < count {
            let index = Int((crc ^ UInt32(ptr[i])) & 0xFF)
            crc = (crc >> 8) ^ crc32cTable0[index]
            i += 1
        }

        return crc ^ 0xFFFFFFFF
    }
}

/// Generate CRC-32C slicing tables (4 tables for slicing-by-4 algorithm)
private let (crc32cTable0, crc32cTable1, crc32cTable2, crc32cTable3): ([UInt32], [UInt32], [UInt32], [UInt32]) = {
    let polynomial: UInt32 = 0x82F63B78 // CRC-32C polynomial (Castagnoli)

    // Generate base table (table0) - standard CRC lookup table
    var table0 = [UInt32](repeating: 0, count: 256)
    for i in 0..<256 {
        var crc = UInt32(i)
        for _ in 0..<8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ polynomial
            } else {
                crc >>= 1
            }
        }
        table0[i] = crc
    }

    // Generate extended tables for slicing-by-4
    // Each table[n][i] represents CRC of byte value i shifted by n bytes
    var table1 = [UInt32](repeating: 0, count: 256)
    var table2 = [UInt32](repeating: 0, count: 256)
    var table3 = [UInt32](repeating: 0, count: 256)

    for i in 0..<256 {
        // table1[i] = CRC of (i followed by one zero byte)
        table1[i] = (table0[i] >> 8) ^ table0[Int(table0[i] & 0xFF)]
        // table2[i] = CRC of (i followed by two zero bytes)
        table2[i] = (table1[i] >> 8) ^ table0[Int(table1[i] & 0xFF)]
        // table3[i] = CRC of (i followed by three zero bytes)
        table3[i] = (table2[i] >> 8) ^ table0[Int(table2[i] & 0xFF)]
    }

    return (table0, table1, table2, table3)
}()

/// SCTP errors
public enum SCTPError: Error, Sendable {
    case insufficientData(expected: Int, actual: Int)
    case invalidFormat(String)
    case associationFailed(String)
    case streamReset(String)
    case timeout
    case checksumMismatch(expected: UInt32, actual: UInt32)
    case cookieValidationFailed
    case cookieExpired
    case maxRetransmitsExceeded
}
