/// SCTP Packet (RFC 4960)
///
/// SCTP common header and chunk format for SCTP-over-DTLS.

import P2PCoreBytes

/// SCTP packet header (12 bytes).
///
/// The Embedded-clean codec encodes/decodes over `[UInt8]`. Host compatibility
/// extensions add the `Data`-based `encode()->Data`/`decode(from:Data)` surface.
struct SCTPPacket: Sendable {
    /// Source port
    let sourcePort: UInt16

    /// Destination port
    let destinationPort: UInt16

    /// Verification tag
    let verificationTag: UInt32

    /// Checksum
    let checksum: UInt32

    /// Chunks
    let chunks: [SCTPChunk]

    /// Encoded byte count without materializing the packet.
    var encodedByteCount: Int {
        12 + chunks.reduce(into: 0) { count, chunk in
            count += chunk.encodedByteCount
        }
    }

    init(
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
    func encodeBytes() -> [UInt8] {
        var data = [UInt8]()
        data.reserveCapacity(encodedByteCount)

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
            chunk.appendEncoded(to: &data)
        }

        // Compute CRC-32C checksum
        // Checksum field is already zeroed, so compute directly
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
    /// - Throws: SCTPWireError if packet is malformed or checksum is invalid
    static func decode(from data: [UInt8], validateChecksum: Bool = true) throws(SCTPWireError) -> SCTPPacket {
        guard data.count >= 12 else {
            throw .decode(.insufficientData(expected: 12, actual: data.count))
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

            // Compute checksum with checksum field treated as zeros (no copy needed)
            let computedChecksum = crc32cWithZeroedChecksum(data)

            guard receivedChecksum == computedChecksum else {
                throw .decode(.checksumMismatch(expected: computedChecksum, actual: receivedChecksum))
            }
        }

        // Parse chunks (use offset-based decode to avoid copies)
        var offset = 12
        var chunks: [SCTPChunk] = []
        while offset + 4 <= data.count {
            let chunk = try SCTPChunk.decode(from: data, at: offset)
            chunks.append(chunk)
            // SCTPChunk.decode rejects length < 4, so paddedLength is always
            // >= 4. Re-assert the loop's progress invariant locally so this
            // loop can never spin without consuming bytes.
            let paddedLength = (Int(chunk.length) + 3) & ~3
            guard paddedLength >= 4 else {
                throw .decode(.invalidFormat("Chunk padded length \(paddedLength) does not advance parser"))
            }
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

// MARK: - CRC-32C (RFC 3309 / Castagnoli), slicing-by-8

/// CRC-32C over a byte buffer.
func crc32c(_ data: [UInt8]) -> UInt32 {
    data.withUnsafeBufferPointer { buffer in
        guard let baseAddress = buffer.baseAddress else { return 0 }
        return crc32cCore(ptr: baseAddress, count: buffer.count)
    }
}

/// CRC-32C with checksum field (bytes 8-11) treated as zeros.
///
/// Avoids copying the entire packet just to zero out 4 bytes.
func crc32cWithZeroedChecksum(_ data: [UInt8]) -> UInt32 {
    data.withUnsafeBufferPointer { buffer in
        guard let ptr = buffer.baseAddress else { return 0 }
        let count = buffer.count

        guard count >= 12 else {
            return crc32cCore(ptr: ptr, count: count)
        }

        var crc: UInt32 = 0xFFFFFFFF

        // Process bytes 0-7 (header before checksum)
        let word0 = crc ^
                   (UInt32(ptr[0]) |
                    (UInt32(ptr[1]) << 8) |
                    (UInt32(ptr[2]) << 16) |
                    (UInt32(ptr[3]) << 24))
        crc = crc32cTable3[Int(word0 & 0xFF)] ^
              crc32cTable2[Int((word0 >> 8) & 0xFF)] ^
              crc32cTable1[Int((word0 >> 16) & 0xFF)] ^
              crc32cTable0[Int((word0 >> 24) & 0xFF)]

        let word1 = crc ^
                   (UInt32(ptr[4]) |
                    (UInt32(ptr[5]) << 8) |
                    (UInt32(ptr[6]) << 16) |
                    (UInt32(ptr[7]) << 24))
        crc = crc32cTable3[Int(word1 & 0xFF)] ^
              crc32cTable2[Int((word1 >> 8) & 0xFF)] ^
              crc32cTable1[Int((word1 >> 16) & 0xFF)] ^
              crc32cTable0[Int((word1 >> 24) & 0xFF)]

        // Process bytes 8-11 as zeros (checksum field)
        // XOR with 0x00000000 is just crc itself
        let word2 = crc // ^ 0x00000000
        crc = crc32cTable3[Int(word2 & 0xFF)] ^
              crc32cTable2[Int((word2 >> 8) & 0xFF)] ^
              crc32cTable1[Int((word2 >> 16) & 0xFF)] ^
              crc32cTable0[Int((word2 >> 24) & 0xFF)]

        // Process remaining bytes (12 to end) using slicing-by-8
        var i = 12
        while i + 8 <= count {
            let w0 = crc ^
                       (UInt32(ptr[i]) |
                        (UInt32(ptr[i + 1]) << 8) |
                        (UInt32(ptr[i + 2]) << 16) |
                        (UInt32(ptr[i + 3]) << 24))
            let w1 = UInt32(ptr[i + 4]) |
                        (UInt32(ptr[i + 5]) << 8) |
                        (UInt32(ptr[i + 6]) << 16) |
                        (UInt32(ptr[i + 7]) << 24)
            crc = crc32cTable7[Int(w0 & 0xFF)] ^
                  crc32cTable6[Int((w0 >> 8) & 0xFF)] ^
                  crc32cTable5[Int((w0 >> 16) & 0xFF)] ^
                  crc32cTable4[Int((w0 >> 24) & 0xFF)] ^
                  crc32cTable3[Int(w1 & 0xFF)] ^
                  crc32cTable2[Int((w1 >> 8) & 0xFF)] ^
                  crc32cTable1[Int((w1 >> 16) & 0xFF)] ^
                  crc32cTable0[Int((w1 >> 24) & 0xFF)]
            i += 8
        }

        // Process remaining 4 bytes if available
        if i + 4 <= count {
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

        // Process remaining bytes
        while i < count {
            let index = Int((crc ^ UInt32(ptr[i])) & 0xFF)
            crc = (crc >> 8) ^ crc32cTable0[index]
            i += 1
        }

        return crc ^ 0xFFFFFFFF
    }
}

/// Core CRC-32C computation using slicing-by-8.
private func crc32cCore(ptr: UnsafePointer<UInt8>, count: Int) -> UInt32 {
    var crc: UInt32 = 0xFFFFFFFF
    var i = 0

    // Process 8 bytes at a time using slicing-by-8
    while i + 8 <= count {
        // First 4 bytes
        let word0 = crc ^
                   (UInt32(ptr[i]) |
                    (UInt32(ptr[i + 1]) << 8) |
                    (UInt32(ptr[i + 2]) << 16) |
                    (UInt32(ptr[i + 3]) << 24))
        // Second 4 bytes
        let word1 = UInt32(ptr[i + 4]) |
                    (UInt32(ptr[i + 5]) << 8) |
                    (UInt32(ptr[i + 6]) << 16) |
                    (UInt32(ptr[i + 7]) << 24)

        crc = crc32cTable7[Int(word0 & 0xFF)] ^
              crc32cTable6[Int((word0 >> 8) & 0xFF)] ^
              crc32cTable5[Int((word0 >> 16) & 0xFF)] ^
              crc32cTable4[Int((word0 >> 24) & 0xFF)] ^
              crc32cTable3[Int(word1 & 0xFF)] ^
              crc32cTable2[Int((word1 >> 8) & 0xFF)] ^
              crc32cTable1[Int((word1 >> 16) & 0xFF)] ^
              crc32cTable0[Int((word1 >> 24) & 0xFF)]
        i += 8
    }

    // Process remaining 4 bytes if available
    if i + 4 <= count {
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

/// Generate CRC-32C slicing tables (8 tables for slicing-by-8 algorithm).
private let (crc32cTable0, crc32cTable1, crc32cTable2, crc32cTable3,
             crc32cTable4, crc32cTable5, crc32cTable6, crc32cTable7):
    ([UInt32], [UInt32], [UInt32], [UInt32], [UInt32], [UInt32], [UInt32], [UInt32]) = {
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

    // Generate extended tables for slicing-by-8
    var table1 = [UInt32](repeating: 0, count: 256)
    var table2 = [UInt32](repeating: 0, count: 256)
    var table3 = [UInt32](repeating: 0, count: 256)
    var table4 = [UInt32](repeating: 0, count: 256)
    var table5 = [UInt32](repeating: 0, count: 256)
    var table6 = [UInt32](repeating: 0, count: 256)
    var table7 = [UInt32](repeating: 0, count: 256)

    for i in 0..<256 {
        table1[i] = (table0[i] >> 8) ^ table0[Int(table0[i] & 0xFF)]
        table2[i] = (table1[i] >> 8) ^ table0[Int(table1[i] & 0xFF)]
        table3[i] = (table2[i] >> 8) ^ table0[Int(table2[i] & 0xFF)]
        table4[i] = (table3[i] >> 8) ^ table0[Int(table3[i] & 0xFF)]
        table5[i] = (table4[i] >> 8) ^ table0[Int(table4[i] & 0xFF)]
        table6[i] = (table5[i] >> 8) ^ table0[Int(table5[i] & 0xFF)]
        table7[i] = (table6[i] >> 8) ^ table0[Int(table6[i] & 0xFF)]
    }

    return (table0, table1, table2, table3, table4, table5, table6, table7)
}()
