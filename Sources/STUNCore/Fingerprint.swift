/// STUN FINGERPRINT (RFC 5389 Section 15.5)
///
/// CRC-32 of the STUN message XOR'd with 0x5354554E.

import Foundation

/// FINGERPRINT computation and verification
public enum STUNFingerprint: Sendable {

    /// XOR constant for STUN fingerprint
    private static let xorConstant: UInt32 = 0x5354554E

    /// Compute FINGERPRINT value
    /// - Parameter data: The STUN message bytes (with adjusted length)
    /// - Returns: 4-byte fingerprint
    public static func compute(data: Data) -> Data {
        let crc = crc32(data)
        let fingerprint = crc ^ xorConstant
        var result = Data(count: 4)
        result[0] = UInt8(fingerprint >> 24)
        result[1] = UInt8((fingerprint >> 16) & 0xFF)
        result[2] = UInt8((fingerprint >> 8) & 0xFF)
        result[3] = UInt8(fingerprint & 0xFF)
        return result
    }

    /// Verify FINGERPRINT in a STUN message
    /// - Parameter message: The complete STUN message bytes
    /// - Returns: True if fingerprint check passes
    public static func verify(message: Data) -> Bool {
        guard message.count >= stunHeaderSize + stunAttributeHeaderSize + 4 else {
            return false
        }

        // FINGERPRINT should be the last attribute
        let fpOffset = message.count - stunAttributeHeaderSize - 4
        let attrType = UInt16(message[fpOffset]) << 8 | UInt16(message[fpOffset + 1])

        guard attrType == STUNAttributeType.fingerprint.rawValue else {
            return false
        }

        let receivedFP = Data(message[fpOffset + stunAttributeHeaderSize..<fpOffset + stunAttributeHeaderSize + 4])

        // Compute over message up to (but not including) FINGERPRINT attribute
        let dataToHash = Data(message[0..<fpOffset])
        var adjustedMsg = dataToHash
        // Adjust length to include FINGERPRINT
        let adjustedLength = UInt16(fpOffset - stunHeaderSize + stunAttributeHeaderSize + 4)
        adjustedMsg[2] = UInt8(adjustedLength >> 8)
        adjustedMsg[3] = UInt8(adjustedLength & 0xFF)

        let computed = compute(data: adjustedMsg)
        return computed == receivedFP
    }

    // MARK: - CRC-32 Implementation

    /// CRC-32 lookup table
    private static let crc32Table: [UInt32] = {
        var table = [UInt32](repeating: 0, count: 256)
        for i in 0..<256 {
            var crc = UInt32(i)
            for _ in 0..<8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320
                } else {
                    crc >>= 1
                }
            }
            table[i] = crc
        }
        return table
    }()

    /// Compute CRC-32
    private static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFFFFFF
        for byte in data {
            let index = Int((crc ^ UInt32(byte)) & 0xFF)
            crc = (crc >> 8) ^ crc32Table[index]
        }
        return crc ^ 0xFFFFFFFF
    }
}
