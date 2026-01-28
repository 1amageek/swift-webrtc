/// STUN MESSAGE-INTEGRITY (RFC 5389 Section 15.4)
///
/// HMAC-SHA1 over the STUN message (header + attributes up to MESSAGE-INTEGRITY).
/// The message length in the header is adjusted to include MESSAGE-INTEGRITY.

import Foundation
import Crypto

/// MESSAGE-INTEGRITY computation and verification
public enum MessageIntegrity: Sendable {

    /// Compute HMAC-SHA1 for MESSAGE-INTEGRITY attribute
    /// - Parameters:
    ///   - data: The STUN message bytes (with adjusted length)
    ///   - key: The HMAC key (ICE password as UTF-8)
    /// - Returns: 20-byte HMAC-SHA1
    public static func compute(data: Data, key: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: data, using: symmetricKey)
        return Data(mac)
    }

    /// Verify MESSAGE-INTEGRITY in a STUN message
    /// - Parameters:
    ///   - message: The complete STUN message bytes
    ///   - key: The HMAC key
    /// - Returns: True if integrity check passes
    public static func verify(message: Data, key: Data) -> Bool {
        guard message.count >= stunHeaderSize else { return false }

        // Find MESSAGE-INTEGRITY attribute
        var offset = stunHeaderSize
        let messageLength = Int(UInt16(message[2]) << 8 | UInt16(message[3]))
        let end = stunHeaderSize + messageLength

        while offset + stunAttributeHeaderSize <= end {
            let attrType = UInt16(message[offset]) << 8 | UInt16(message[offset + 1])
            let attrLength = Int(UInt16(message[offset + 2]) << 8 | UInt16(message[offset + 3]))

            if attrType == STUNAttributeType.messageIntegrity.rawValue {
                guard attrLength == 20 else { return false }

                let receivedMAC = Data(message[offset + stunAttributeHeaderSize..<offset + stunAttributeHeaderSize + 20])

                // Recompute: use message up to (but not including) MESSAGE-INTEGRITY
                // with length adjusted to include MESSAGE-INTEGRITY
                var adjustedMsg = Data(message[0..<offset])
                let adjustedLength = UInt16(offset - stunHeaderSize + stunAttributeHeaderSize + 20)
                adjustedMsg[2] = UInt8(adjustedLength >> 8)
                adjustedMsg[3] = UInt8(adjustedLength & 0xFF)

                let computed = compute(data: adjustedMsg, key: key)
                return computed == receivedMAC
            }

            offset += stunAttributeHeaderSize + ((attrLength + 3) & ~3)
        }

        return false // No MESSAGE-INTEGRITY found
    }
}
