/// Embedded-clean STUN MESSAGE-INTEGRITY (RFC 5389 Section 15.4).
///
/// This core owns the integrity INPUT construction (locate the MESSAGE-INTEGRITY
/// attribute, rebuild the prefix with the header length adjusted to cover the
/// attribute) and the constant-time verification, routing the HMAC through the
/// `MessageAuthenticationCode` seam. The concrete HMAC-SHA1 is supplied by the
/// caller (the STUNCore adapter's FoundationProvider). The verification is
/// fail-closed: a mismatch yields `.invalid`, never `.valid`.

import NetworkingCore
import SSLCrypto

/// Result of MESSAGE-INTEGRITY verification.
enum IntegrityResult: Sendable, Equatable {
    /// MESSAGE-INTEGRITY attribute present and valid.
    case valid
    /// MESSAGE-INTEGRITY attribute present but invalid.
    case invalid
    /// MESSAGE-INTEGRITY attribute not present.
    case missing
}

/// MESSAGE-INTEGRITY computation and verification, Embedded-clean.
enum MessageIntegrityCore: Sendable {

    /// HMAC-SHA1 length (the MESSAGE-INTEGRITY value is always 20 bytes).
    static let macSize = 20

    /// Compute the MAC for MESSAGE-INTEGRITY over `data` under `key`, via the seam.
    /// - Parameters:
    ///   - data: the STUN message bytes (with the length already adjusted).
    ///   - key: the HMAC key (ICE password as UTF-8).
    ///   - macType: the concrete MAC type backing the seam (HMAC-SHA1).
    /// - Returns: the MAC (20 bytes for HMAC-SHA1).
    static func compute<M: MessageAuthenticationCode>(
        data: [UInt8],
        key: [UInt8],
        as macType: M.Type
    ) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: M.tagByteCount)
        do {
            var destination = output.mutableSpan
            try M.authenticate(data.span, using: key.span, into: &destination)
        } catch {
            preconditionFailure(
                "Validated STUN HMAC input exceeded the primitive contract: \(error)"
            )
        }
        return output
    }

    /// Verify MESSAGE-INTEGRITY in a STUN message (tri-state result).
    ///
    /// Locates the MESSAGE-INTEGRITY attribute, rebuilds the HMAC input (message
    /// up to the attribute, with the header length adjusted to include it), and
    /// constant-time compares the stored MAC against a recompute via the seam.
    /// Fail-closed: any difference yields `.invalid`.
    /// - Parameters:
    ///   - message: the complete STUN message bytes (zero-based).
    ///   - key: the HMAC key.
    ///   - macType: the concrete MAC type backing the seam (HMAC-SHA1).
    static func verifyWithResult<M: MessageAuthenticationCode>(
        message: [UInt8],
        key: [UInt8],
        as macType: M.Type
    ) -> IntegrityResult {
        guard message.count >= stunHeaderSize else { return .missing }

        var offset = stunHeaderSize
        let messageLength = Int(UInt16(message[2]) << 8 | UInt16(message[3]))
        let end = stunHeaderSize + messageLength
        guard end <= message.count else { return .missing }

        while offset + stunAttributeHeaderSize <= end {
            let attrType = UInt16(message[offset]) << 8 | UInt16(message[offset + 1])
            let attrLength = Int(UInt16(message[offset + 2]) << 8 | UInt16(message[offset + 3]))

            if attrType == STUNAttributeType.messageIntegrity.rawValue {
                guard attrLength == macSize else { return .invalid }
                guard offset + stunAttributeHeaderSize + macSize <= message.count else {
                    return .invalid
                }

                // The stored MAC.
                var receivedMAC = [UInt8]()
                receivedMAC.reserveCapacity(macSize)
                for i in 0..<macSize {
                    receivedMAC.append(message[offset + stunAttributeHeaderSize + i])
                }

                // HMAC input: message up to (but excluding) MESSAGE-INTEGRITY,
                // with the header length adjusted to include the attribute.
                var adjustedMsg = [UInt8]()
                adjustedMsg.reserveCapacity(offset)
                for i in 0..<offset {
                    adjustedMsg.append(message[i])
                }
                let adjustedLength = UInt16(offset - stunHeaderSize + stunAttributeHeaderSize + macSize)
                adjustedMsg[2] = UInt8(adjustedLength >> 8)
                adjustedMsg[3] = UInt8(adjustedLength & 0xFF)

                // Constant-time recompute-and-compare via the seam. `M.isValid`
                // never short-circuits on a byte difference.
                let valid: Bool
                do {
                    valid = try M.isValidAuthenticationCode(
                        receivedMAC.span,
                        authenticating: adjustedMsg.span,
                        using: key.span
                    )
                } catch {
                    return .invalid
                }
                return valid ? .valid : .invalid
            }

            offset += stunAttributeHeaderSize + ((attrLength + 3) & ~3)
        }

        return .missing
    }
}
