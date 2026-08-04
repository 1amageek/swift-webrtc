/// STUN MESSAGE-INTEGRITY (RFC 5389 Section 15.4) — dual-build adapter.
///
/// The integrity-input construction and the constant-time verification live in
/// the Embedded-clean `MessageIntegrityCore` (STUNWireCore), which routes the
/// HMAC through the `MessageAuthenticationCode` seam. This adapter selects
/// `DefaultHMACSHA1` on every target and exposes both a `[UInt8]` surface
/// (Embedded-clean) and the historical `Data` surface (non-Embedded only).
/// Verification is fail-closed: a mismatch yields `.invalid`, never `.valid`.

import P2PCoreCrypto
#if !hasFeature(Embedded) && !os(WASI)
import Foundation
#endif
import P2PCrypto

/// The concrete MESSAGE-INTEGRITY HMAC-SHA1 for every build.
typealias STUNIntegrityMAC = DefaultHMACSHA1

/// MESSAGE-INTEGRITY computation and verification.
enum MessageIntegrity: Sendable {

    // MARK: - [UInt8] surface (Embedded-clean)

    /// Compute HMAC-SHA1 for the MESSAGE-INTEGRITY attribute (`[UInt8]`).
    static func computeBytes(data: [UInt8], key: [UInt8]) -> [UInt8] {
        MessageIntegrityCore.compute(data: data, key: key, as: STUNIntegrityMAC.self)
    }

    /// Verify MESSAGE-INTEGRITY in a STUN message (`[UInt8]`, tri-state result).
    static func verifyWithResultBytes(message input: [UInt8], key: [UInt8]) -> IntegrityResult {
        MessageIntegrityCore.verifyWithResult(message: input, key: key, as: STUNIntegrityMAC.self)
    }

    #if !hasFeature(Embedded) && !os(WASI)
    // MARK: - Data surface (host-only)

    /// Compute HMAC-SHA1 for the MESSAGE-INTEGRITY attribute.
    /// - Returns: 20-byte HMAC-SHA1.
    static func compute(data: Data, key: Data) -> Data {
        Data(computeBytes(data: [UInt8](data), key: [UInt8](key)))
    }

    /// Verify MESSAGE-INTEGRITY in a STUN message (tri-state result).
    static func verifyWithResult(message input: Data, key: Data) -> IntegrityResult {
        // `[UInt8](input)` is always zero-based, so a Data slice with a non-zero
        // startIndex is normalized here (the core uses absolute offsets).
        verifyWithResultBytes(message: [UInt8](input), key: [UInt8](key))
    }

    /// Verify MESSAGE-INTEGRITY in a STUN message (legacy boolean API).
    /// - Returns: True if integrity check passes (valid or missing returns false).
    @available(*, deprecated, message: "Use verifyWithResult instead for proper error handling")
    static func verify(message: Data, key: Data) -> Bool {
        verifyWithResult(message: message, key: key) == .valid
    }
    #endif
}
