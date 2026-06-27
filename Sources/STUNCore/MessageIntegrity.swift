/// STUN MESSAGE-INTEGRITY (RFC 5389 Section 15.4) — dual-build adapter.
///
/// The integrity-input construction and the constant-time verification live in
/// the Embedded-clean `MessageIntegrityCore` (STUNWireCore), which routes the
/// HMAC through the `MessageAuthenticationCode` seam. This adapter selects the
/// concrete HMAC-SHA1 for the build (host: ``FoundationHMACSHA1``; Embedded:
/// `BoringHMACSHA1`) and exposes both a `[UInt8]` surface (Embedded-clean) and the
/// historical `Data` surface (host-only). Verification is fail-closed: a mismatch
/// yields `.invalid`, never `.valid`.

import STUNWireCore
import P2PCoreCrypto
#if !hasFeature(Embedded)
import Foundation
#else
import P2PCryptoBoringSSL
#endif

/// The concrete MESSAGE-INTEGRITY HMAC-SHA1 for this build.
#if !hasFeature(Embedded)
typealias STUNIntegrityMAC = FoundationHMACSHA1
#else
typealias STUNIntegrityMAC = BoringHMACSHA1
#endif

// Re-export the moved `IntegrityResult` so existing call sites keep using
// `STUNCore.IntegrityResult` unchanged.
public typealias IntegrityResult = STUNWireCore.IntegrityResult

/// MESSAGE-INTEGRITY computation and verification.
public enum MessageIntegrity: Sendable {

    // MARK: - [UInt8] surface (Embedded-clean)

    /// Compute HMAC-SHA1 for the MESSAGE-INTEGRITY attribute (`[UInt8]`).
    public static func computeBytes(data: [UInt8], key: [UInt8]) -> [UInt8] {
        MessageIntegrityCore.compute(data: data, key: key, as: STUNIntegrityMAC.self)
    }

    /// Verify MESSAGE-INTEGRITY in a STUN message (`[UInt8]`, tri-state result).
    public static func verifyWithResultBytes(message input: [UInt8], key: [UInt8]) -> IntegrityResult {
        MessageIntegrityCore.verifyWithResult(message: input, key: key, as: STUNIntegrityMAC.self)
    }

    #if !hasFeature(Embedded)
    // MARK: - Data surface (host-only)

    /// Compute HMAC-SHA1 for the MESSAGE-INTEGRITY attribute.
    /// - Returns: 20-byte HMAC-SHA1.
    public static func compute(data: Data, key: Data) -> Data {
        Data(computeBytes(data: [UInt8](data), key: [UInt8](key)))
    }

    /// Verify MESSAGE-INTEGRITY in a STUN message (tri-state result).
    public static func verifyWithResult(message input: Data, key: Data) -> IntegrityResult {
        // `[UInt8](input)` is always zero-based, so a Data slice with a non-zero
        // startIndex is normalized here (the core uses absolute offsets).
        verifyWithResultBytes(message: [UInt8](input), key: [UInt8](key))
    }

    /// Verify MESSAGE-INTEGRITY in a STUN message (legacy boolean API).
    /// - Returns: True if integrity check passes (valid or missing returns false).
    @available(*, deprecated, message: "Use verifyWithResult instead for proper error handling")
    public static func verify(message: Data, key: Data) -> Bool {
        verifyWithResult(message: message, key: key) == .valid
    }
    #endif
}
