/// STUN MESSAGE-INTEGRITY (RFC 5389 Section 15.4) — Foundation adapter.
///
/// The integrity-input construction and the constant-time verification live in
/// the Embedded-clean `MessageIntegrityCore` (STUNWireCore), which routes the
/// HMAC through the `MessageAuthenticationCode` seam. This adapter keeps the
/// historical `Data`-based surface and supplies the concrete HMAC-SHA1 via the
/// lib-internal ``FoundationHMACSHA1`` provider. Verification is fail-closed: a
/// mismatch yields `.invalid`, never `.valid`.

import Foundation
import STUNWireCore

// Re-export the moved `IntegrityResult` so existing call sites keep using
// `STUNCore.IntegrityResult` unchanged.
public typealias IntegrityResult = STUNWireCore.IntegrityResult

/// MESSAGE-INTEGRITY computation and verification (`Data`-based adapter surface).
public enum MessageIntegrity: Sendable {

    /// Compute HMAC-SHA1 for the MESSAGE-INTEGRITY attribute.
    /// - Parameters:
    ///   - data: The STUN message bytes (with adjusted length)
    ///   - key: The HMAC key (ICE password as UTF-8)
    /// - Returns: 20-byte HMAC-SHA1
    public static func compute(data: Data, key: Data) -> Data {
        Data(MessageIntegrityCore.compute(
            data: [UInt8](data),
            key: [UInt8](key),
            as: FoundationHMACSHA1.self
        ))
    }

    /// Verify MESSAGE-INTEGRITY in a STUN message (tri-state result).
    /// - Parameters:
    ///   - message: The complete STUN message bytes
    ///   - key: The HMAC key
    /// - Returns: IntegrityResult indicating valid, invalid, or missing
    public static func verifyWithResult(message input: Data, key: Data) -> IntegrityResult {
        // `[UInt8](input)` is always zero-based, so a Data slice with a non-zero
        // startIndex is normalized here (the core uses absolute offsets).
        MessageIntegrityCore.verifyWithResult(
            message: [UInt8](input),
            key: [UInt8](key),
            as: FoundationHMACSHA1.self
        )
    }

    /// Verify MESSAGE-INTEGRITY in a STUN message (legacy boolean API).
    /// - Parameters:
    ///   - message: The complete STUN message bytes
    ///   - key: The HMAC key
    /// - Returns: True if integrity check passes (valid or missing returns false)
    @available(*, deprecated, message: "Use verifyWithResult instead for proper error handling")
    public static func verify(message: Data, key: Data) -> Bool {
        verifyWithResult(message: message, key: key) == .valid
    }
}
