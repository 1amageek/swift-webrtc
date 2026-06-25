/// Embedded-clean STUN error type + bridging from the `STUNWireCore` typed throws.
///
/// These carry NO Foundation / `Data` dependency, so they are shared by both the
/// host adapter and the Embedded path (`ICELiteAgent` etc. surface `STUNError`).
/// The `Data`-based bridges live in `STUNWireCompat.swift` (host-only).

@_exported import STUNWireCore

/// STUN errors (historical concrete type).
///
/// The Embedded-clean core throws ``STUNWireError``; this type is the historical
/// surface callers (and tests) catch.
public enum STUNError: Error, Sendable {
    case insufficientData(expected: Int, actual: Int)
    case invalidFormat(String)
    case invalidMagicCookie(UInt32)
    case integrityCheckFailed
    case fingerprintCheckFailed
}

extension STUNWireError {
    /// Rethrows the *wrapped* error mapped onto the historical ``STUNError``.
    ///
    /// In the bare `catch`, `error` has static type `STUNWireError` (the core's
    /// typed throw), so this avoids the generic-helper / `catch as` forms that
    /// miscompile with typed throws on this toolchain. Typed-throws `STUNError`
    /// keeps the Embedded build clean (an untyped `throws` erases to `any Error`).
    public func rethrowUnwrapped() throws(STUNError) -> Never {
        switch self {
        case .bytes:
            // The wrapped `ByteError` is not interpolated: string-interpolating an
            // arbitrary value forces machinery unavailable under Embedded Swift.
            throw STUNError.invalidFormat("byte error")
        case .decode(let e):
            switch e {
            case .insufficientData(let expected, let actual):
                throw STUNError.insufficientData(expected: expected, actual: actual)
            case .invalidFormat(let message):
                throw STUNError.invalidFormat(message)
            case .invalidMagicCookie(let cookie):
                throw STUNError.invalidMagicCookie(cookie)
            }
        }
    }
}
