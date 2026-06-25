/// Embedded-clean error bridging between the `SCTPWireCore` typed throws and the
/// historical ``SCTPError``.
///
/// These two extensions carry NO Foundation / `Data` dependency, so they are
/// shared by both the host adapter and the Embedded-clean ``SCTPAssociationEngine``
/// (which calls `error.asSCTPError` / `error.rethrowUnwrapped()` to surface the
/// historical error type). The `Data`-based bridges live in `SCTPWireCompat.swift`
/// (host-only).

@_exported import SCTPWireCore

// MARK: - SCTPStateError bridging

extension SCTPStateError {
    /// Maps the Embedded-clean state-machine error onto the historical
    /// ``SCTPError`` so existing call sites (and tests) keep catching `SCTPError`.
    public var asSCTPError: SCTPError {
        switch self {
        case .receiveBufferExceeded(let streamID):
            return .receiveBufferExceeded(streamID: streamID)
        case .sendQueueFull(let bytesInFlight, let limit):
            return .sendQueueFull(bytesInFlight: bytesInFlight, limit: limit)
        }
    }
}

// MARK: - SCTPWireError unwrapping

extension SCTPWireError {
    /// Rethrows the *wrapped* error mapped onto the historical ``SCTPError``.
    ///
    /// Usage at a boundary that calls a typed-throws core method:
    /// ```swift
    /// do { return try coreCall() } catch { try error.rethrowUnwrapped() }
    /// ```
    /// In the bare `catch`, `error` has static type `SCTPWireError` (the core's
    /// typed throw), so this avoids the generic-helper / `catch as` forms that
    /// miscompile with typed throws on this toolchain.
    ///
    /// Typed-throws `SCTPError`: an untyped `throws` erases to `any Error`, which
    /// is rejected under Embedded Swift.
    public func rethrowUnwrapped() throws(SCTPError) -> Never {
        switch self {
        case .bytes:
            // The wrapped `ByteError` is not interpolated: string-interpolating an
            // arbitrary value forces `any Error`/reflection machinery that is
            // unavailable under Embedded Swift. A static message keeps the bridge
            // Embedded-clean while still surfacing a typed `SCTPError`.
            throw SCTPError.invalidFormat("byte error")
        case .decode(let e):
            switch e {
            case .insufficientData(let expected, let actual):
                throw SCTPError.insufficientData(expected: expected, actual: actual)
            case .invalidFormat(let message):
                throw SCTPError.invalidFormat(message)
            case .checksumMismatch(let expected, let actual):
                throw SCTPError.checksumMismatch(expected: expected, actual: actual)
            }
        }
    }
}
