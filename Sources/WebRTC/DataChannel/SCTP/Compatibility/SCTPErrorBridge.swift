/// Embedded-clean error bridging between the `SCTPWireCore` typed throws and the
/// historical ``SCTPError``.
///
/// These two extensions carry NO Foundation / `Data` dependency, so they are
/// shared by both the host adapter and the Embedded-clean ``SCTPAssociationEngine``
/// (which calls `error.asSCTPError` / `error.rethrowUnwrapped()` to surface the
/// historical error type). The `Data`-based bridges live in `SCTPWireCompat.swift`
/// (host-only).


// MARK: - SCTPStateError bridging

extension SCTPStateError {
    /// Maps the Embedded-clean state-machine error onto the historical
    /// ``SCTPError`` so existing call sites (and tests) keep catching `SCTPError`.
    var asSCTPError: SCTPError {
        switch self {
        case .receiveBufferExceeded(let streamID):
            return .receiveBufferExceeded(streamID: streamID)
        case .sendQueueFull(let bytesInFlight, let limit):
            return .sendQueueFull(bytesInFlight: bytesInFlight, limit: limit)
        case .sendChunkLimitReached(let retainedChunkCount, let limit):
            return .sendChunkLimitReached(
                retainedChunkCount: retainedChunkCount,
                limit: limit
            )
        case .sendWindowUnavailable(let requiredByteCount, let availableByteCount):
            return .sendWindowUnavailable(
                requiredByteCount: requiredByteCount,
                availableByteCount: availableByteCount
            )
        }
    }
}

// MARK: - SCTPWireError unwrapping

extension SCTPWireError {
    /// Maps a wire-codec failure onto the historical association error type.
    var asSCTPError: SCTPError {
        switch self {
        case .bytes:
            return .invalidFormat("byte error")
        case .decode(let error):
            switch error {
            case .insufficientData(let expected, let actual):
                return .insufficientData(expected: expected, actual: actual)
            case .invalidFormat(let message):
                return .invalidFormat(message)
            case .checksumMismatch(let expected, let actual):
                return .checksumMismatch(expected: expected, actual: actual)
            }
        case .chunkValueTooLarge(let actual, let maximum):
            return .chunkValueTooLarge(actual: actual, maximum: maximum)
        }
    }

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
    func rethrowUnwrapped() throws(SCTPError) -> Never {
        throw asSCTPError
    }
}
