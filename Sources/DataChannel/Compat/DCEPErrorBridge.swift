/// Embedded-clean error bridging from the `DataChannelCore` typed throws to the
/// historical ``DataChannelError``.
///
/// Carries NO Foundation / `Data` dependency, so it is shared by both the host
/// adapter and the Embedded path (`DataChannelManager` surfaces `DataChannelError`
/// from the `[UInt8]` DCEP decode). The `Data`-based bridges live in
/// `DCEPDataCompat.swift` (host-only).

@_exported import DataChannelCore

extension DataChannelWireError {
    /// Rethrows the *wrapped* error mapped onto the historical
    /// ``DataChannelError``.
    ///
    /// In the bare `catch`, `error` has static type `DataChannelWireError` (the
    /// core's typed throw), so this avoids the generic-helper / `catch as` forms
    /// that miscompile with typed throws on this toolchain. Typed-throws
    /// `DataChannelError` keeps the Embedded build clean (an untyped `throws`
    /// erases to `any Error`).
    public func rethrowUnwrapped() throws(DataChannelError) -> Never {
        switch self {
        case .bytes:
            // The wrapped `ByteError` is not interpolated: string-interpolating an
            // arbitrary value forces machinery unavailable under Embedded Swift.
            throw DataChannelError.invalidFormat("byte error")
        case .decode(let e):
            switch e {
            case .invalidFormat(let message):
                throw DataChannelError.invalidFormat(message)
            }
        }
    }
}
