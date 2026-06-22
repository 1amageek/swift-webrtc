/// Foundation `Data` compatibility layer over the Embedded-clean
/// `DataChannelCore`.
///
/// `DataChannelCore` expresses the DCEP wire codec over `[UInt8]`/`P2PCoreBytes`
/// so it can build under Embedded Swift. This adapter restores the historical
/// `Data`-based `encode()`/`decode(from:Data)` surface that `DataChannelManager`,
/// `WebRTC`, and the existing test suite bind to.

import Foundation
@_exported import DataChannelCore

// MARK: - DataChannelWireError unwrapping

extension DataChannelWireError {
    /// Rethrows the *wrapped* error mapped onto the historical
    /// ``DataChannelError``.
    ///
    /// Usage at a `Data`-API boundary that calls a typed-throws core method:
    /// ```swift
    /// do { return try coreCall() } catch { try error.rethrowUnwrapped() }
    /// ```
    /// In the bare `catch`, `error` has static type `DataChannelWireError` (the
    /// core's typed throw), so this avoids the generic-helper / `catch as` forms
    /// that miscompile with typed throws on this toolchain.
    public func rethrowUnwrapped() throws -> Never {
        switch self {
        case .bytes(let e):
            throw DataChannelError.invalidFormat("byte error: \(e)")
        case .decode(let e):
            switch e {
            case .invalidFormat(let message):
                throw DataChannelError.invalidFormat(message)
            }
        }
    }
}

// MARK: - DCEPOpen (Data surface)

extension DCEPOpen {
    /// Encode to wire format as `Data`.
    public func encode() -> Data {
        Data(encodeBytes())
    }

    /// Decode from `Data` wire format.
    public static func decode(from data: Data) throws -> DCEPOpen {
        do {
            return try decode(from: [UInt8](data))
        } catch {
            try error.rethrowUnwrapped()
        }
    }
}

// MARK: - DCEPAck (Data surface)

extension DCEPAck {
    /// Encode to wire format as `Data`.
    public func encode() -> Data {
        Data(encodeBytes())
    }

    /// Decode from `Data` wire format.
    public static func decode(from data: Data) throws -> DCEPAck {
        do {
            return try decode(from: [UInt8](data))
        } catch {
            try error.rethrowUnwrapped()
        }
    }
}
