/// Foundation `Data` compatibility layer over the Embedded-clean
/// `DataChannelCore`.
///
/// `DataChannelCore` expresses the DCEP wire codec over `[UInt8]`/`P2PCoreBytes`
/// so it can build under Embedded Swift. This adapter restores the historical
/// `Data`-based `encode()`/`decode(from:Data)` surface that `DataChannelManager`,
/// `WebRTC`, and the existing test suite bind to.
///
/// Host-only: the `Data` surface below is gated out of the Embedded build, which
/// uses the `[UInt8]` core primitives directly. The Embedded-clean error bridge
/// (`DataChannelWireError.rethrowUnwrapped`) lives in `DCEPErrorBridge.swift`.

#if !hasFeature(Embedded)
import Foundation
@_exported import DataChannelCore

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

#endif
