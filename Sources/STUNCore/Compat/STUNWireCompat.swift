/// Foundation `Data` compatibility layer over the Embedded-clean `STUNWireCore`.
///
/// `STUNWireCore` expresses the STUN wire codec over `[UInt8]`/`P2PCoreBytes` so
/// it can build under Embedded Swift. This adapter restores the historical
/// `Data`-based public surface that the rest of `swift-webrtc` (ICE, WebRTC) and
/// the existing test suite bind to. It is pure bridging plus the crypto-bearing
/// helpers (`encodeWithIntegrity`) that must stay Foundation/Crypto side.

import Foundation
@_exported import STUNWireCore

// MARK: - STUNError (adapter-owned, historical concrete error)

/// STUN errors (historical concrete type).
///
/// The Embedded-clean core throws ``STUNWireError``; the adapter unwraps it back
/// to this type at the `Data`-based boundary so callers (and the existing test
/// suite) continue to catch `STUNError` directly.
public enum STUNError: Error, Sendable {
    case insufficientData(expected: Int, actual: Int)
    case invalidFormat(String)
    case invalidMagicCookie(UInt32)
    case integrityCheckFailed
    case fingerprintCheckFailed
}

// MARK: - STUNWireError unwrapping

extension STUNWireError {
    /// Rethrows the *wrapped* error mapped onto the historical ``STUNError``.
    ///
    /// Usage at a `Data`-API boundary that calls a typed-throws core method:
    /// ```swift
    /// do { return try coreCall() } catch { try error.rethrowUnwrapped() }
    /// ```
    /// In the bare `catch`, `error` has static type `STUNWireError` (the core's
    /// typed throw), so this avoids the generic-helper / `catch as` forms that
    /// miscompile with typed throws on this toolchain.
    public func rethrowUnwrapped() throws -> Never {
        switch self {
        case .bytes(let e):
            throw STUNError.invalidFormat("byte error: \(e)")
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

// MARK: - Byte-array <-> Data equality bridges

// The wire types store byte fields as `[UInt8]`. These overloads let existing
// call sites (and tests) compare those fields directly to `Data` values.

public func == (lhs: [UInt8], rhs: Data) -> Bool { lhs == [UInt8](rhs) }
public func == (lhs: Data, rhs: [UInt8]) -> Bool { [UInt8](lhs) == rhs }
public func != (lhs: [UInt8], rhs: Data) -> Bool { !(lhs == rhs) }
public func != (lhs: Data, rhs: [UInt8]) -> Bool { !(lhs == rhs) }

// MARK: - String(data:encoding:) bridge for [UInt8] value fields

extension String {
    /// Decode a `[UInt8]` value field with the given encoding.
    ///
    /// Mirrors `String(data:encoding:)` for STUN attribute values, which the
    /// Embedded-clean core stores as `[UInt8]`.
    public init?(data bytes: [UInt8], encoding: String.Encoding) {
        self.init(data: Data(bytes), encoding: encoding)
    }
}

// MARK: - TransactionID (Data surface + random)

extension TransactionID {
    /// The 12-byte transaction ID as `Data`.
    public var bytes: Data { Data(byteValues) }

    /// Create a transaction ID from `Data`.
    public init(bytes: Data) {
        self.init(byteValues: [UInt8](bytes))
    }

    /// Generate a random transaction ID.
    public static func random() -> TransactionID {
        TransactionID(bytes: SecureRandom.data(count: 12))
    }
}

// MARK: - STUNAttribute (Data surface)

extension STUNAttribute {
    /// The attribute value as `Data`.
    public var valueData: Data { Data(value) }

    /// Create an attribute from a `Data` value.
    public init(type: UInt16, value: Data) {
        self.init(type: type, value: [UInt8](value))
    }

    /// Create a XOR-MAPPED-ADDRESS attribute from a `Data` address.
    public static func xorMappedAddress(
        address: Data,
        port: UInt16,
        transactionID: TransactionID
    ) -> STUNAttribute {
        xorMappedAddress(address: [UInt8](address), port: port, transactionID: transactionID)
    }
}
