/// Foundation `Data` compatibility layer over the Embedded-clean `STUNWireCore`.
///
/// `STUNWireCore` expresses the STUN wire codec over `[UInt8]`/`P2PCoreBytes` so
/// it can build under Embedded Swift. This adapter restores the historical
/// `Data`-based public surface that the rest of `swift-webrtc` (ICE, WebRTC) and
/// the existing test suite bind to. It is pure bridging plus the crypto-bearing
/// helpers (`encodeWithIntegrity`) that must stay Foundation/Crypto side.
///
/// Host-only: the `Data`-based bridges below are gated out of the Embedded build.
/// The Embedded-clean `STUNError` + `STUNWireError.rethrowUnwrapped` (used by the
/// Embedded path too) live in `STUNErrorBridge.swift` (no Foundation).

#if !hasFeature(Embedded) && !os(WASI)
import Foundation

// MARK: - Byte-array <-> Data equality bridges

// The wire types store byte fields as `[UInt8]`. These overloads let existing
// call sites (and tests) compare those fields directly to `Data` values.

func == (lhs: [UInt8], rhs: Data) -> Bool { lhs.elementsEqual(rhs) }
func == (lhs: Data, rhs: [UInt8]) -> Bool { rhs.elementsEqual(lhs) }
func != (lhs: [UInt8], rhs: Data) -> Bool { !(lhs == rhs) }
func != (lhs: Data, rhs: [UInt8]) -> Bool { !(lhs == rhs) }

// MARK: - String(data:encoding:) bridge for [UInt8] value fields

extension String {
    /// Decode a `[UInt8]` value field with the given encoding.
    ///
    /// Mirrors `String(data:encoding:)` for STUN attribute values, which the
    /// Embedded-clean core stores as `[UInt8]`.
    init?(data bytes: [UInt8], encoding: String.Encoding) {
        self.init(data: Data(bytes), encoding: encoding)
    }
}

// MARK: - TransactionID (Data surface + random)

extension TransactionID {
    /// The 12-byte transaction ID as `Data`.
    var bytes: Data { Data(byteValues) }

    /// Create a transaction ID from `Data`.
    init(bytes: Data) {
        self.init(byteValues: [UInt8](bytes))
    }

    /// Generate a random transaction ID.
    static func random() -> TransactionID {
        TransactionID(bytes: SecureRandom.data(count: 12))
    }
}

// MARK: - STUNAttribute (Data surface)

extension STUNAttribute {
    /// The attribute value as `Data`.
    var valueData: Data { Data(value) }

    /// Create an attribute from a `Data` value.
    init(type: UInt16, value: Data) {
        self.init(type: type, value: [UInt8](value))
    }

    /// Create a XOR-MAPPED-ADDRESS attribute from a `Data` address.
    static func xorMappedAddress(
        address: Data,
        port: UInt16,
        transactionID: TransactionID
    ) -> STUNAttribute {
        xorMappedAddress(address: [UInt8](address), port: port, transactionID: transactionID)
    }
}

#endif
