/// STUN Transaction ID (RFC 5389)
///
/// 96-bit (12 bytes) random identifier for matching requests/responses.

/// A 96-bit STUN transaction identifier.
///
/// The Embedded-clean core stores the identifier as `[UInt8]`. The `STUNCore`
/// adapter adds the `Data`-based init/property and the crypto-backed
/// `random()` factory.
public struct TransactionID: Sendable, Hashable, Equatable {
    /// The 12-byte transaction ID
    public let byteValues: [UInt8]

    public init(byteValues: [UInt8]) {
        precondition(byteValues.count == 12, "TransactionID must be 12 bytes")
        self.byteValues = byteValues
    }
}

extension TransactionID: CustomStringConvertible {
    public var description: String {
        var s = ""
        for byte in byteValues {
            let hi = byte >> 4
            let lo = byte & 0x0F
            s.append(Self.hexDigit(hi))
            s.append(Self.hexDigit(lo))
        }
        return s
    }

    private static func hexDigit(_ nibble: UInt8) -> Character {
        if nibble < 10 {
            return Character(Unicode.Scalar(0x30 + nibble))
        } else {
            return Character(Unicode.Scalar(0x61 + (nibble - 10)))
        }
    }
}
