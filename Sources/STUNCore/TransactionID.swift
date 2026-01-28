/// STUN Transaction ID (RFC 5389)
///
/// 96-bit (12 bytes) random identifier for matching requests/responses.

import Foundation

/// A 96-bit STUN transaction identifier
public struct TransactionID: Sendable, Hashable, Equatable {
    /// The 12-byte transaction ID
    public let bytes: Data

    public init(bytes: Data) {
        precondition(bytes.count == 12, "TransactionID must be 12 bytes")
        self.bytes = bytes
    }

    /// Generate a random transaction ID
    public static func random() -> TransactionID {
        var bytes = Data(count: 12)
        bytes.withUnsafeMutableBytes { ptr in
            let _ = SecRandomCopyBytes(kSecRandomDefault, 12, ptr.baseAddress!)
        }
        return TransactionID(bytes: bytes)
    }
}

extension TransactionID: CustomStringConvertible {
    public var description: String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}
