/// ICE Credentials (RFC 8445)
///
/// Local and remote ICE username fragments and passwords.

import Foundation

/// ICE credential pair for connectivity checks
public struct ICECredentials: Sendable, Equatable {
    /// Local username fragment (ufrag)
    public let localUfrag: String

    /// Local password
    public let localPassword: String

    /// Remote username fragment
    public var remoteUfrag: String?

    /// Remote password
    public var remotePassword: String?

    public init(
        localUfrag: String? = nil,
        localPassword: String? = nil
    ) {
        self.localUfrag = localUfrag ?? Self.generateUfrag()
        self.localPassword = localPassword ?? Self.generatePassword()
    }

    /// Generate a random ufrag (4+ characters, ICE spec)
    private static func generateUfrag() -> String {
        randomAlphanumeric(length: 8)
    }

    /// Generate a random password (22+ characters, ICE spec)
    private static func generatePassword() -> String {
        randomAlphanumeric(length: 24)
    }

    private static func randomAlphanumeric(length: Int) -> String {
        let chars = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        let charCount = UInt8(chars.count) // 62

        // Use rejection sampling to avoid modulo bias
        // Reject values >= 248 (248 = 62 * 4, largest multiple of 62 <= 256)
        let threshold: UInt8 = 248

        var result = ""
        result.reserveCapacity(length)

        while result.count < length {
            var byte: UInt8 = 0
            withUnsafeMutableBytes(of: &byte) { ptr in
                _ = SecRandomCopyBytes(kSecRandomDefault, 1, ptr.baseAddress!)
            }

            // Rejection sampling: discard biased values
            if byte < threshold {
                let index = Int(byte % charCount)
                result.append(chars[index])
            }
        }

        return result
    }

    /// The username for STUN messages: "remoteUfrag:localUfrag"
    public var stunUsername: String? {
        guard let remoteUfrag else { return nil }
        return "\(remoteUfrag):\(localUfrag)"
    }

    /// The STUN key (local password as UTF-8)
    public var stunKey: Data {
        Data(localPassword.utf8)
    }
}
