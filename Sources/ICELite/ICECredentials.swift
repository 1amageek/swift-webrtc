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
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        var result = ""
        var bytes = Data(count: length)
        bytes.withUnsafeMutableBytes { ptr in
            let _ = SecRandomCopyBytes(kSecRandomDefault, length, ptr.baseAddress!)
        }
        for byte in bytes {
            let index = Int(byte) % chars.count
            result.append(chars[chars.index(chars.startIndex, offsetBy: index)])
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
