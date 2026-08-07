/// ICE Credentials (RFC 8445)
///
/// Local and remote ICE username fragments and passwords.
///
/// Embedded-clean: the random ufrag/password generation uses the `RandomSource`
/// seam (via `STUNCore.SecureRandom`) and `String` building, both available under
/// Embedded. The `stunKey` is exposed as `[UInt8]` (the seam currency); the `Data`
/// convenience is gated host-only.

#if !hasFeature(Embedded) && !os(WASI)
import Foundation
#endif

/// ICE credential pair for connectivity checks
public struct ICECredentials: Sendable, Equatable {
    /// Local username fragment (ufrag)
    public let localUfrag: String

    /// Local password
    public let localPassword: String

    /// Remote username fragment
    public internal(set) var remoteUfrag: String?

    /// Remote password
    public internal(set) var remotePassword: String?

    /// Generates a fresh cryptographically random local credential pair.
    public init() {
        self.localUfrag = Self.generateUfrag()
        self.localPassword = Self.generatePassword()
        self.remoteUfrag = nil
        self.remotePassword = nil
    }

    /// Creates an explicit local and remote ICE credential pair.
    ///
    /// Protocol integrations use this initializer when signaling, or an
    /// implicit-signaling profile, has already established both credential
    /// pairs. Validation is performed when the credentials are installed on a
    /// connection so invalid input is reported as a typed ``WebRTCError``.
    public init(
        localUfrag: String,
        localPassword: String,
        remoteUfrag: String? = nil,
        remotePassword: String? = nil
    ) {
        self.localUfrag = localUfrag
        self.localPassword = localPassword
        self.remoteUfrag = remoteUfrag
        self.remotePassword = remotePassword
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
            let byte = SecureRandom.byte()

            // Rejection sampling: discard biased values
            if byte < threshold {
                let index = Int(byte % charCount)
                result.append(chars[index])
            }
        }

        return result
    }

    /// The username for STUN messages: "remoteUfrag:localUfrag"
    var stunUsername: String? {
        guard let remoteUfrag else { return nil }
        return "\(remoteUfrag):\(localUfrag)"
    }

    /// The STUN key (local password as UTF-8 bytes) — the seam currency.
    var stunKeyBytes: [UInt8] {
        Array(localPassword.utf8)
    }

    #if !hasFeature(Embedded) && !os(WASI)
    /// The STUN key (local password as UTF-8) as `Data`. Host-only convenience.
    var stunKey: Data {
        Data(localPassword.utf8)
    }
    #endif
}
