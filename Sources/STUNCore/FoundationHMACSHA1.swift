/// swift-crypto-backed concrete HMAC-SHA1 satisfying the Embedded-clean
/// `MessageAuthenticationCode` seam.
///
/// This is the STUNCore adapter's lib-internal FoundationProvider for the STUN
/// MESSAGE-INTEGRITY HMAC: the only place the concrete crypto backend
/// (swift-crypto's `Insecure.SHA1`) is named for STUN. The `STUNWireCore`
/// integrity core depends only on the `MessageAuthenticationCode` protocol; this
/// type plugs it into HMAC-SHA1 at the host boundary.
///
/// Host-only: under Embedded the STUN adapter routes MESSAGE-INTEGRITY through
/// `P2PCryptoBoringSSL.BoringHMACSHA1`, so this swift-crypto-backed provider is
/// gated out of the Embedded build.

#if !hasFeature(Embedded)
import Crypto
import P2PCoreCrypto

/// HMAC-SHA1 over swift-crypto, conforming to the Embedded-clean
/// ``P2PCoreCrypto/MessageAuthenticationCode`` seam. The protocol is fully
/// qualified because `Crypto` re-exports a same-named `CryptoKit` protocol.
struct FoundationHMACSHA1: P2PCoreCrypto.MessageAuthenticationCode {
    static var macLength: Int { Insecure.SHA1.byteCount }

    private var context: HMAC<Insecure.SHA1>

    init(key: Span<UInt8>) {
        var keyBytes = [UInt8]()
        keyBytes.reserveCapacity(key.count)
        for i in 0..<key.count { keyBytes.append(key[i]) }
        self.context = HMAC<Insecure.SHA1>(key: SymmetricKey(data: keyBytes))
    }

    mutating func update(_ data: Span<UInt8>) {
        var bytes = [UInt8]()
        bytes.reserveCapacity(data.count)
        for i in 0..<data.count { bytes.append(data[i]) }
        context.update(data: bytes)
    }

    consuming func finalize() -> [UInt8] {
        Array(context.finalize())
    }

    static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        var keyBytes = [UInt8]()
        keyBytes.reserveCapacity(key.count)
        for i in 0..<key.count { keyBytes.append(key[i]) }
        var msgBytes = [UInt8]()
        msgBytes.reserveCapacity(message.count)
        for i in 0..<message.count { msgBytes.append(message[i]) }
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: msgBytes, using: SymmetricKey(data: keyBytes))
        return Array(mac)
    }

    static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        var keyBytes = [UInt8]()
        keyBytes.reserveCapacity(key.count)
        for i in 0..<key.count { keyBytes.append(key[i]) }
        var msgBytes = [UInt8]()
        msgBytes.reserveCapacity(message.count)
        for i in 0..<message.count { msgBytes.append(message[i]) }
        var macBytes = [UInt8]()
        macBytes.reserveCapacity(mac.count)
        for i in 0..<mac.count { macBytes.append(mac[i]) }
        // swift-crypto's isValidAuthenticationCode is constant-time.
        return HMAC<Insecure.SHA1>.isValidAuthenticationCode(
            macBytes,
            authenticating: msgBytes,
            using: SymmetricKey(data: keyBytes)
        )
    }
}

#endif
