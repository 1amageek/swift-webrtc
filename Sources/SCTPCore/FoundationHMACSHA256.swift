/// swift-crypto-backed concrete HMAC-SHA256 satisfying the Embedded-clean
/// `MessageAuthenticationCode` seam.
///
/// This is the SCTPCore adapter's lib-internal FoundationProvider for the cookie
/// HMAC: the only place the concrete crypto backend (swift-crypto) is named. The
/// `SCTPWireCore` cookie core depends only on the `MessageAuthenticationCode`
/// protocol; this type plugs the protocol into HMAC-SHA256 at the host boundary.
///
/// Host-only: under Embedded the SCTP adapter routes the COOKIE HMAC through
/// `P2PCryptoEmbedded.BoringHMACSHA256`, so this swift-crypto-backed provider is
/// gated out of the Embedded build.

#if !hasFeature(Embedded)
import Crypto
import P2PCoreCrypto

/// HMAC-SHA256 over swift-crypto, conforming to the Embedded-clean
/// ``P2PCoreCrypto/MessageAuthenticationCode`` seam. The protocol is fully
/// qualified because `Crypto` re-exports a same-named `CryptoKit` protocol.
struct FoundationHMACSHA256: P2PCoreCrypto.MessageAuthenticationCode {
    static var macLength: Int { SHA256.byteCount }

    private var context: HMAC<SHA256>

    init(key: Span<UInt8>) {
        var keyBytes = [UInt8]()
        keyBytes.reserveCapacity(key.count)
        for i in 0..<key.count { keyBytes.append(key[i]) }
        self.context = HMAC<SHA256>(key: SymmetricKey(data: keyBytes))
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
        let mac = HMAC<SHA256>.authenticationCode(for: msgBytes, using: SymmetricKey(data: keyBytes))
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
        return HMAC<SHA256>.isValidAuthenticationCode(
            macBytes,
            authenticating: msgBytes,
            using: SymmetricKey(data: keyBytes)
        )
    }
}

#endif
