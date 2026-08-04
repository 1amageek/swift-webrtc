import P2PCoreCrypto

/// Immutable operations required by the RFC 3711 AES-CM/HMAC-SHA1 profile.
///
/// Platform composition resolves a concrete crypto backend once and injects
/// these non-generic operations into SRTPCore. This keeps associated-type
/// metadata and provider selection outside the per-packet runtime path.
///
/// `authenticateSHA1` receives the caller's complete packet owner plus the
/// exact authenticated range. It must update one incremental HMAC directly
/// from that range, then from `suffix` when present, without materializing a
/// packet-sized copy or retaining any argument beyond the synchronous call.
final class SRTPCryptoContext: Sendable {
    typealias MakeAES128CounterModeOperation = @Sendable (
        _ key: [UInt8]
    ) throws(AESCounterModeError) -> SRTPAES128CounterModeContext

    typealias AuthenticateSHA1Operation = @Sendable (
        _ message: [UInt8],
        _ authenticatedRange: Range<Int>,
        _ suffix: [UInt8]?,
        _ key: [UInt8]
    ) -> [UInt8]

    package let hmacSHA1ByteCount: Int
    private let makeAES128CounterModeOperation: MakeAES128CounterModeOperation
    private let authenticateSHA1Operation: AuthenticateSHA1Operation

    init(
        hmacSHA1ByteCount: Int,
        makeAES128CounterMode: @escaping MakeAES128CounterModeOperation,
        authenticateSHA1: @escaping AuthenticateSHA1Operation
    ) {
        self.hmacSHA1ByteCount = hmacSHA1ByteCount
        self.makeAES128CounterModeOperation = makeAES128CounterMode
        self.authenticateSHA1Operation = authenticateSHA1
    }

    package func makeAES128CounterMode(
        key: [UInt8]
    ) throws(AESCounterModeError) -> SRTPAES128CounterModeContext {
        try makeAES128CounterModeOperation(key)
    }

    package func authenticationCodeSHA1(
        message: [UInt8],
        authenticatedRange: Range<Int>,
        suffix: [UInt8]?,
        key: [UInt8]
    ) -> [UInt8] {
        authenticateSHA1Operation(message, authenticatedRange, suffix, key)
    }
}
