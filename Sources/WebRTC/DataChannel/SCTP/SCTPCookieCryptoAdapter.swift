import P2PCoreBytes
import P2PCoreCrypto
import P2PCrypto

private typealias SCTPConcreteCookieMAC = DefaultHMACSHA256

/// Resolves the package's default cookie HMAC once at the SCTP composition boundary.
///
/// The returned immutable owner is retained by the association engine. Each
/// operation borrows its fixed-size cookie input and secret synchronously and
/// delegates constant-time verification to the concrete provider.
func makeSCTPCookieCryptoContext() -> SCTPCookieCryptoContext {
    SCTPCookieCryptoContext(
        authenticationCode: { @Sendable (
            message: [UInt8],
            key: [UInt8]
        ) -> [UInt8] in
            SCTPConcreteCookieMAC.authenticationCode(
                for: message.span,
                key: key.span
            )
        },
        isValid: { @Sendable (
            authenticationCode: [UInt8],
            message: [UInt8],
            key: [UInt8]
        ) -> Bool in
            SCTPConcreteCookieMAC.isValid(
                authenticationCode.span,
                for: message.span,
                key: key.span
            )
        }
    )
}
