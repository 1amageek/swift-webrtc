import NetworkingCore
import SSLCrypto

private typealias SCTPConcreteCookieMAC = HMACSHA256

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
            var output = [UInt8](
                repeating: 0,
                count: SCTPConcreteCookieMAC.tagByteCount
            )
            do {
                var destination = output.mutableSpan
                try SCTPConcreteCookieMAC.authenticate(
                    message.span,
                    using: key.span,
                    into: &destination
                )
            } catch {
                preconditionFailure(
                    "Validated SCTP cookie input exceeded the primitive contract"
                )
            }
            return output
        },
        isValid: { @Sendable (
            authenticationCode: [UInt8],
            message: [UInt8],
            key: [UInt8]
        ) -> Bool in
            do {
                return try SCTPConcreteCookieMAC.isValidAuthenticationCode(
                    authenticationCode.span,
                    authenticating: message.span,
                    using: key.span
                )
            } catch {
                return false
            }
        }
    )
}
