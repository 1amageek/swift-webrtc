/// Immutable HMAC operations used to bind an SCTP state cookie.
///
/// The SCTP composition layer captures one concrete HMAC-SHA256 backend in
/// these synchronous operations. Message, MAC, and key arrays use copy-on-write
/// storage and are borrowed for the duration of a call; implementations must
/// not retain them. The validation operation must compare in constant time.
final class SCTPCookieCryptoContext: Sendable {
    typealias AuthenticationCodeOperation = @Sendable (
        _ message: [UInt8],
        _ key: [UInt8]
    ) -> [UInt8]

    typealias ValidationOperation = @Sendable (
        _ authenticationCode: [UInt8],
        _ message: [UInt8],
        _ key: [UInt8]
    ) -> Bool

    private let authenticationCodeOperation: AuthenticationCodeOperation
    private let validationOperation: ValidationOperation

    init(
        authenticationCode: @escaping AuthenticationCodeOperation,
        isValid: @escaping ValidationOperation
    ) {
        self.authenticationCodeOperation = authenticationCode
        self.validationOperation = isValid
    }

    package func authenticationCode(
        for message: [UInt8],
        key: [UInt8]
    ) -> [UInt8] {
        authenticationCodeOperation(message, key)
    }

    package func isValid(
        _ authenticationCode: [UInt8],
        for message: [UInt8],
        key: [UInt8]
    ) -> Bool {
        validationOperation(authenticationCode, message, key)
    }
}
