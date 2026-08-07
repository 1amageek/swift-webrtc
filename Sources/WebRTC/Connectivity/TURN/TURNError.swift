public enum TURNError: Error, Sendable, Equatable {
    case invalidCredential
    case invalidAddressLength(Int)
    case invalidPort
    case malformedMessage
    case transactionMismatch
    case unexpectedMessageType(UInt16)
    case missingAuthenticationChallenge
    case duplicateAttribute(UInt16)
    case authenticationFailed
    case staleNonce
    case serverError(code: UInt16, reason: String)
    case missingRelayedAddress
    case missingLifetime
    case missingPeerAddress
    case missingData
    case payloadTooLarge(Int)
}
