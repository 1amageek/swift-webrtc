/// ICE connectivity-check validation failures (RFC 8445) — Embedded-clean.

/// Errors raised while validating an inbound ICE connectivity check. The
/// `ICELite` adapter maps each case onto a STUN error response.
enum ICEValidationError: Error, Sendable, Equatable {
    case missingUsername
    case invalidUsernameFormat
    case localUfragMismatch
    case remoteUfragMismatch
    case missingMessageIntegrity
    case invalidMessageIntegrity
    case fingerprintVerificationFailed
    case roleConflict
}
