@testable import WebRTC

enum WebRTCTestIdentityError: Error {
    case identityRejected
}

private struct WebRTCTestCertificateClock: WebRTCCertificateClock {
    let seconds: Int64

    func nowUnixSeconds() -> Int64? { seconds }
}

/// Cross-platform identity fixture using the same Pure Swift production path.
/// Re-importing the result also exercises externally provisioned credentials.
enum WebRTCTestIdentity {
    enum Fixture: Sendable {
        case primary
        case secondary
    }

    static func make(
        _ fixture: Fixture = .primary
    ) throws(WebRTCTestIdentityError) -> WebRTCCertificate {
        let seconds: Int64
        switch fixture {
        case .primary:
            seconds = 1_750_000_000
        case .secondary:
            seconds = 1_750_000_001
        }
        do {
            let generated = try WebRTCCertificate.generateSelfSigned(
                clock: WebRTCTestCertificateClock(seconds: seconds)
            )
            return try WebRTCCertificate(
                derEncoded: generated.derEncoded,
                rawPrivateKey: generated.rawPrivateKey
            )
        } catch {
            throw .identityRejected
        }
    }

    static func endpoint() throws(WebRTCTestIdentityError) -> WebRTCEndpoint {
        WebRTCEndpoint(certificate: try make())
    }
}
