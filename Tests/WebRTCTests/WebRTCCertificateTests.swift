import Testing
import P2PCoreDER
@testable import WebRTC

private struct FixedCertificateClock: WebRTCCertificateClock {
    let seconds: Int64

    func nowUnixSeconds() -> Int64? { seconds }
}

private struct UnavailableCertificateClock: WebRTCCertificateClock {
    func nowUnixSeconds() -> Int64? { nil }
}

@Suite("WebRTC certificate validation")
struct WebRTCCertificateTests {
    @Test("Pure Swift self-signed certificate round-trips through the DER boundary")
    func generatedIdentityRoundTrips() throws {
        let generated = try WebRTCCertificate.generateSelfSigned(
            clock: FixedCertificateClock(seconds: 1_750_000_000)
        )
        let parsed = try X509CertificateDER.subjectPublicKeyInfo(
            in: generated.derEncoded
        )
        #expect(parsed.curve == .p256)
        #expect(parsed.keyBytes.count == 65)

        let provisioned = try WebRTCCertificate(
            derEncoded: generated.derEncoded,
            rawPrivateKey: generated.rawPrivateKey
        )
        #expect(provisioned.fingerprint == generated.fingerprint)
    }

    @Test("Certificate generation reports an unavailable wall clock")
    func unavailableClockFailsClosed() {
        #expect(throws: WebRTCCertificateError.clockUnavailable) {
            try WebRTCCertificate.generateSelfSigned(
                clock: UnavailableCertificateClock()
            )
        }
    }

    @Test("Provisioned X.509 identity accepts its matching P-256 key")
    func acceptsMatchingIdentity() throws {
        let generated = try WebRTCTestIdentity.make()
        let provisioned = try WebRTCCertificate(
            derEncoded: generated.derEncoded,
            rawPrivateKey: generated.rawPrivateKey
        )

        #expect(provisioned.derEncoded == generated.derEncoded)
        #expect(provisioned.rawPrivateKey == generated.rawPrivateKey)
        #expect(provisioned.fingerprint == generated.fingerprint)
    }

    @Test("Malformed certificate DER is rejected at construction")
    func rejectsMalformedCredential() throws {
        let generated = try WebRTCTestIdentity.make()

        #expect(throws: WebRTCCertificateError.malformedCredential) {
            try WebRTCCertificate(
                derEncoded: [0x30, 0x00],
                rawPrivateKey: generated.rawPrivateKey
            )
        }
    }

    @Test("Malformed private key is rejected at construction")
    func rejectsMalformedPrivateKey() throws {
        let generated = try WebRTCTestIdentity.make()

        #expect(throws: WebRTCCertificateError.malformedPrivateKey) {
            try WebRTCCertificate(
                derEncoded: generated.derEncoded,
                rawPrivateKey: [0x01]
            )
        }
    }

    @Test("A valid certificate paired with another valid key is rejected")
    func rejectsCredentialKeyMismatch() throws {
        let certificateOwner = try WebRTCTestIdentity.make()
        let otherKeyOwner = try WebRTCTestIdentity.make(.secondary)

        #expect(throws: WebRTCCertificateError.credentialKeyMismatch) {
            try WebRTCCertificate(
                derEncoded: certificateOwner.derEncoded,
                rawPrivateKey: otherKeyOwner.rawPrivateKey
            )
        }
    }
}
