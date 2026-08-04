import P2PCoreDER
@testable import WebRTC
enum WebRTCTestIdentityError: Error {
    case fixtureEncodingFailed
    case identityRejected
}

/// Cross-platform test identity provisioning.
///
/// Darwin exercises the production self-signing path. Portable targets use two
/// fixed, mathematically valid P-256 key pairs wrapped in a strict X.509 envelope.
/// The fixed certificate signature is only envelope data: WebRTC authentication
/// binds the complete leaf fingerprint and DTLS separately proves possession of
/// the matching private key.
enum WebRTCTestIdentity {
    enum Fixture: Sendable {
        case primary
        case secondary
    }

    static func make(
        _ fixture: Fixture = .primary
    ) throws(WebRTCTestIdentityError) -> WebRTCCertificate {
        #if canImport(Darwin)
        do {
            return try WebRTCCertificate.generateSelfSigned()
        } catch {
            throw .identityRejected
        }
        #else
        switch fixture {
        case .primary:
            return try provisionedIdentity(
                scalarLastByte: 0x01,
                uncompressedPoint: p256Generator
            )
        case .secondary:
            return try provisionedIdentity(
                scalarLastByte: 0x02,
                uncompressedPoint: p256GeneratorTimesTwo
            )
        }
        #endif
    }

    static func endpoint() throws(WebRTCTestIdentityError) -> WebRTCEndpoint {
        WebRTCEndpoint(certificate: try make())
    }

    #if !canImport(Darwin)
    private static func provisionedIdentity(
        scalarLastByte: UInt8,
        uncompressedPoint: [UInt8]
    ) throws(WebRTCTestIdentityError) -> WebRTCCertificate {
        let subjectPublicKeyInfo: [UInt8]
        do {
            subjectPublicKeyInfo = try SubjectPublicKeyInfoDER.encodeP256(
                uncompressedPoint65: uncompressedPoint
            )
        } catch {
            throw .fixtureEncodingFailed
        }

        let certificate = try LibP2PCertificateDER.buildSelfSignedCert(
            spkiDER: subjectPublicKeyInfo,
            signedKeyExtension: [],
            serial16: [UInt8](repeating: scalarLastByte, count: 16),
            notBefore: 1_735_689_600,
            notAfter: 1_830_297_600,
            signFn: { (_: [UInt8]) throws(WebRTCTestIdentityError) -> [UInt8] in
                // Structurally valid ECDSA-Sig-Value. Certificate trust is the
                // negotiated SHA-256 fingerprint, not a CA signature chain.
                [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]
            }
        )

        var rawPrivateKey = [UInt8](repeating: 0, count: 32)
        rawPrivateKey[31] = scalarLastByte
        do {
            return try WebRTCCertificate(
                derEncoded: certificate,
                rawPrivateKey: rawPrivateKey
            )
        } catch {
            throw .identityRejected
        }
    }

    private static let p256Generator: [UInt8] = [
        0x04,
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
        0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
        0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
        0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
        0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
        0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
        0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
    ]

    private static let p256GeneratorTimesTwo: [UInt8] = [
        0x04,
        0x7C, 0xF2, 0x7B, 0x18, 0x8D, 0x03, 0x4F, 0x7E,
        0x8A, 0x52, 0x38, 0x03, 0x04, 0xB5, 0x1A, 0xC3,
        0xC0, 0x89, 0x69, 0xE2, 0x77, 0xF2, 0x1B, 0x35,
        0xA6, 0x0B, 0x48, 0xFC, 0x47, 0x66, 0x99, 0x78,
        0x07, 0x77, 0x55, 0x10, 0xDB, 0x8E, 0xD0, 0x40,
        0x29, 0x3D, 0x9A, 0xC6, 0x9F, 0x74, 0x30, 0xDB,
        0xBA, 0x7D, 0xAD, 0xE6, 0x3C, 0xE9, 0x82, 0x29,
        0x9E, 0x04, 0xB7, 0x9D, 0x22, 0x78, 0x73, 0xD1,
    ]
    #endif
}
