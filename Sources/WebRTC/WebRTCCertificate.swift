/// WebRTC DTLS-SRTP certificate and fingerprint.
///
/// WebRTC peer authentication binds the DTLS leaf certificate to a SHA-256
/// fingerprint advertised out of band (SDP `a=fingerprint` / libp2p `/certhash`
/// multiaddr). This type owns the self-signed ECDSA P-256 certificate generation
/// and fingerprint computation locally so the WebRTC layer can drive the swift-tls
/// Tier-1 `DTLSClient`/`DTLSServer` facade (which takes a `TLSIdentity`) while
/// keeping the fingerprint as the unit of peer identity.
///
/// The self-signed generation mirrors the WebRTC convention: a v3 ECDSA-P256
/// certificate, `digitalSignature` key usage, not a CA, valid for one year.

import Foundation
import Crypto
import TLS
@preconcurrency import X509
import SwiftASN1

/// Fingerprint hash algorithm. WebRTC mandates SHA-256 in current deployments.
public enum FingerprintAlgorithm: String, Sendable, Hashable {
    case sha256 = "sha-256"
}

/// A certificate fingerprint used for WebRTC SDP and the libp2p `/certhash`
/// multiaddr component.
public struct CertificateFingerprint: Sendable, Hashable, Equatable {
    /// The hash algorithm used.
    public let algorithm: FingerprintAlgorithm

    /// The fingerprint bytes (32 bytes for SHA-256).
    public let bytes: Data

    public init(algorithm: FingerprintAlgorithm, bytes: Data) {
        self.algorithm = algorithm
        self.bytes = bytes
    }

    /// Compute a fingerprint from a DER-encoded X.509 certificate by hashing it.
    public static func fromDER(_ data: Data) -> CertificateFingerprint {
        let hash = SHA256.hash(data: data)
        return CertificateFingerprint(algorithm: .sha256, bytes: Data(hash))
    }

    /// Create from an existing SHA-256 digest (e.g. extracted from a multihash
    /// `/certhash`). Unlike `fromDER`, this does NOT hash again, so it never
    /// produces a hash-of-hash.
    public static func fromDigest(_ digest: Data) -> CertificateFingerprint {
        CertificateFingerprint(algorithm: .sha256, bytes: digest)
    }

    /// Multihash-encoded fingerprint (0x12 = SHA2-256, 0x20 = 32-byte length).
    public var multihash: Data {
        var result = Data(capacity: 2 + bytes.count)
        result.append(0x12)
        result.append(0x20)
        result.append(bytes)
        return result
    }

    /// Multibase base64url encoding (prefix `u`).
    public var multibaseEncoded: String {
        let base64url = multihash.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "u" + base64url
    }

    /// SDP fingerprint format: `sha-256 AB:CD:EF:...`.
    public var sdpFormat: String {
        let hexParts = bytes.map { String(format: "%02X", $0) }
        return "\(algorithm.rawValue) \(hexParts.joined(separator: ":"))"
    }
}

/// A WebRTC DTLS certificate: an ECDSA P-256 leaf certificate, its private key,
/// and the SHA-256 fingerprint of the DER encoding.
public struct WebRTCCertificate: Sendable {
    /// The DER-encoded X.509 leaf certificate.
    public let derEncoded: Data

    /// The ECDSA P-256 signing private key.
    public let privateKey: P256.Signing.PrivateKey

    /// SHA-256 fingerprint of `derEncoded`.
    public let fingerprint: CertificateFingerprint

    /// Wrap an externally-generated DER certificate and its private key.
    public init(derEncoded: Data, privateKey: P256.Signing.PrivateKey) throws {
        // Validate the DER parses as an X.509 certificate (fail-closed on garbage).
        _ = try X509.Certificate(derEncoded: Array(derEncoded))
        self.derEncoded = derEncoded
        self.privateKey = privateKey
        self.fingerprint = CertificateFingerprint.fromDER(derEncoded)
    }

    /// Generate a self-signed ECDSA P-256 certificate (WebRTC convention).
    public static func generateSelfSigned(commonName: String = "webrtc") throws -> WebRTCCertificate {
        let privateKey = P256.Signing.PrivateKey()

        let subject = try DistinguishedName {
            CommonName(commonName)
        }

        let now = Date()
        let certificate = try X509.Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: .init(privateKey.publicKey),
            notValidBefore: now,
            notValidAfter: now.addingTimeInterval(365 * 24 * 60 * 60),
            issuer: subject,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
            },
            issuerPrivateKey: .init(privateKey)
        )

        var serializer = DER.Serializer()
        try certificate.serialize(into: &serializer)
        let derData = Data(serializer.serializedBytes)

        return try WebRTCCertificate(derEncoded: derData, privateKey: privateKey)
    }

    /// Build the swift-tls `TLSIdentity` the DTLS facade requires (raw P-256
    /// private-key scalar + DER leaf certificate).
    public var tlsIdentity: TLS.TLSIdentity {
        TLS.TLSIdentity(
            privateKey: [UInt8](privateKey.rawRepresentation),
            keyType: .ecdsaP256,
            certificateChain: [TLS.Certificate(der: [UInt8](derEncoded))]
        )
    }
}
