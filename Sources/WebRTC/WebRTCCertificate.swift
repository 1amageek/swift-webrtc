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

import TLS
#if !hasFeature(Embedded)
import Foundation
import Crypto
@preconcurrency import X509
import SwiftASN1
#else
import P2PCoreBytes
import P2PCoreCrypto
import P2PCryptoBoringSSL
#endif

/// Fingerprint hash algorithm. WebRTC mandates SHA-256 in current deployments.
public enum FingerprintAlgorithm: String, Sendable, Hashable {
    case sha256 = "sha-256"
}

/// A certificate fingerprint used for WebRTC SDP and the libp2p `/certhash`
/// multiaddr component.
///
/// The public surface is `[UInt8]`-based so it is Embedded-clean (Foundation
/// `Data` is unavailable under Embedded). Host-only `Data` convenience overloads
/// (gated `#if !hasFeature(Embedded)`) preserve the historical ergonomics for
/// callers that work in `Data`.
public struct CertificateFingerprint: Sendable, Hashable, Equatable {
    /// The hash algorithm used.
    public let algorithm: FingerprintAlgorithm

    /// The fingerprint bytes (32 bytes for SHA-256).
    public let bytes: [UInt8]

    public init(algorithm: FingerprintAlgorithm, bytes: [UInt8]) {
        self.algorithm = algorithm
        self.bytes = bytes
    }

    /// Compute a fingerprint from a DER-encoded X.509 certificate by hashing it.
    ///
    /// The SHA-256 is routed through a build-gated seam so DTLS-SRTP fingerprint
    /// verification (RFC 8122) is byte-identical and fail-closed on BOTH host and
    /// Embedded: host uses swift-crypto's `SHA256`, Embedded uses the BoringSSL
    /// `BoringSHA256`. There is no platform on which fingerprint computation
    /// silently degrades.
    public static func fromDER(_ data: [UInt8]) -> CertificateFingerprint {
        #if !hasFeature(Embedded)
        let hash = SHA256.hash(data: data)
        return CertificateFingerprint(algorithm: .sha256, bytes: [UInt8](hash))
        #else
        let hash = BoringSHA256.hash(data.span)
        return CertificateFingerprint(algorithm: .sha256, bytes: [UInt8](hash))
        #endif
    }

    /// Create from an existing SHA-256 digest (e.g. extracted from a multihash
    /// `/certhash`). Unlike `fromDER`, this does NOT hash again, so it never
    /// produces a hash-of-hash.
    public static func fromDigest(_ digest: [UInt8]) -> CertificateFingerprint {
        CertificateFingerprint(algorithm: .sha256, bytes: digest)
    }

    /// Multihash-encoded fingerprint (0x12 = SHA2-256, 0x20 = 32-byte length).
    public var multihash: [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(2 + bytes.count)
        result.append(0x12)
        result.append(0x20)
        result.append(contentsOf: bytes)
        return result
    }

    /// Multibase base64url encoding (prefix `u`).
    ///
    /// Uses an Embedded-clean base64url encoder (no Foundation), so the encoding
    /// is byte-identical on host and Embedded.
    public var multibaseEncoded: String {
        "u" + Self.base64URLEncode(multihash)
    }

    /// SDP fingerprint format: `sha-256 AB:CD:EF:...`.
    public var sdpFormat: String {
        var hexParts: [String] = []
        hexParts.reserveCapacity(bytes.count)
        for byte in bytes {
            hexParts.append(Self.hexUppercase(byte))
        }
        return "\(algorithm.rawValue) \(hexParts.joined(separator: ":"))"
    }

    // MARK: - Embedded-clean encoders

    /// Base64url (RFC 4648 §5) without padding, no Foundation.
    private static func base64URLEncode(_ input: [UInt8]) -> String {
        let alphabet: [Character] = [
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
            "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
            "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "-", "_",
        ]
        var output = String()
        output.reserveCapacity((input.count + 2) / 3 * 4)
        var index = 0
        let count = input.count
        while index + 3 <= count {
            let b0 = UInt32(input[index])
            let b1 = UInt32(input[index + 1])
            let b2 = UInt32(input[index + 2])
            let triple = (b0 << 16) | (b1 << 8) | b2
            output.append(alphabet[Int((triple >> 18) & 0x3F)])
            output.append(alphabet[Int((triple >> 12) & 0x3F)])
            output.append(alphabet[Int((triple >> 6) & 0x3F)])
            output.append(alphabet[Int(triple & 0x3F)])
            index += 3
        }
        let remaining = count - index
        if remaining == 1 {
            let b0 = UInt32(input[index])
            let triple = b0 << 16
            output.append(alphabet[Int((triple >> 18) & 0x3F)])
            output.append(alphabet[Int((triple >> 12) & 0x3F)])
        } else if remaining == 2 {
            let b0 = UInt32(input[index])
            let b1 = UInt32(input[index + 1])
            let triple = (b0 << 16) | (b1 << 8)
            output.append(alphabet[Int((triple >> 18) & 0x3F)])
            output.append(alphabet[Int((triple >> 12) & 0x3F)])
            output.append(alphabet[Int((triple >> 6) & 0x3F)])
        }
        return output
    }

    /// Two-character uppercase hex of a byte, no Foundation (`String(format:)`).
    private static func hexUppercase(_ byte: UInt8) -> String {
        let digits: [Character] = [
            "0", "1", "2", "3", "4", "5", "6", "7",
            "8", "9", "A", "B", "C", "D", "E", "F",
        ]
        var s = String()
        s.append(digits[Int(byte >> 4)])
        s.append(digits[Int(byte & 0x0F)])
        return s
    }

    #if !hasFeature(Embedded)
    /// Host-only `Data` convenience initializer.
    public init(algorithm: FingerprintAlgorithm, bytes: Data) {
        self.init(algorithm: algorithm, bytes: [UInt8](bytes))
    }

    /// Host-only `Data` convenience: compute a fingerprint from a DER-encoded
    /// X.509 certificate. Wraps the `[UInt8]` core.
    public static func fromDER(_ data: Data) -> CertificateFingerprint {
        fromDER([UInt8](data))
    }

    /// Host-only `Data` convenience: wrap an existing SHA-256 digest without
    /// re-hashing. Wraps the `[UInt8]` core.
    public static func fromDigest(_ digest: Data) -> CertificateFingerprint {
        fromDigest([UInt8](digest))
    }
    #endif
}

/// A WebRTC DTLS certificate: an ECDSA P-256 leaf certificate, its private key,
/// and the SHA-256 fingerprint of the DER encoding.
///
/// ## Host vs Embedded
///
/// On host, the certificate can be self-signed locally (`generateSelfSigned`)
/// using swift-certificates / swift-asn1, and the typed `privateKey`
/// (`P256.Signing.PrivateKey`) is exposed for callers that want it. Under
/// Embedded, X.509 generation is unavailable: the embedder MUST supply the DER
/// certificate and the raw P-256 private-key scalar externally via
/// `init(derEncoded:rawPrivateKey:)`. There is no silent fallback — neither build
/// fabricates an identity it was not given. The DTLS facade is fed the raw key
/// scalar + DER chain via `tlsIdentity` identically on both builds.
public struct WebRTCCertificate: Sendable {
    /// The DER-encoded X.509 leaf certificate.
    public let derEncoded: [UInt8]

    /// The raw ECDSA P-256 private-key scalar (32 bytes). This is the canonical
    /// key representation fed to the DTLS facade's `TLSIdentity` on both builds.
    public let rawPrivateKey: [UInt8]

    /// SHA-256 fingerprint of `derEncoded`.
    public let fingerprint: CertificateFingerprint

    #if !hasFeature(Embedded)
    /// The ECDSA P-256 signing private key (host-only typed view).
    public let privateKey: P256.Signing.PrivateKey

    /// Wrap an externally-generated DER certificate and its typed private key.
    public init(derEncoded: [UInt8], privateKey: P256.Signing.PrivateKey) throws {
        // Validate the DER parses as an X.509 certificate (fail-closed on garbage).
        _ = try X509.Certificate(derEncoded: derEncoded)
        self.derEncoded = derEncoded
        self.privateKey = privateKey
        self.rawPrivateKey = [UInt8](privateKey.rawRepresentation)
        self.fingerprint = CertificateFingerprint.fromDER(derEncoded)
    }

    /// Host-only `Data` convenience: wrap a DER certificate and typed private key.
    public init(derEncoded: Data, privateKey: P256.Signing.PrivateKey) throws {
        try self.init(derEncoded: [UInt8](derEncoded), privateKey: privateKey)
    }

    /// Generate a self-signed ECDSA P-256 certificate (WebRTC convention).
    ///
    /// Host-only: self-signed X.509 generation needs swift-certificates /
    /// swift-asn1, which are unavailable under Embedded. Under Embedded use
    /// `init(derEncoded:rawPrivateKey:)` with an externally-provisioned identity.
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

        return try WebRTCCertificate(
            derEncoded: serializer.serializedBytes,
            privateKey: privateKey
        )
    }
    #endif

    /// Wrap an externally-provisioned DER certificate and raw P-256 key scalar.
    ///
    /// This is the Embedded provisioning path (and is also available on host): the
    /// embedder supplies the DER leaf and the 32-byte private-key scalar directly.
    /// The fingerprint is computed fail-closed from the DER. No certificate or key
    /// is fabricated — if the embedder has no identity, none is created.
    ///
    /// On host this validates the DER and recovers the typed key, so it `throws`
    /// (preserving the historical untyped-throws host API). Under Embedded there is
    /// no X.509 / typed-key validation available to fail (and untyped `throws` is
    /// rejected by Embedded Swift), so the Embedded variant is non-throwing — it
    /// simply records the provisioned bytes and computes the fingerprint.
    #if !hasFeature(Embedded)
    public init(derEncoded: [UInt8], rawPrivateKey: [UInt8]) throws {
        // On host, validate the DER parses as an X.509 certificate and recover the
        // typed key (fail-closed on garbage DER or a malformed key scalar).
        _ = try X509.Certificate(derEncoded: derEncoded)
        self.privateKey = try P256.Signing.PrivateKey(rawRepresentation: rawPrivateKey)
        self.derEncoded = derEncoded
        self.rawPrivateKey = rawPrivateKey
        self.fingerprint = CertificateFingerprint.fromDER(derEncoded)
    }
    #else
    public init(derEncoded: [UInt8], rawPrivateKey: [UInt8]) {
        self.derEncoded = derEncoded
        self.rawPrivateKey = rawPrivateKey
        self.fingerprint = CertificateFingerprint.fromDER(derEncoded)
    }
    #endif

    #if !hasFeature(Embedded)
    /// Host-only `Data` convenience: wrap a DER certificate and raw P-256 key
    /// scalar. Wraps the `[UInt8]` provisioning initializer.
    public init(derEncoded: Data, rawPrivateKey: [UInt8]) throws {
        try self.init(derEncoded: [UInt8](derEncoded), rawPrivateKey: rawPrivateKey)
    }
    #endif

    /// Build the swift-tls `TLSIdentity` the DTLS facade requires (raw P-256
    /// private-key scalar + DER leaf certificate).
    public var tlsIdentity: TLS.TLSIdentity {
        TLS.TLSIdentity(
            privateKey: rawPrivateKey,
            keyType: .ecdsaP256,
            certificateChain: [TLS.Certificate(der: derEncoded)]
        )
    }
}
