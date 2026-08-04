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
import P2PCoreBytes
import P2PCoreCrypto
import P2PCrypto
import P2PCoreDER
#if canImport(Foundation)
import Foundation
#endif
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(WASILibc)
import WASILibc
#endif

/// Supplies Unix wall-clock seconds for certificate validity windows.
///
/// Certificate generation is a provisioning operation, not a packet-path
/// operation. The clock is therefore injectable so Embedded deployments can
/// provide their board or RTC implementation without making the protocol
/// facade depend on a platform-specific time API.
public protocol WebRTCCertificateClock: Sendable {
    func nowUnixSeconds() -> Int64?
}

/// The system wall clock when the target provides a C time service.
///
/// Targets without a wall-clock implementation return `nil`; callers then get
/// the typed `.clockUnavailable` failure instead of a certificate with a fake
/// validity interval. Embedded applications can pass their own clock to
/// `generateSelfSigned(clock:)`.
public struct SystemWebRTCCertificateClock: WebRTCCertificateClock {
    public init() {}

    public func nowUnixSeconds() -> Int64? {
        #if canImport(Darwin) || canImport(Glibc) || canImport(Musl) || canImport(WASILibc)
        return Int64(time(nil))
        #else
        return nil
        #endif
    }
}

/// Fingerprint hash algorithm. WebRTC mandates SHA-256 in current deployments.
public enum FingerprintAlgorithm: String, Sendable, Hashable {
    case sha256 = "sha-256"
}

/// A certificate fingerprint used for WebRTC SDP and the libp2p `/certhash`
/// multiaddr component.
///
/// The public surface is `[UInt8]`-based so it is Embedded-clean (Foundation
/// `Data` is unavailable under Embedded). Non-Embedded `Data` convenience
/// overloads preserve the historical ergonomics for callers that work in
/// `Data`.
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
    /// verification (RFC 8122) is byte-identical and fail-closed on every
    /// supported platform through `P2PCrypto.DefaultSHA256`. There is no
    /// platform on which fingerprint computation silently degrades.
    public static func fromDER(_ data: [UInt8]) -> CertificateFingerprint {
        let hash = DefaultSHA256.hash(data.span)
        return CertificateFingerprint(algorithm: .sha256, bytes: [UInt8](hash))
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

    #if canImport(Foundation)
    /// Foundation `Data` convenience initializer.
    public init(algorithm: FingerprintAlgorithm, bytes: Data) {
        self.init(algorithm: algorithm, bytes: [UInt8](bytes))
    }

    /// Non-Embedded `Data` convenience: compute a fingerprint from a DER-encoded
    /// X.509 certificate. Wraps the `[UInt8]` core.
    public static func fromDER(_ data: Data) -> CertificateFingerprint {
        fromDER([UInt8](data))
    }

    /// Non-Embedded `Data` convenience: wrap an existing SHA-256 digest without
    /// re-hashing. Wraps the `[UInt8]` core.
    public static func fromDigest(_ digest: Data) -> CertificateFingerprint {
        fromDigest([UInt8](digest))
    }
    #endif
}

/// A WebRTC DTLS certificate: an ECDSA P-256 leaf certificate, its private key,
/// and the SHA-256 fingerprint of the DER encoding.
///
/// ## Locally generated vs externally provisioned identity
///
    /// On every supported target, the certificate can be self-signed locally
    /// (`generateSelfSigned`) using the shared Pure Swift DER and P-256 backend. The
    /// same constructor and key representation are used on Native, WASI, and
/// Embedded; there is no host-only certificate generator or silent fallback.
/// The DTLS facade is fed the raw key scalar + DER chain via `tlsIdentity` on
/// every build.
public struct WebRTCCertificate: Sendable {
    /// The DER-encoded X.509 leaf certificate.
    public let derEncoded: [UInt8]

    /// The raw ECDSA P-256 private-key scalar (32 bytes). This is the canonical
    /// key representation fed to the DTLS facade's `TLSIdentity` on both builds.
    public let rawPrivateKey: [UInt8]

    /// SHA-256 fingerprint of `derEncoded`.
    public let fingerprint: CertificateFingerprint

    /// Generate a self-signed ECDSA P-256 certificate (WebRTC convention).
    /// The certificate builder is Pure Swift and is available on every target.
    public static func generateSelfSigned<Clock: WebRTCCertificateClock>(
        clock: Clock = SystemWebRTCCertificateClock()
    ) throws(WebRTCCertificateError) -> WebRTCCertificate {
        guard let now = clock.nowUnixSeconds() else {
            throw .clockUnavailable
        }
        let signingKey: DefaultCryptoProvider.P256Signature.SigningKey
        do {
            signingKey = try DefaultCryptoProvider.P256Signature.generateSigningKey()
        } catch {
            throw .generationFailed
        }
        let publicPoint = DefaultCryptoProvider.P256Signature.rawRepresentation(
            of: DefaultCryptoProvider.P256Signature.verifyingKey(for: signingKey)
        )
        let spki: [UInt8]
        do {
            spki = try SubjectPublicKeyInfoDER.encodeP256(uncompressedPoint65: publicPoint)
        } catch {
            throw .generationFailed
        }
        let serial = DefaultCryptoProvider.random.randomBytes(16).map { $0 & 0x7F }
        let certificate: [UInt8]
        do {
            certificate = try Self.buildSelfSignedCertificate(
                spki: spki,
                serial: serial,
                notBefore: now - 60,
                notAfter: now + 365 * 24 * 60 * 60,
                signingKey: signingKey
            )
        } catch {
            throw .generationFailed
        }
        return try self.init(
            derEncoded: certificate,
            rawPrivateKey: DefaultCryptoProvider.P256Signature.rawRepresentation(of: signingKey)
        )
    }

    /// Wrap an externally-provisioned DER certificate and raw P-256 key scalar.
    ///
    /// This is the WASI / Embedded provisioning path (and is also available on
    /// Native platforms): the embedder supplies the DER leaf and the 32-byte
    /// private-key scalar directly. The fingerprint is computed from the DER. No
    /// certificate or key is fabricated — if the embedder has no identity, none
    /// is created.
    ///
    /// On every platform this validates the X.509 envelope, extracts its
    /// SubjectPublicKeyInfo, imports both keys, and proves that the private scalar
    /// matches the certificate public key before accepting the credential.
    public init(
        derEncoded: [UInt8],
        rawPrivateKey: [UInt8]
    ) throws(WebRTCCertificateError) {
        let parsed: SubjectPublicKeyInfoDER.Parsed
        do {
            parsed = try X509CertificateDER.subjectPublicKeyInfo(in: derEncoded)
        } catch {
            throw .malformedCredential
        }
        guard parsed.curve == .p256 else {
            throw .malformedCredential
        }

        let signingKey: DefaultCryptoProvider.P256Signature.SigningKey
        let verifyingKey: DefaultCryptoProvider.P256Signature.VerifyingKey
        do {
            signingKey = try DefaultCryptoProvider.P256Signature.signingKey(
                rawRepresentation: rawPrivateKey.span
            )
            verifyingKey = try DefaultCryptoProvider.P256Signature.verifyingKey(
                rawRepresentation: parsed.keyBytes.span
            )
        } catch {
            throw .malformedPrivateKey
        }

        // A signature round trip proves both that the scalar is usable and that
        // it corresponds to the SPKI without calling a derivation API that may
        // assume an already-validated scalar. This one-time construction cost is
        // outside the packet path.
        let challenge: [UInt8] = [
            0x57, 0x65, 0x62, 0x52, 0x54, 0x43, 0x20, 0x69,
            0x64, 0x65, 0x6E, 0x74, 0x69, 0x74, 0x79,
        ]
        let signature: [UInt8]
        do {
            signature = try DefaultCryptoProvider.P256Signature.sign(
                challenge.span,
                with: signingKey
            )
        } catch {
            throw .malformedPrivateKey
        }
        guard DefaultCryptoProvider.P256Signature.isValid(
            signature: signature.span,
            for: challenge.span,
            with: verifyingKey
        ) else {
            throw .credentialKeyMismatch
        }

        self.derEncoded = derEncoded
        self.rawPrivateKey = rawPrivateKey
        self.fingerprint = CertificateFingerprint.fromDER(derEncoded)
    }

    private static func buildSelfSignedCertificate(
        spki: [UInt8],
        serial: [UInt8],
        notBefore: Int64,
        notAfter: Int64,
        signingKey: DefaultCryptoProvider.P256Signature.SigningKey
    ) throws(CryptoError) -> [UInt8] {
        let signatureAlgorithm = DERWriter.sequence([DERWriter.encodeOID(.ecdsaSHA256)])
        let version = DERWriter.encode(.context0, DERWriter.encodeInteger([0x02]))
        let basicConstraintsOID = DERWriter.encodeOID(ObjectID([0x55, 0x1D, 0x13]))
        let keyUsageOID = DERWriter.encodeOID(ObjectID([0x55, 0x1D, 0x0F]))
        let basicConstraints = DERWriter.sequence([
            basicConstraintsOID,
            DERWriter.encodeBoolean(true),
            DERWriter.encodeOctetString(DERWriter.sequence([])),
        ])
        let digitalSignature = DERWriter.encode(.bitString, [0x07, 0x80])
        let keyUsage = DERWriter.sequence([
            keyUsageOID,
            DERWriter.encodeBoolean(true),
            DERWriter.encodeOctetString(digitalSignature),
        ])
        let extensions = DERWriter.encode(
            .context3,
            DERWriter.sequence([basicConstraints, keyUsage])
        )
        let validity = DERWriter.sequence([
            Self.utcTime(notBefore),
            Self.utcTime(notAfter),
        ])
        let tbs = DERWriter.sequence([
            version,
            DERWriter.encodeInteger(serial),
            signatureAlgorithm,
            DERWriter.sequence([]),
            validity,
            DERWriter.sequence([]),
            spki,
            extensions,
        ])
        let signature = try DefaultCryptoProvider.P256Signature.sign(tbs.span, with: signingKey)
        return DERWriter.sequence([
            tbs,
            signatureAlgorithm,
            DERWriter.encodeBitString(signature),
        ])
    }

    private static func utcTime(_ epochSeconds: Int64) -> [UInt8] {
        // DERTime is intentionally internal to the shared codec; this fixed
        // Gregorian conversion keeps certificate creation target-independent.
        let days = epochSeconds / 86_400
        let seconds = epochSeconds % 86_400
        let civil = Self.civilDate(daysSince1970: days)
        let hour = seconds / 3_600
        let minute = (seconds % 3_600) / 60
        let second = seconds % 60
        var content: [UInt8] = []
        content.reserveCapacity(13)
        Self.appendTwoDigits(civil.year % 100, to: &content)
        Self.appendTwoDigits(civil.month, to: &content)
        Self.appendTwoDigits(civil.day, to: &content)
        Self.appendTwoDigits(hour, to: &content)
        Self.appendTwoDigits(minute, to: &content)
        Self.appendTwoDigits(second, to: &content)
        content.append(contentsOf: [0x5A])
        return DERWriter.encode(.utcTime, content)
    }

    private static func appendTwoDigits(_ value: Int64, to output: inout [UInt8]) {
        let clamped = value < 0 ? 0 : value % 100
        output.append(UInt8(0x30 + (clamped / 10)))
        output.append(UInt8(0x30 + (clamped % 10)))
    }

    private static func civilDate(daysSince1970: Int64) -> (year: Int64, month: Int64, day: Int64) {
        let z = daysSince1970 + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365
        let year = yoe + era * 400
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let day = doy - (153 * mp + 2) / 5 + 1
        let month = mp + (mp < 10 ? 3 : -9)
        return (year + (month <= 2 ? 1 : 0), month, day)
    }

    #if canImport(Foundation)
    /// Foundation `Data` convenience for an externally provisioned identity.
    public init(
        derEncoded: Data,
        rawPrivateKey: [UInt8]
    ) throws(WebRTCCertificateError) {
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
