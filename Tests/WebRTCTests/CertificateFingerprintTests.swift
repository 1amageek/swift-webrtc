/// Tests for CertificateFingerprint

import Testing
import Foundation
@testable import DTLSCore

@Suite("CertificateFingerprint Tests")
struct CertificateFingerprintTests {

    @Test("fromDigest preserves bytes unchanged")
    func fromDigestPreservesBytes() {
        let digest = Data(repeating: 0xAB, count: 32)
        let fingerprint = CertificateFingerprint.fromDigest(digest)
        #expect(fingerprint.bytes == digest)
        #expect(fingerprint.algorithm == .sha256)
    }

    @Test("fromDigest does not double-hash")
    func fromDigestDoesNotDoubleHash() {
        let digest = Data(repeating: 0xCD, count: 32)

        let fromDigestFP = CertificateFingerprint.fromDigest(digest)
        let fromDERFP = CertificateFingerprint.fromDER(digest)

        // fromDigest keeps bytes as-is; fromDER hashes them
        #expect(fromDigestFP.bytes == digest)
        #expect(fromDERFP.bytes != digest)
        #expect(fromDigestFP != fromDERFP)
    }

    @Test("fromDER hashes input with SHA-256")
    func fromDERHashesInput() {
        let derData = Data(repeating: 0xEF, count: 100)
        let fingerprint = CertificateFingerprint.fromDER(derData)

        // SHA-256 always produces 32 bytes
        #expect(fingerprint.bytes.count == 32)
        // Hash output differs from input
        #expect(fingerprint.bytes != derData)
    }

    @Test("fromDigest equality for same bytes")
    func fromDigestEquality() {
        let digest = Data(repeating: 0x42, count: 32)
        let fp1 = CertificateFingerprint.fromDigest(digest)
        let fp2 = CertificateFingerprint.fromDigest(digest)
        #expect(fp1 == fp2)
        #expect(fp1.hashValue == fp2.hashValue)
    }

    @Test("multihash roundtrip via fromDigest")
    func multihashRoundtrip() {
        let originalDigest = Data(repeating: 0x99, count: 32)
        let fingerprint = CertificateFingerprint.fromDigest(originalDigest)

        let multihash = fingerprint.multihash
        // multihash format: [0x12 (SHA2-256), 0x20 (32 bytes), ...digest]
        #expect(multihash.count == 34)
        #expect(multihash[0] == 0x12)
        #expect(multihash[1] == 0x20)

        // Extract digest from multihash and recreate
        let extractedDigest = Data(multihash[2...])
        let reconstructed = CertificateFingerprint.fromDigest(extractedDigest)
        #expect(reconstructed == fingerprint)
    }
}
