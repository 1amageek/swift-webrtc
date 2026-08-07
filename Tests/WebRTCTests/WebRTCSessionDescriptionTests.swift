import Testing
@testable import WebRTC

@Suite("WebRTC Session Description Tests")
struct WebRTCSessionDescriptionTests {
    @Test("Offer and answer SDP round-trip data-channel signaling")
    func roundTrip() throws {
        let candidate = try WebRTCICECandidate(
            foundation: "1",
            priority: 2_130_706_431,
            address: "192.0.2.10",
            port: 50_000,
            type: .host
        )
        let fingerprint = CertificateFingerprint(
            algorithm: .sha256,
            bytes: (0..<32).map(UInt8.init)
        )
        let offer = try WebRTCSessionDescription(
            type: .offer,
            iceCredentials: ICECredentials(
                localUfrag: "offerUfrag",
                localPassword: "offerPassword0123456789"
            ),
            fingerprint: fingerprint,
            setupRole: .actpass,
            candidates: [candidate]
        )

        let parsed = try WebRTCSessionDescription.parse(offer.sdp, type: .offer)
        #expect(parsed == offer)

        let answer = try WebRTCSessionDescription(
            type: .answer,
            iceCredentials: ICECredentials(
                localUfrag: "answerUfrag",
                localPassword: "answerPassword01234567"
            ),
            fingerprint: fingerprint,
            setupRole: .passive,
            candidates: [candidate]
        )
        #expect(
            try WebRTCSessionDescription.parse(answer.sdp, type: .answer)
                == answer
        )
    }

    @Test("Session-level ICE and DTLS attributes apply to application media")
    func parsesSessionLevelAttributes() throws {
        let fingerprint = CertificateFingerprint(
            algorithm: .sha256,
            bytes: (0..<32).map(UInt8.init)
        )
        let sdp = [
            "v=0",
            "o=- 0 0 IN IP4 0.0.0.0",
            "s=-",
            "t=0 0",
            "a=ice-ufrag:globalUfrag",
            "a=ice-pwd:globalPassword0123456789",
            "a=fingerprint:\(fingerprint.sdpFormat)",
            "a=setup:actpass",
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
            "c=IN IP4 0.0.0.0",
            "a=sctp-port:5000",
        ].joined(separator: "\r\n") + "\r\n"

        let parsed = try WebRTCSessionDescription.parse(sdp, type: .offer)

        #expect(parsed.iceCredentials.localUfrag == "globalUfrag")
        #expect(parsed.setupRole == .actpass)
        #expect(parsed.fingerprint.bytes.count == 32)
    }

    @Test("Browser candidate extensions are accepted without weakening route fields")
    func parsesBrowserCandidateExtensions() throws {
        let candidate = try WebRTCICECandidate.parse(
            "candidate:842163049 1 udp 1677734911 203.0.113.2 54400 "
                + "typ srflx raddr 10.0.0.2 rport 50000 generation 0 network-cost 999"
        )

        #expect(candidate.type == .serverReflexive)
        #expect(candidate.transport == .udp)
        #expect(candidate.relatedAddress == "10.0.0.2")
        #expect(candidate.relatedPort == 50_000)
    }

    @Test("Offer rejects an answer-only DTLS role")
    func offerRejectsPassiveRole() {
        #expect(throws: WebRTCSessionDescriptionError.self) {
            _ = try WebRTCSessionDescription(
                type: .offer,
                iceCredentials: ICECredentials(
                    localUfrag: "ufrag",
                    localPassword: "password"
                ),
                fingerprint: CertificateFingerprint(
                    algorithm: .sha256,
                    bytes: [UInt8](repeating: 0, count: 32)
                ),
                setupRole: .passive
            )
        }
    }

    @Test("Oversized candidate input fails before tokenization")
    func oversizedCandidateFails() {
        let oversized = String(
            repeating: "x",
            count: WebRTCICECandidate.maximumSDPByteCount + 1
        )
        #expect(throws: WebRTCSessionDescriptionError.self) {
            _ = try WebRTCICECandidate.parse(oversized)
        }
    }
}
