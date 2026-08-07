import Testing
@testable import WebRTC

@Suite("WebRTC Trickle ICE Candidate Tests")
struct WebRTCTrickleICECandidateTests {
    @Test("Pion candidate JSON round-trips")
    func roundTrip() throws {
        let candidate = try WebRTCICECandidate(
            foundation: "842163049",
            priority: 1_677_734_911,
            address: "203.0.113.2",
            port: 54_400,
            type: .serverReflexive,
            relatedAddress: "10.0.0.2",
            relatedPort: 50_000
        )
        let value = try WebRTCTrickleICECandidate(
            candidate: candidate,
            usernameFragment: "ufrag"
        )

        let decoded = try WebRTCTrickleICECandidate.parse(value.jsonString)

        #expect(decoded == value)
    }

    @Test("Nullable browser fields and unknown nested values are accepted")
    func nullableFields() throws {
        let decoded = try WebRTCTrickleICECandidate.parse(
            "{\"candidate\":\"candidate:1 1 UDP 1 127.0.0.1 5000 typ host\","
                + "\"sdpMid\":null,\"sdpMLineIndex\":null,"
                + "\"usernameFragment\":null,\"future\":{\"enabled\":true}}"
        )

        #expect(decoded.mediaStreamIdentification == nil)
        #expect(decoded.mediaLineIndex == nil)
        #expect(decoded.usernameFragment == nil)
    }

    @Test("Unicode escapes are decoded strictly")
    func unicodeEscape() throws {
        let decoded = try WebRTCTrickleICECandidate.parse(
            "{\"candidate\":\"candidate:1 1 UDP 1 127.0.0.1 5000 typ host\","
                + "\"sdpMid\":\"\\u0030\",\"sdpMLineIndex\":0,"
                + "\"usernameFragment\":\"user\"}"
        )

        #expect(decoded.mediaStreamIdentification == "0")
    }

    @Test("Duplicate route fields and oversized input fail")
    func rejectsAmbiguousInput() {
        #expect(throws: WebRTCSessionDescriptionError.self) {
            _ = try WebRTCTrickleICECandidate.parse(
                "{\"candidate\":\"candidate:1 1 UDP 1 127.0.0.1 5000 typ host\","
                    + "\"candidate\":\"candidate:2 1 UDP 1 127.0.0.1 5001 typ host\"}"
            )
        }
        #expect(throws: WebRTCSessionDescriptionError.self) {
            _ = try WebRTCTrickleICECandidate.parse(
                String(
                    repeating: "x",
                    count: WebRTCTrickleICECandidate.maximumJSONByteCount + 1
                )
            )
        }
    }
}
