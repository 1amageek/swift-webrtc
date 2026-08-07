/// A data-channel-only WebRTC SDP offer or answer.
public struct WebRTCSessionDescription: Sendable, Equatable {
    public static let maximumSDPByteCount = 64 * 1_024
    public static let defaultSCTPPort: UInt16 = 5_000
    public static let defaultMaximumMessageSize: UInt64 = 16_384

    public let type: WebRTCSessionDescriptionType
    public let iceCredentials: ICECredentials
    public let fingerprint: CertificateFingerprint
    public let setupRole: WebRTCDTLSSetupRole
    public let candidates: [WebRTCICECandidate]
    public let sctpPort: UInt16
    public let maximumMessageSize: UInt64

    public init(
        type: WebRTCSessionDescriptionType,
        iceCredentials: ICECredentials,
        fingerprint: CertificateFingerprint,
        setupRole: WebRTCDTLSSetupRole,
        candidates: [WebRTCICECandidate] = [],
        sctpPort: UInt16 = defaultSCTPPort,
        maximumMessageSize: UInt64 = defaultMaximumMessageSize
    ) throws(WebRTCSessionDescriptionError) {
        guard !iceCredentials.localUfrag.isEmpty else {
            throw .missingICEUsernameFragment
        }
        guard !iceCredentials.localPassword.isEmpty else {
            throw .missingICEPassword
        }
        guard sctpPort > 0 else {
            throw .invalidSCTPPort(String(sctpPort))
        }
        guard maximumMessageSize > 0 else {
            throw .invalidMaximumMessageSize(String(maximumMessageSize))
        }
        switch type {
        case .offer:
            guard setupRole == .actpass else {
                throw .invalidDTLSSetupRole(setupRole.rawValue)
            }
        case .answer:
            guard setupRole == .active || setupRole == .passive else {
                throw .invalidDTLSSetupRole(setupRole.rawValue)
            }
        }
        self.type = type
        self.iceCredentials = iceCredentials
        self.fingerprint = fingerprint
        self.setupRole = setupRole
        self.candidates = candidates
        self.sctpPort = sctpPort
        self.maximumMessageSize = maximumMessageSize
    }

    /// Serializes the canonical data-channel SDP using CRLF line endings.
    public var sdp: String {
        var lines = [
            "v=0",
            "o=- 0 0 IN IP4 0.0.0.0",
            "s=-",
            "t=0 0",
            "a=group:BUNDLE 0",
            "a=ice-options:trickle",
            "a=msid-semantic: WMS",
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
            "c=IN IP4 0.0.0.0",
            "a=mid:0",
            "a=ice-ufrag:\(iceCredentials.localUfrag)",
            "a=ice-pwd:\(iceCredentials.localPassword)",
            "a=fingerprint:\(fingerprint.sdpFormat)",
            "a=setup:\(setupRole.rawValue)",
            "a=sctp-port:\(sctpPort)",
            "a=max-message-size:\(maximumMessageSize)",
        ]
        lines.reserveCapacity(lines.count + candidates.count + 1)
        for candidate in candidates {
            lines.append("a=\(candidate.sdpAttribute)")
        }
        return lines.joined(separator: "\r\n") + "\r\n"
    }

    public static func parse(
        _ sdp: String,
        type: WebRTCSessionDescriptionType
    ) throws(WebRTCSessionDescriptionError) -> WebRTCSessionDescription {
        guard sdp.utf8.count <= maximumSDPByteCount else {
            throw .inputTooLarge(size: sdp.utf8.count, maximum: maximumSDPByteCount)
        }

        var hasSeenMedia = false
        var hasApplicationMedia = false
        var inApplicationMedia = false
        var iceUfrag: String?
        var icePassword: String?
        var fingerprint: CertificateFingerprint?
        var setupRole: WebRTCDTLSSetupRole?
        var candidates: [WebRTCICECandidate] = []
        var sctpPort = defaultSCTPPort
        var maximumMessageSize = defaultMaximumMessageSize

        // Split the UTF-8 view instead of Character. Swift treats CRLF as one
        // grapheme cluster, so Character-based splitting would not recognize
        // either delimiter in canonical SDP.
        for bytes in sdp.utf8.split(whereSeparator: { $0 == 0x0D || $0 == 0x0A }) {
            let line = String(decoding: bytes, as: UTF8.self)
            guard !line.contains("\0") else {
                throw .malformedLine(line)
            }
            if line.hasPrefix("m=") {
                hasSeenMedia = true
                inApplicationMedia = line.hasPrefix("m=application ")
                hasApplicationMedia = hasApplicationMedia || inApplicationMedia
                continue
            }
            // Session-level attributes are inherited by every media section.
            // Once media sections begin, only the application section may
            // contribute signaling attributes to this data-channel model.
            guard !hasSeenMedia || inApplicationMedia || !line.hasPrefix("a=") else {
                continue
            }

            if line.hasPrefix("a=ice-ufrag:") {
                iceUfrag = String(line.dropFirst("a=ice-ufrag:".count))
            } else if line.hasPrefix("a=ice-pwd:") {
                icePassword = String(line.dropFirst("a=ice-pwd:".count))
            } else if line.hasPrefix("a=fingerprint:") {
                fingerprint = try parseFingerprint(
                    String(line.dropFirst("a=fingerprint:".count))
                )
            } else if line.hasPrefix("a=setup:") {
                let value = String(line.dropFirst("a=setup:".count))
                guard let parsed = WebRTCDTLSSetupRole(rawValue: value) else {
                    throw .invalidDTLSSetupRole(value)
                }
                setupRole = parsed
            } else if line.hasPrefix("a=candidate:") {
                candidates.append(try WebRTCICECandidate.parse(line))
            } else if line.hasPrefix("a=sctp-port:") {
                let value = String(line.dropFirst("a=sctp-port:".count))
                guard let parsed = UInt16(value), parsed > 0 else {
                    throw .invalidSCTPPort(value)
                }
                sctpPort = parsed
            } else if line.hasPrefix("a=max-message-size:") {
                let value = String(line.dropFirst("a=max-message-size:".count))
                guard let parsed = UInt64(value), parsed > 0 else {
                    throw .invalidMaximumMessageSize(value)
                }
                maximumMessageSize = parsed
            }
        }

        guard hasApplicationMedia else { throw .unsupportedMedia }
        guard let iceUfrag, !iceUfrag.isEmpty else {
            throw .missingICEUsernameFragment
        }
        guard let icePassword, !icePassword.isEmpty else {
            throw .missingICEPassword
        }
        guard let fingerprint else { throw .missingFingerprint }
        guard let setupRole else { throw .missingDTLSSetupRole }

        return try WebRTCSessionDescription(
            type: type,
            iceCredentials: ICECredentials(
                localUfrag: iceUfrag,
                localPassword: icePassword
            ),
            fingerprint: fingerprint,
            setupRole: setupRole,
            candidates: candidates,
            sctpPort: sctpPort,
            maximumMessageSize: maximumMessageSize
        )
    }

    private static func parseFingerprint(
        _ value: String
    ) throws(WebRTCSessionDescriptionError) -> CertificateFingerprint {
        let fields = value.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard fields.count == 2,
              fields[0].lowercased() == FingerprintAlgorithm.sha256.rawValue else {
            throw .invalidFingerprint
        }
        let components = fields[1].split(separator: ":", omittingEmptySubsequences: false)
        guard components.count == 32 else { throw .invalidFingerprint }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(32)
        for component in components {
            guard component.count == 2,
                  let byte = UInt8(component, radix: 16) else {
                throw .invalidFingerprint
            }
            bytes.append(byte)
        }
        return CertificateFingerprint(algorithm: .sha256, bytes: bytes)
    }
}
