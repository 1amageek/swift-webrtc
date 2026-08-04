/// Negotiation policy for an authenticated RTP/RTCP media path.
public struct WebRTCMediaConfiguration: Sendable, Equatable {
    /// The SRTP profile that DTLS must negotiate.
    public let protectionProfile: WebRTCMediaProtectionProfile

    /// RTP payload types negotiated by the signaling layer.
    ///
    /// Values 64...95 are rejected because the RTP marker bit would make their
    /// second octet collide with the RTCP packet-type range under RFC 5761 mux.
    public let rtpPayloadTypes: [UInt8]

    /// Whether RFC 5506 reduced-size RTCP packets may be accepted after SRTP
    /// authentication. Compound RTCP remains the default policy.
    public let allowsReducedSizeRTCP: Bool

    public init(
        protectionProfile: WebRTCMediaProtectionProfile = .aes128CMHMACSHA180,
        rtpPayloadTypes: [UInt8],
        allowsReducedSizeRTCP: Bool = false
    ) throws(WebRTCMediaConfigurationError) {
        guard !rtpPayloadTypes.isEmpty else {
            throw .emptyRTPPayloadTypes
        }

        for index in rtpPayloadTypes.indices {
            let payloadType = rtpPayloadTypes[index]
            guard !(64...95).contains(payloadType) else {
                throw .rtpRTCPMuxConflict(payloadType)
            }
            guard !rtpPayloadTypes[..<index].contains(payloadType) else {
                throw .duplicateRTPPayloadType(payloadType)
            }
        }

        self.protectionProfile = protectionProfile
        self.rtpPayloadTypes = rtpPayloadTypes
        self.allowsReducedSizeRTCP = allowsReducedSizeRTCP
    }
}
