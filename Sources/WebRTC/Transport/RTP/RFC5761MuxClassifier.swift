/// RFC 5761 RTP/RTCP mux classification and payload-type policy.
struct RFC5761MuxClassifier: RTPRTCPClassifying, Sendable {
    init() {}

    func classify(_ packet: Span<UInt8>) throws(RTPWireError) -> RTPRTCPPacketKind {
        guard packet.count >= 2 else {
            throw .insufficientBytes(field: .rtpFixedHeader, required: 2, available: packet.count)
        }

        let version = packet[0] >> 6
        guard version == 2 else {
            throw .invalidVersion(actual: version)
        }

        return (192...223).contains(packet[1]) ? .rtcp : .rtp
    }

    func validateNegotiatedRTPPayloadType(
        _ payloadType: UInt8
    ) throws(RTPMuxConfigurationError) {
        guard payloadType <= 127 else {
            throw .payloadTypeOutOfRange(payloadType)
        }
        guard !(64...95).contains(payloadType) else {
            throw .payloadTypeConflictsWithRTCP(payloadType)
        }
    }
}
