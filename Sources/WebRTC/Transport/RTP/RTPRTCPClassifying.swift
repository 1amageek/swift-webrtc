/// Classifies RTP and RTCP sharing one transport port under RFC 5761.
protocol RTPRTCPClassifying: Sendable {
    func classify(_ packet: Span<UInt8>) throws(RTPWireError) -> RTPRTCPPacketKind

    /// Validates a negotiated RTP payload type before an RTP/RTCP-mux session starts.
    func validateNegotiatedRTPPayloadType(
        _ payloadType: UInt8
    ) throws(RTPMuxConfigurationError)
}
