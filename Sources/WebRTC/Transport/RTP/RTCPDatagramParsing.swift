/// Decodes RTCP framing without taking ownership of packet bytes.
protocol RTCPDatagramParsing: Sendable {
    func layout(
        in datagram: Span<UInt8>,
        framing: RTCPFraming,
        limits: RTCPParseLimits
    ) throws(RTPWireError) -> RTCPDatagramLayout
}
