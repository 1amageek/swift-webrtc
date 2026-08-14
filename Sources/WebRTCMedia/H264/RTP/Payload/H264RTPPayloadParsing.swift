import NetworkingCore

/// Parses RFC 6184 payload structure without retaining or copying media bytes.
public protocol H264RTPPayloadParsing: Sendable {
    func layout(
        in payload: Span<UInt8>,
        mode: H264PacketizationMode
    ) throws(H264RTPPayloadError) -> H264RTPPayloadLayout
}
