import P2PCoreBytes

/// Materializes a validated packetization layout into caller-owned storage.
public protocol H264RTPPayloadEncoding: Sendable {
    /// Appends directly to `destination`. Callers should reserve RTP header,
    /// payload, and SRTP tailroom in that same owner before calling this API.
    func appendPayload(
        _ layout: H264RTPPacketizationLayout,
        from accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>,
        to destination: inout [UInt8]
    ) throws(H264RTPPayloadError)
}
