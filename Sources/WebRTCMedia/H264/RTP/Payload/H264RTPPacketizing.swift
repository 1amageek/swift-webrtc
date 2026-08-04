import P2PCoreBytes

/// Produces RFC 6184 packet layouts without taking ownership of media bytes.
public protocol H264RTPPacketizing: Sendable {
    /// Validates the complete access unit, then synchronously emits range-only
    /// layouts. The callback does not escape and no payload-sized container is
    /// created by this operation.
    func forEachPacket(
        in accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>,
        mode: H264PacketizationMode,
        maximumPayloadByteCount: Int,
        _ body: (H264RTPPacketizationLayout) -> Void
    ) throws(H264RTPPayloadError)

    /// Validates the complete access unit, then visits range-only layouts until
    /// the body requests a stop. No payload-sized container is materialized.
    func traversePackets(
        in accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>,
        mode: H264PacketizationMode,
        maximumPayloadByteCount: Int,
        _ body: (H264RTPPacketizationLayout) -> H264RTPPacketTraversalDecision
    ) throws(H264RTPPayloadError) -> H264RTPPacketTraversalOutcome
}
