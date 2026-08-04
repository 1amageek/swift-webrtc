/// Bounded metadata describing every RTCP packet in one owner datagram.
///
/// This value retains only scalar metadata and ranges. It does not retain the
/// datagram parsed by ``RTCPDatagramParsing/layout(in:framing:limits:)``. The
/// caller owns that datagram for the complete lifetime of every borrowed view
/// extracted from ``packetLayouts``.
public struct RTCPDatagramLayout: Sendable, Equatable {
    public let framing: RTCPFraming
    public let packetLayouts: [RTCPPacketLayout]
    public let byteCount: Int

    init(
        framing: RTCPFraming,
        packetLayouts: [RTCPPacketLayout],
        byteCount: Int
    ) {
        self.framing = framing
        self.packetLayouts = packetLayouts
        self.byteCount = byteCount
    }
}
