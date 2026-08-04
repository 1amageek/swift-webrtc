
/// One authenticated, decrypted RTP packet and its zero-copy wire layout.
///
/// `bytes` owns the datagram storage. `layout` contains only scalar metadata and
/// ranges into that exact owner. Copying this value uses `Array` copy-on-write;
/// media bytes are not duplicated unless a copy is subsequently mutated.
public struct WebRTCRTPPacket: Sendable {
    public let bytes: [UInt8]
    public let layout: RTPPacketLayout

    /// A zero-copy view over the media payload bytes.
    public var payload: ArraySlice<UInt8> {
        bytes[layout.payloadRange]
    }

    init(bytes: consuming [UInt8], layout: RTPPacketLayout) {
        self.bytes = bytes
        self.layout = layout
    }
}
