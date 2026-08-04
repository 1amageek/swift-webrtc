
/// One authenticated, decrypted RTCP datagram and its zero-copy wire layout.
///
/// `bytes` owns the datagram storage. Each packet range in `layout` refers to
/// this owner. Copying the value retains the same copy-on-write byte storage.
public struct WebRTCRTCPPacket: Sendable {
    public let bytes: [UInt8]
    public let layout: RTCPDatagramLayout

    init(bytes: consuming [UInt8], layout: RTCPDatagramLayout) {
        self.bytes = bytes
        self.layout = layout
    }
}
