/// Decodes RTP wire structure without taking ownership of packet bytes.
package protocol RTPPacketParsing: Sendable {
    /// Returns scalar fields and ranges into `packet` without copying payload bytes.
    func layout(in packet: Span<UInt8>) throws(RTPWireError) -> RTPPacketLayout
}
