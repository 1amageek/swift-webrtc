/// A zero-copy description of one packet inside an RTCP datagram.
///
/// The ranges identify bytes in the exact datagram passed to
/// ``RTCPDatagramParsing/layout(in:framing:limits:)``. They do not retain that
/// owner. The caller must keep the original datagram alive and must not apply
/// these ranges to a different byte owner when extracting a borrowed `Span`.
public struct RTCPPacketLayout: Sendable, Equatable {
    public let commonHeader: RTCPCommonHeader
    public let packetRange: Range<Int>
    public let bodyRange: Range<Int>
    public let paddingRange: Range<Int>?

    init(
        commonHeader: RTCPCommonHeader,
        packetRange: Range<Int>,
        bodyRange: Range<Int>,
        paddingRange: Range<Int>?
    ) {
        self.commonHeader = commonHeader
        self.packetRange = packetRange
        self.bodyRange = bodyRange
        self.paddingRange = paddingRange
    }
}
