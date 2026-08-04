/// A zero-copy description of one RTP packet.
///
/// The ranges borrow bytes from the datagram parsed by ``RTPPacketParsing``.
/// The caller must retain that owner while extracting any `Span` from a range.
public struct RTPPacketLayout: Sendable, Equatable {
    public let packetLength: Int
    public let fixedHeader: RTPFixedHeader
    public let contributingSourcesRange: Range<Int>
    public let headerExtension: RTPHeaderExtensionLayout?
    public let payloadRange: Range<Int>
    public let paddingRange: Range<Int>?

    init(
        packetLength: Int,
        fixedHeader: RTPFixedHeader,
        contributingSourcesRange: Range<Int>,
        headerExtension: RTPHeaderExtensionLayout?,
        payloadRange: Range<Int>,
        paddingRange: Range<Int>?
    ) {
        self.packetLength = packetLength
        self.fixedHeader = fixedHeader
        self.contributingSourcesRange = contributingSourcesRange
        self.headerExtension = headerExtension
        self.payloadRange = payloadRange
        self.paddingRange = paddingRange
    }
}
