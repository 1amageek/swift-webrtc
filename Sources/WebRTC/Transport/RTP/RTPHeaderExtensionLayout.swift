/// The location of an RFC 3550 RTP header extension in its owner datagram.
public struct RTPHeaderExtensionLayout: Sendable, Equatable {
    public let profileIdentifier: UInt16
    public let dataRange: Range<Int>

    init(profileIdentifier: UInt16, dataRange: Range<Int>) {
        self.profileIdentifier = profileIdentifier
        self.dataRange = dataRange
    }
}
