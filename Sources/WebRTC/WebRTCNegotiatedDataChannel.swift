/// A data channel whose SCTP stream identifier is agreed outside DCEP.
///
/// Negotiated channels are installed before the SCTP association starts, so an
/// incoming message can never race channel registration. Their identifiers stay
/// reserved for the association lifetime after close.
public struct WebRTCNegotiatedDataChannel: Sendable, Equatable {
    public let id: UInt16
    public let label: String
    public let ordered: Bool
    public let reliability: DataChannelReliability

    public init(
        id: UInt16,
        label: String = "",
        ordered: Bool = true,
        reliability: DataChannelReliability = .reliable
    ) {
        self.id = id
        self.label = label
        self.ordered = ordered
        self.reliability = reliability
    }
}
