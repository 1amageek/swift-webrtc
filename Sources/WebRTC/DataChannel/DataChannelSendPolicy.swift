/// The SCTP flags selected atomically from one data-channel state snapshot.
struct DataChannelSendPolicy: Sendable, Equatable {
    /// Whether SCTP DATA may set the unordered-delivery bit.
    let unordered: Bool

    /// How long SCTP should persist in transmitting each application message.
    let reliability: SCTPMessageReliability

    init(
        unordered: Bool,
        reliability: SCTPMessageReliability = .reliable
    ) {
        self.unordered = unordered
        self.reliability = reliability
    }
}
