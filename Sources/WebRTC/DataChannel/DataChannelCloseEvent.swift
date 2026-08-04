
/// A terminal data-channel close notification.
public enum DataChannelCloseEvent: Sendable, Equatable {
    /// Both the incoming and outgoing SCTP stream resets completed.
    case closed(channelID: UInt16, generation: UInt64)

    /// The peer rejected the local outgoing stream reset.
    case failed(
        channelID: UInt16,
        generation: UInt64,
        result: SCTPReconfigurationResult
    )

    public var channelID: UInt16 {
        switch self {
        case .closed(let channelID, _), .failed(let channelID, _, _):
            channelID
        }
    }

    public var generation: UInt64 {
        switch self {
        case .closed(_, let generation), .failed(_, let generation, _):
            generation
        }
    }
}

/// Data-channel work produced by one incoming SCTP reset event.
struct DataChannelResetTransition: Sendable {
    /// Streams for which RFC 8831 requires a reciprocal outgoing reset.
    let reciprocalReset: SCTPStreamSelection?
    let closeEvents: [DataChannelCloseEvent]

    init(
        reciprocalReset: SCTPStreamSelection?,
        closeEvents: [DataChannelCloseEvent]
    ) {
        self.reciprocalReset = reciprocalReset
        self.closeEvents = closeEvents
    }
}
