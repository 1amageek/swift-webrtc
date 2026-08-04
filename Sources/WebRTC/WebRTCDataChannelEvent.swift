/// One ordered application event from the SCTP data-channel association.
///
/// This is the canonical data-channel delivery surface. A single consumer sees
/// channel creation, owned payloads, and terminal close results in association
/// order, including synchronous transport re-entry.
public enum WebRTCDataChannelEvent: Sendable, Equatable {
    case opened(
        channel: DataChannel,
        direction: WebRTCDataChannelDirection
    )
    case message(channelID: UInt16, generation: UInt64, payload: [UInt8])
    case closed(DataChannelCloseEvent)
}
