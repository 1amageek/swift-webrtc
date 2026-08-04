
/// Canonical result of one caller-driven outbound protocol poll.
///
/// A terminal timer or retransmission failure can require a final ABORT on the
/// wire. Keeping the packet owner beside the typed failure lets a transport
/// commit terminal state, emit that final packet once, and only then release its
/// encryption/network owners.
enum SCTPOutboundPollOutcome: Sendable {
    case packets([SCTPPacket])
    case terminal(packets: [SCTPPacket], error: SCTPError)
}
