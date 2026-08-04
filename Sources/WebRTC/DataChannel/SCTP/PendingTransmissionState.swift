/// Sender-side lifecycle of one retained SCTP DATA chunk.
enum PendingTransmissionState: Sendable, Equatable {
    /// Retained but not yet emitted because congestion or receiver flow control
    /// has no allowance.
    case queued

    /// Emitted and not selectively acknowledged by the peer.
    case inFlight

    /// Selectively acknowledged but retained until a cumulative acknowledgment
    /// releases the payload owner because SCTP permits reneging.
    case gapAcknowledged

    /// Scheduled for immediate fast retransmission.
    case markedForRetransmission
}
