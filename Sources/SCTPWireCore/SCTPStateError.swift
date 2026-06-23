/// Typed-throws error for the Embedded-clean SCTP association state machine.
///
/// Embedded Swift forbids untyped `throws` (which is `throws(any Error)`), so the
/// state-machine value types (`FragmentAssembler`, `RetransmissionQueue`, …) use
/// typed throws with this single closed enum. These mirror the historical
/// `SCTPError` cases the state machine raises; the `SCTPCore` adapter maps them
/// back onto `SCTPError` at the `Data`-based boundary so callers (and the existing
/// test suite) continue to catch `SCTPError` directly.

/// The single typed-throws error raised by the SCTP state machine value types.
public enum SCTPStateError: Error, Sendable, Equatable {
    /// A peer exceeded the reassembly or reordering buffer limits for a stream.
    case receiveBufferExceeded(streamID: UInt16)
    /// The retransmission queue's send-window byte ceiling was reached.
    case sendQueueFull(bytesInFlight: Int, limit: Int)
}

/// Non-throwing retransmission outcome: a DATA chunk hit the retransmit ceiling.
///
/// `RetransmissionQueue.pendingRetransmissions(nowMillis:)` returns this through a
/// `Result` (rather than throwing) so the caller can distinguish "nothing to
/// retransmit" from "the association must abort" (RFC 4960 §8.2).
public enum RetransmissionError: Error, Sendable, Equatable {
    case maxRetransmitsExceeded(tsn: UInt32)
}
