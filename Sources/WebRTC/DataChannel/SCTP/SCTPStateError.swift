/// Typed-throws error for the Embedded-clean SCTP association state machine.
///
/// Embedded Swift forbids untyped `throws` (which is `throws(any Error)`), so the
/// state-machine value types (`FragmentAssembler`, `RetransmissionQueue`, …) use
/// typed throws with this single closed enum. These mirror the historical
/// `SCTPError` cases the state machine raises; the association adapter maps them
/// back onto `SCTPError` at the `Data`-based boundary so callers (and the existing
/// test suite) continue to catch `SCTPError` directly.

/// The single typed-throws error raised by the SCTP state machine value types.
enum SCTPStateError: Error, Sendable, Equatable {
    /// A peer exceeded the reassembly or reordering buffer limits for a stream.
    case receiveBufferExceeded(streamID: UInt16)
    /// The retransmission queue's send-window byte ceiling was reached.
    case sendQueueFull(bytesInFlight: Int, limit: Int)
    /// The retransmission queue's retained chunk metadata ceiling was reached.
    case sendChunkLimitReached(retainedChunkCount: Int, limit: Int)
    /// The legacy one-packet API cannot queue a chunk when no immediate sender
    /// window is available.
    case sendWindowUnavailable(requiredByteCount: Int, availableByteCount: Int)
}

/// Non-throwing retransmission outcome: a DATA chunk hit the retransmit ceiling.
///
/// `RetransmissionQueue.pendingRetransmissions(nowMillis:)` returns this through a
/// `Result` (rather than throwing) so the caller can distinguish "nothing to
/// retransmit" from "the association must abort" (RFC 4960 §8.2).
enum RetransmissionError: Error, Sendable, Equatable {
    case maxRetransmitsExceeded(tsn: UInt32)
    case accountingInvariantViolation
}
