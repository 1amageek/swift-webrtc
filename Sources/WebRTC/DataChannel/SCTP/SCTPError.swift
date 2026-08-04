/// SCTP errors (historical concrete type).
///
/// The Embedded-clean SCTP wire codec in `SCTPWireCore` throws
/// ``SCTPWireError``; the adapter unwraps it back to this type at the
/// `Data`-based boundary so callers (and the existing test suite) continue to
/// catch `SCTPError` directly. The state machine (`SCTPAssociation`,
/// `FragmentAssembler`, `RetransmissionQueue`, `SCTPCookie`, …) also throws this
/// type for protocol-level violations.
///
/// Embedded-clean: `Error`/`Sendable` are available under Embedded Swift, so this
/// type needs no Foundation import and is shared by both the host adapter and the
/// Embedded engine.

public enum SCTPError: Error, Sendable {
    case insufficientData(expected: Int, actual: Int)
    case invalidFormat(String)
    case associationFailed(String)
    case streamReset(String)
    case timeout
    case checksumMismatch(expected: UInt32, actual: UInt32)
    case cookieValidationFailed
    case cookieExpired
    case restartEntropyUnavailable
    case restartInitiateTagCollision
    case maxRetransmitsExceeded
    case verificationTagMismatch(expected: UInt32, actual: UInt32)
    case associationAborted
    case invalidState(String)
    case receiveBufferExceeded(streamID: UInt16)
    case invalidStreamIdentifier(streamID: UInt16, negotiated: UInt16)
    case sendQueueFull(bytesInFlight: Int, limit: Int)
    case sendChunkLimitReached(retainedChunkCount: Int, limit: Int)
    case sendWindowUnavailable(requiredByteCount: Int, availableByteCount: Int)
    case sackProtocolViolation(SCTPSackViolation)
    /// The compatibility API can return only one packet, but this message needs
    /// the canonical packet-batch API.
    case messageRequiresPacketBatch(
        payloadByteCount: Int,
        maximumSinglePacketPayloadByteCount: Int
    )
    /// The caller supplied a packet budget too small for one non-empty DATA
    /// fragment and the SCTP/DATA headers.
    case invalidMaximumPacketByteCount(actual: Int, minimum: Int)
    /// A generated packet violated the validated path-MTU budget.
    case packetSizeExceeded(actual: Int, limit: Int)
    case chunkValueTooLarge(actual: Int, maximum: Int)
    case streamReconfigurationNotNegotiated
    case partialReliabilityNotNegotiated
    case streamResetQueueFull(limit: Int)
    /// The single-packet compatibility API cannot represent an accepted send
    /// that intentionally emits no packet until the stream reset completes.
    case sendRequiresPacketBatchDuringReset(streamID: UInt16)
    /// The single-packet compatibility API cannot represent a timed message
    /// that expires before TSN assignment and intentionally emits no packet.
    case sendRequiresPacketBatchForExpiredMessage
    /// Advancing existing protocol state generated control plus DATA packets;
    /// the compatibility API cannot return the complete atomic batch.
    case sendRequiresPacketBatchForProtocolProgress(packetCount: Int)
    case invalidStreamResetIdentifier(streamID: UInt16, negotiated: UInt16)
    case reconfigurationTimeout(requestSequenceNumber: UInt32)
    case shutdownTimeout
    case shutdownGuardTimeout
    case invalidShutdownRTO(actual: UInt64)
    case monotonicClockFailure(code: UInt32)
    case monotonicClockValueOutOfRange
}
