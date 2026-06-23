/// Retransmission Queue (RFC 4960 Section 6.3) — clock-seam adapter.
///
/// This is the host-side adapter over the Embedded-clean value type
/// `SCTPWireCore.RetransmissionState`. The core does all retransmission / RTO /
/// RTT / congestion accounting in plain milliseconds; this wrapper restores the
/// historical `ContinuousClock`/`Duration` surface that the SCTP state machine and
/// the existing test suite bind to.
///
/// ## Clock seam
///
/// The core takes a monotonic `nowMillis: UInt64` parameter instead of reading a
/// clock. This wrapper captures a fixed `ContinuousClock` epoch at init and
/// converts each injected `ContinuousClock.Instant` to epoch-relative milliseconds
/// before delegating, so the millisecond deltas the core reasons about match the
/// `Duration` deltas callers pass. `Duration`-typed results (RTO) are converted
/// back from the core's millis.

import Foundation

/// Retransmission error surfaced by the queue's retransmission scan.
///
/// Re-exposes the core's ``SCTPWireCore/RetransmissionError`` under the historical
/// adapter name so existing call sites keep catching it unchanged.
public typealias RetransmissionError = SCTPWireCore.RetransmissionError

/// Pending chunk awaiting acknowledgment.
///
/// Re-exposes the core value type under the historical adapter name.
public typealias PendingChunk = SCTPWireCore.PendingChunk

/// Retransmission queue for reliable delivery.
///
/// A thin caller-driven wrapper around ``SCTPWireCore/RetransmissionState`` that
/// converts the historical `ContinuousClock`/`Duration` surface to and from the
/// core's millisecond domain.
public struct RetransmissionQueue: Sendable {
    /// The Embedded-clean accounting state.
    private var state: RetransmissionState

    /// Monotonic epoch against which injected instants are measured. Captured at
    /// init so the core's elapsed-millis arithmetic matches caller-supplied
    /// `Duration` deltas.
    private let epoch: ContinuousClock.Instant

    public init() {
        self.state = RetransmissionState()
        self.epoch = ContinuousClock.now
    }

    /// Converts an instant to epoch-relative milliseconds (saturating).
    private func millis(_ instant: ContinuousClock.Instant) -> UInt64 {
        Self.durationToMillis(instant - epoch)
    }

    /// Converts a `Duration` to milliseconds (saturating, non-negative).
    private static func durationToMillis(_ duration: Duration) -> UInt64 {
        let components = duration.components
        guard components.seconds > 0 || components.attoseconds > 0 else { return 0 }
        let secondsMillis = UInt64(max(0, components.seconds)) &* 1000
        let attoMillis = UInt64(max(0, components.attoseconds) / 1_000_000_000_000_000)
        return secondsMillis &+ attoMillis
    }

    /// Add a chunk to the retransmission queue, enforcing the send-window cap.
    /// - Throws: `SCTPStateError.sendQueueFull` (typed backpressure), bridged to
    ///   `SCTPError.sendQueueFull` at the association boundary.
    public mutating func enqueue(_ chunk: SCTPDataChunk, sentTime: ContinuousClock.Instant = .now) throws {
        do {
            try state.enqueue(chunk, sentMillis: millis(sentTime))
        } catch {
            throw error.asSCTPError
        }
    }

    /// Process a SACK acknowledgment.
    /// - Returns: True if any new data was acknowledged.
    @discardableResult
    public mutating func acknowledge(
        cumulativeTSN: UInt32,
        gapBlocks: [(start: UInt16, end: UInt16)],
        receivedTime: ContinuousClock.Instant = .now
    ) -> Bool {
        state.acknowledge(
            cumulativeTSN: cumulativeTSN,
            gapBlocks: gapBlocks,
            receivedMillis: millis(receivedTime)
        )
    }

    /// Get chunks that need retransmission.
    /// - Parameter now: Current time; injectable for deterministic testing.
    /// - Returns: Chunks to retransmit, or failure if max retransmits exceeded.
    public mutating func pendingRetransmissions(
        now: ContinuousClock.Instant = .now
    ) -> Result<[SCTPDataChunk], RetransmissionError> {
        state.pendingRetransmissions(nowMillis: millis(now))
    }

    /// Mark a chunk for fast retransmit (3 duplicate SACKs).
    public mutating func markForFastRetransmit(tsn: UInt32) {
        state.markForFastRetransmit(tsn: tsn)
    }

    /// Check if queue is empty.
    public var isEmpty: Bool { state.isEmpty }

    /// Number of pending chunks.
    public var count: Int { state.count }

    /// Check if we can send more data (congestion window check).
    public var canSend: Bool { state.canSend }

    /// Highest TSN sent.
    public var highestSentTSN: UInt32? { state.highestSentTSN }

    /// Number of bytes in flight.
    public var bytesInFlight: Int { state.bytesInFlight }

    /// Congestion window.
    public var cwnd: Int { state.cwnd }

    /// Current RTO value as a `Duration` (converted from the core's millis).
    public var currentRTO: Duration { .milliseconds(Int64(state.currentRTOMillis)) }
}
