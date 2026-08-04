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
///
/// Host-only: this `ContinuousClock`/`Duration` surface exists for the historical
/// public API and the test suite. The Embedded path drives
/// `SCTPWireCore.RetransmissionState` directly (millis domain), so this wrapper is
/// gated out of the Embedded build.

#if !hasFeature(Embedded) && !os(WASI)
import Foundation

/// Retransmission queue for reliable delivery.
///
/// A thin caller-driven wrapper around ``SCTPWireCore/RetransmissionState`` that
/// converts the historical `ContinuousClock`/`Duration` surface to and from the
/// core's millisecond domain.
struct RetransmissionQueue: Sendable {
    /// The Embedded-clean accounting state.
    private var state: RetransmissionState

    /// Monotonic epoch against which injected instants are measured. Captured at
    /// init so the core's elapsed-millis arithmetic matches caller-supplied
    /// `Duration` deltas.
    private let epoch: ContinuousClock.Instant

    init() {
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
        let positiveSeconds = UInt64(max(0, components.seconds))
        let (secondsMillis, multiplicationOverflow) = positiveSeconds
            .multipliedReportingOverflow(by: 1_000)
        guard !multiplicationOverflow else { return UInt64.max }
        let attoMillis = UInt64(max(0, components.attoseconds) / 1_000_000_000_000_000)
        let (milliseconds, additionOverflow) = secondsMillis
            .addingReportingOverflow(attoMillis)
        return additionOverflow ? UInt64.max : milliseconds
    }

    /// Add a chunk to the retransmission queue, enforcing the send-window cap.
    /// - Throws: `SCTPStateError.sendQueueFull` (typed backpressure), bridged to
    ///   `SCTPError.sendQueueFull` at the association boundary.
    mutating func enqueue(_ chunk: SCTPDataChunk, sentTime: ContinuousClock.Instant = .now) throws {
        do {
            try state.enqueue(chunk, sentMillis: millis(sentTime))
        } catch {
            throw error.asSCTPError
        }
    }

    /// Validate and atomically apply one SACK acknowledgment.
    @discardableResult
    mutating func acknowledge(
        cumulativeTSN: UInt32,
        gapBlocks: [(start: UInt16, end: UInt16)],
        advertisedReceiverWindowCredit: UInt32 = 65_535,
        receivedTime: ContinuousClock.Instant = .now
    ) -> SCTPSackOutcome {
        state.acknowledge(
            cumulativeTSN: cumulativeTSN,
            gapBlocks: gapBlocks,
            advertisedReceiverWindowCredit: advertisedReceiverWindowCredit,
            receivedMillis: millis(receivedTime)
        )
    }

    /// Get chunks that need retransmission.
    /// - Parameter now: Current time; injectable for deterministic testing.
    /// - Returns: Chunks to retransmit, or failure if max retransmits exceeded.
    mutating func pendingRetransmissions(
        now: ContinuousClock.Instant = .now
    ) -> Result<[SCTPDataChunk], RetransmissionError> {
        state.pendingRetransmissions(nowMillis: millis(now))
    }

    /// Mark a chunk for fast retransmit (3 duplicate SACKs).
    mutating func markForFastRetransmit(tsn: UInt32) {
        state.markForFastRetransmit(tsn: tsn)
    }

    /// Check if queue is empty.
    var isEmpty: Bool { state.isEmpty }

    /// Number of pending chunks.
    var count: Int { state.count }

    /// Check if we can send more data (congestion window check).
    var canSend: Bool { state.canSend }

    /// Highest TSN sent.
    var highestSentTSN: UInt32? { state.highestSentTSN }

    /// Number of bytes in flight.
    var bytesInFlight: Int { state.bytesInFlight }

    /// Payload bytes retained until cumulative acknowledgment.
    var retainedPayloadByteCount: Int {
        state.retainedPayloadByteCount
    }

    /// Effective peer receive-window allowance for new DATA.
    var peerReceiverWindow: UInt64 { state.peerReceiverWindow }

    /// Congestion window.
    var cwnd: Int { state.cwnd }

    /// Current RTO value as a `Duration` (converted from the core's millis).
    var currentRTO: Duration { .milliseconds(Int64(state.currentRTOMillis)) }
}

#endif
