/// The facade's timer seam selection.
///
/// `WebRTCConnection` drives the periodic SCTP T3-rtx retransmission tick and any
/// other deadline-based scheduling through the `AsyncTimer` seam (declared in
/// `P2PCoreCrypto`) rather than `Task.sleep` / `ContinuousClock`, both of which
/// are `@available(*, unavailable)` under Embedded Swift. `WebRTCTimer` erases
/// one concrete implementation without an existential; this file selects the
/// package-provided default.
///
///   native host:       WebRTCDefaultTimer = WebRTCHostTimer
///   WASI / Embedded:   WebRTCDefaultTimer = WebRTCPortableTimer
///
/// The webrtc package defines its own timers (rather than depending on
/// swift-p2p-transport's `DefaultAsyncTimer`) so the Embedded build is driven by
/// the SAME `P2P_CORE_EMBEDDED=1` flag as the rest of this package — pulling in
/// `P2PTransportPOSIX` would key its Embedded mode off a different flag
/// (`P2P_TRANSPORT_EMBEDDED`) and desynchronise the Embedded module graph. This
/// mirrors swift-mDNS's `MDNSTimer` seam.

import P2PCoreCrypto

extension Duration {
    /// This duration as whole nanoseconds (saturating, non-negative), for the
    /// `AsyncTimer.sleep(untilNanos:)` deadline math. `components` is Embedded-clean
    /// (unlike `ContinuousClock`), so this works in both builds.
    var facadeNanoseconds: UInt64 {
        let (seconds, attoseconds) = components
        let positiveSeconds = UInt64(max(0, seconds))
        let (secNanos, secondsOverflow) = positiveSeconds
            .multipliedReportingOverflow(by: 1_000_000_000)
        if secondsOverflow {
            return UInt64.max
        }
        let fracNanos = UInt64(max(0, attoseconds) / 1_000_000_000)
        let (total, additionOverflow) = secNanos.addingReportingOverflow(
            fracNanos
        )
        return additionOverflow ? UInt64.max : total
    }
}

#if !hasFeature(Embedded) && !canImport(WASILibc)
import _Concurrency

/// The host default timer: `ContinuousClock` for time, `Task.sleep` for the wait.
typealias WebRTCDefaultTimer = WebRTCHostTimer

/// A host `AsyncTimer` backed by `ContinuousClock` + `Task.sleep(until:clock:)`.
struct WebRTCHostTimer: AsyncTimer {
    private let origin: ContinuousClock.Instant
    private let clock = ContinuousClock()

    init() {
        self.origin = ContinuousClock.now
    }

    func monotonicNanos() -> UInt64 {
        let elapsed = ContinuousClock.now - origin
        let (seconds, attoseconds) = elapsed.components
        return UInt64(max(0, seconds)) &* 1_000_000_000
            &+ UInt64(max(0, attoseconds) / 1_000_000_000)
    }

    func monotonicMillis() -> UInt64 {
        monotonicNanos() / 1_000_000
    }

    func sleep(untilNanos deadlineNanos: UInt64) async throws(CancellationError) {
        let now = monotonicNanos()
        if deadlineNanos <= now { return }
        let waitNanos = deadlineNanos - now
        let instant = ContinuousClock.now.advanced(by: .nanoseconds(waitNanos))
        do {
            try await Task.sleep(until: instant, clock: clock)
        } catch {
            // `Task.sleep` throws only `CancellationError`; re-surface it typed.
            throw CancellationError()
        }
    }
}

#else
import _Concurrency

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(WASILibc)
import WASILibc
#endif

/// The WASI / Embedded default timer over the platform monotonic clock.
typealias WebRTCDefaultTimer = WebRTCPortableTimer

/// An Embedded-clean `AsyncTimer` over the platform C library.
///
/// `monotonicNanos()` reads the platform monotonic clock. `sleep(untilNanos:)`
/// parks in fixed slices, yielding after every slice and honoring cancellation
/// between slices. Embedded-clean:
/// only the platform C library + `_Concurrency`; no
/// Foundation, no NIO, no `any`, no `ContinuousClock`, no `Task.sleep`.
///
/// A production embedder should inject its own timer parked on the platform's
/// real executor. This fallback blocks only for one bounded slice before
/// cooperatively yielding to other tasks.
struct WebRTCPortableTimer: AsyncTimer {

    init() {}

    func monotonicNanos() -> UInt64 {
        Self.nowNanos()
    }

    func monotonicMillis() -> UInt64 {
        Self.nowNanos() / 1_000_000
    }

    func sleep(untilNanos deadlineNanos: UInt64) async throws(CancellationError) {
        if Task.isCancelled { throw CancellationError() }
        if deadlineNanos <= Self.nowNanos() { return }

        // Park in fixed slices, re-checking cancellation and the deadline each
        // slice. A throwing continuation (`any Error`) is forbidden under
        // Embedded, so this loops with short non-throwing suspensions rather than
        // resuming a thrown error across a continuation boundary.
        let sliceNanos: UInt64 = 20_000_000   // 20 ms
        while true {
            if Task.isCancelled { throw CancellationError() }
            let now = Self.nowNanos()
            if now >= deadlineNanos { return }
            let remaining = deadlineNanos - now
            Self.nanosleepFor(min(remaining, sliceNanos))
            await Task.yield()
        }
    }

    @inline(__always)
    static func nowNanos() -> UInt64 {
        #if canImport(WASILibc)
        var timestamp: __wasi_timestamp_t = 0
        let result = __wasi_clock_time_get(__wasi_clockid_t(1), 1, &timestamp)
        precondition(result == 0, "WASI monotonic clock failed")
        return UInt64(timestamp)
        #else
        var ts = timespec()
        let result = clock_gettime(CLOCK_MONOTONIC, &ts)
        precondition(result == 0, "clock_gettime(CLOCK_MONOTONIC) failed")
        let seconds = UInt64(ts.tv_sec)
        let nanos = UInt64(ts.tv_nsec)
        return seconds &* 1_000_000_000 &+ nanos
        #endif
    }

    @inline(__always)
    static func nanosleepFor(_ nanos: UInt64) {
        #if canImport(WASILibc)
        var subscription = __wasi_subscription_t()
        subscription.userdata = 0
        subscription.u.tag = __wasi_eventtype_t(0)
        subscription.u.u.clock.id = __wasi_clockid_t(1)
        subscription.u.u.clock.timeout = __wasi_timestamp_t(nanos)
        subscription.u.u.clock.precision = 1
        subscription.u.u.clock.flags = 0

        var event = __wasi_event_t()
        var eventCount: __wasi_size_t = 0
        let result = __wasi_poll_oneoff(&subscription, &event, 1, &eventCount)
        precondition(result == 0, "WASI clock sleep failed")
        precondition(eventCount == 1, "WASI clock sleep produced no event")
        precondition(event.error == 0, "WASI clock event failed")
        #else
        var request = timespec(
            tv_sec: Int(nanos / 1_000_000_000),
            tv_nsec: Int(nanos % 1_000_000_000)
        )
        var remaining = timespec()
        while nanosleep(&request, &remaining) != 0 {
            guard errno == EINTR else {
                preconditionFailure("POSIX monotonic sleep failed")
            }
            request = remaining
        }
        #endif
    }
}

#endif
