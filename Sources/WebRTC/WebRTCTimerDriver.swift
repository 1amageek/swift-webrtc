import _Concurrency
import P2PCoreCrypto

/// Type-erased timer driver used by `WebRTCConnection`.
///
/// WebRTC is a non-generic public facade, while Embedded deployments must be
/// able to provide a board or event-loop timer that genuinely suspends the
/// current task. This value captures one concrete `AsyncTimer` without an
/// existential and preserves its monotonic-clock and typed-cancellation
/// contracts on Native, WASM, and Embedded targets.
public struct WebRTCTimer: AsyncTimer, Sendable {
    private let readNanoseconds: @Sendable () -> UInt64
    private let readMilliseconds: @Sendable () -> UInt64
    private let park: @Sendable (
        UInt64
    ) async throws(CancellationError) -> Void

    public init<Timer: AsyncTimer>(_ timer: Timer) {
        self.readNanoseconds = {
            timer.monotonicNanos()
        }
        self.readMilliseconds = {
            timer.monotonicMillis()
        }
        self.park = {
            deadline throws(CancellationError) in
            try await timer.sleep(untilNanos: deadline)
        }
    }

    /// The package-provided timer for the current target.
    ///
    /// WASI and Embedded products should inject their executor-integrated timer
    /// when available. The built-in portable implementation cooperatively
    /// yields between bounded platform sleep slices; it is not a board-specific
    /// scheduler.
    public static var platformDefault: WebRTCTimer {
        WebRTCTimer(WebRTCDefaultTimer())
    }

    public func monotonicNanos() -> UInt64 {
        readNanoseconds()
    }

    public func monotonicMillis() -> UInt64 {
        readMilliseconds()
    }

    public func sleep(
        untilNanos deadlineNanos: UInt64
    ) async throws(CancellationError) {
        try await park(deadlineNanos)
    }
}
