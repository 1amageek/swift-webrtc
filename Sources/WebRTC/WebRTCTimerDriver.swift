import NetworkingTime
#if canImport(WASILibc)
import NetworkingWASI
#elseif hasFeature(Embedded)
import NetworkingPOSIX
#endif

/// Non-generic timer owner used by the public WebRTC facade.
///
/// Both closures preserve the source timer's clock domain and typed failures.
public struct WebRTCTimer: AsyncTimer, Sendable {
    private let readInstant: @Sendable () throws(TimeError) -> MonotonicInstant
    private let park: @Sendable (
        MonotonicInstant
    ) async throws(TimeError) -> Void

    public init<Timer: AsyncTimer>(_ timer: Timer) {
        readInstant = { () throws(TimeError) -> MonotonicInstant in
            try timer.now()
        }
        park = { deadline throws(TimeError) in
            try await timer.sleep(until: deadline)
        }
    }

    public static var platformDefault: WebRTCTimer {
        WebRTCTimer(WebRTCDefaultTimer())
    }

    public func now() throws(TimeError) -> MonotonicInstant {
        try readInstant()
    }

    public func sleep(
        until deadline: MonotonicInstant
    ) async throws(TimeError) {
        try await park(deadline)
    }
}
