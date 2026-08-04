#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(WASILibc)
import WASILibc
#endif

/// The platform monotonic clock used by the default SCTP association facade.
struct SCTPSystemMonotonicClock: SCTPMonotonicClock {
    init() {}

    func currentMilliseconds() throws(SCTPError) -> UInt64 {
        #if !hasFeature(Embedded)
        return Self.milliseconds(from: ContinuousClock.now)
        #elseif canImport(WASILibc)
        var timestamp: __wasi_timestamp_t = 0
        let result = __wasi_clock_time_get(__wasi_clockid_t(1), 1, &timestamp)
        guard result == 0 else {
            throw .monotonicClockFailure(code: UInt32(result))
        }
        return UInt64(timestamp) / 1_000_000
        #else
        var timestamp = timespec()
        let result = clock_gettime(CLOCK_MONOTONIC, &timestamp)
        guard result == 0 else {
            throw .monotonicClockFailure(code: UInt32(bitPattern: errno))
        }
        guard timestamp.tv_sec >= 0,
              timestamp.tv_nsec >= 0,
              timestamp.tv_nsec < 1_000_000_000 else {
            throw .monotonicClockValueOutOfRange
        }
        let seconds = UInt64(timestamp.tv_sec)
        let nanoseconds = UInt64(timestamp.tv_nsec)
        let (secondMilliseconds, multiplicationOverflow) =
            seconds.multipliedReportingOverflow(by: 1_000)
        let (milliseconds, additionOverflow) =
            secondMilliseconds.addingReportingOverflow(
                nanoseconds / 1_000_000
            )
        guard !multiplicationOverflow, !additionOverflow else {
            throw .monotonicClockValueOutOfRange
        }
        return milliseconds
        #endif
    }

    #if !hasFeature(Embedded)
    /// Fixed epoch keeps injected `ContinuousClock.Instant` values and the
    /// self-sourced clock in the same monotonic millisecond domain.
    static let epoch = ContinuousClock.now

    static func milliseconds(from instant: ContinuousClock.Instant) -> UInt64 {
        let duration = instant - epoch
        let (seconds, attoseconds) = duration.components
        guard seconds > 0 || attoseconds > 0 else { return 0 }
        let positiveSeconds = UInt64(max(0, seconds))
        let positiveAttoseconds = UInt64(max(0, attoseconds))
        let (secondMilliseconds, multiplicationOverflow) =
            positiveSeconds.multipliedReportingOverflow(by: 1_000)
        guard !multiplicationOverflow else { return UInt64.max }
        let attosecondMilliseconds =
            positiveAttoseconds / 1_000_000_000_000_000
        let (milliseconds, additionOverflow) =
            secondMilliseconds.addingReportingOverflow(attosecondMilliseconds)
        return additionOverflow ? UInt64.max : milliseconds
    }
    #endif
}
