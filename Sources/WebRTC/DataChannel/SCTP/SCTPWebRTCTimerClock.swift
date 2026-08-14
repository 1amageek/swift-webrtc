import NetworkingTime

/// Adapts the connection timer's monotonic domain to SCTP's millisecond policy.
///
/// Scheduling and protocol deadlines must observe the same clock owner. The
/// adapter changes only the unit; it does not invent an epoch or recover from a
/// failed clock read.
struct SCTPWebRTCTimerClock: SCTPMonotonicClock {
    let timer: WebRTCTimer

    func currentMilliseconds() throws(SCTPError) -> UInt64 {
        do {
            return try timer.now().nanoseconds / 1_000_000
        } catch {
            throw .timeFailed(error)
        }
    }
}
