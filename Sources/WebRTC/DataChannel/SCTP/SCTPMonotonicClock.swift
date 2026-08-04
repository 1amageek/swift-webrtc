/// Supplies monotonic time to the SCTP host facade.
///
/// Implementations must return one nondecreasing millisecond domain for their
/// complete lifetime. A clock read failure is part of the typed SCTP failure
/// contract and must never be replaced with wall-clock time or a synthetic
/// value.
protocol SCTPMonotonicClock: Sendable {
    func currentMilliseconds() throws(SCTPError) -> UInt64
}
