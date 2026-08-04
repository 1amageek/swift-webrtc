/// Caller-driven RFC 9260 T2-shutdown timer state.
struct SCTPShutdownTimerState: Sendable {
    enum ControlFlight: Sendable, Equatable {
        case shutdown
        case shutdownAck
    }

    static let maximumRetransmitCount = 10
    static let maximumRTOMillis: UInt64 = 60_000
    static let shutdownGuardMillis = maximumRTOMillis * 5

    let controlFlight: ControlFlight
    var t2DeadlineMillis: UInt64
    let t5DeadlineMillis: UInt64?
    var rtoMillis: UInt64
    var retransmitCount: Int

    init(
        controlFlight: ControlFlight,
        sentMillis: UInt64,
        rtoMillis: UInt64,
        inheritedT5DeadlineMillis: UInt64? = nil
    ) throws(SCTPError) {
        try Self.validate(rtoMillis: rtoMillis)
        let t2DeadlineMillis = try Self.deadline(
            after: sentMillis,
            intervalMillis: rtoMillis
        )
        let t5DeadlineMillis: UInt64?
        switch controlFlight {
        case .shutdown:
            t5DeadlineMillis = try Self.deadline(
                after: sentMillis,
                intervalMillis: Self.shutdownGuardMillis
            )
        case .shutdownAck:
            t5DeadlineMillis = inheritedT5DeadlineMillis
        }

        self.controlFlight = controlFlight
        self.t2DeadlineMillis = t2DeadlineMillis
        self.t5DeadlineMillis = t5DeadlineMillis
        self.rtoMillis = rtoMillis
        self.retransmitCount = 0
    }

    func isT2Expired(at nowMillis: UInt64) -> Bool {
        nowMillis >= t2DeadlineMillis
    }

    func isT5Expired(at nowMillis: UInt64) -> Bool {
        guard let t5DeadlineMillis else { return false }
        return nowMillis >= t5DeadlineMillis
    }

    mutating func restart(at nowMillis: UInt64) throws(SCTPError) {
        let nextDeadline = try Self.deadline(
            after: nowMillis,
            intervalMillis: rtoMillis
        )
        retransmitCount = 0
        t2DeadlineMillis = nextDeadline
    }

    mutating func backoff(at nowMillis: UInt64) throws(SCTPError) {
        let (nextRetransmitCount, countOverflow) = retransmitCount
            .addingReportingOverflow(1)
        guard !countOverflow else {
            throw .monotonicClockValueOutOfRange
        }
        let (doubledRTO, rtoOverflow) = rtoMillis
            .multipliedReportingOverflow(by: 2)
        guard !rtoOverflow else {
            throw .monotonicClockValueOutOfRange
        }
        let nextRTO = min(doubledRTO, Self.maximumRTOMillis)
        let nextDeadline = try Self.deadline(
            after: nowMillis,
            intervalMillis: nextRTO
        )
        retransmitCount = nextRetransmitCount
        rtoMillis = nextRTO
        t2DeadlineMillis = nextDeadline
    }

    private static func validate(rtoMillis: UInt64) throws(SCTPError) {
        guard rtoMillis > 0, rtoMillis <= maximumRTOMillis else {
            throw .invalidShutdownRTO(actual: rtoMillis)
        }
    }

    private static func deadline(
        after nowMillis: UInt64,
        intervalMillis: UInt64
    ) throws(SCTPError) -> UInt64 {
        let (deadline, overflow) = nowMillis.addingReportingOverflow(
            intervalMillis
        )
        guard !overflow else {
            throw .monotonicClockValueOutOfRange
        }
        return deadline
    }
}
