import Synchronization

enum WebRTCDataChannelEventBudgetFailure: Error, Sendable {
    case eventCount
    case payloadByteCount
}

/// Connection-wide event-count and payload-byte budget shared by staged and
/// consumer-owned events.
///
/// An event reserves its payload bytes once when admitted. Moving the event
/// between queues does not change the reservation. The reservation is released
/// exactly once when the application receives the event or terminal cleanup
/// drops its final owner.
final class WebRTCDataChannelEventBudget: Sendable {
    private struct State: Sendable {
        var reservedEventCount = 0
        var reservedPayloadByteCount = 0
    }

    let maximumEventCount: Int
    let maximumPayloadByteCount: Int
    private let state = Mutex(State())

    init(maximumEventCount: Int, maximumPayloadByteCount: Int) {
        precondition(maximumEventCount > 0)
        precondition(maximumPayloadByteCount > 0)
        self.maximumEventCount = maximumEventCount
        self.maximumPayloadByteCount = maximumPayloadByteCount
    }

    func reserve(
        _ events: [WebRTCDataChannelEvent]
    ) -> Result<Void, WebRTCDataChannelEventBudgetFailure> {
        guard let requested = Self.payloadByteCount(of: events) else {
            return .failure(.payloadByteCount)
        }
        return state.withLock { state in
            guard events.count <= maximumEventCount,
                  state.reservedEventCount
                    <= maximumEventCount - events.count else {
                return .failure(.eventCount)
            }
            guard requested <= maximumPayloadByteCount,
                  state.reservedPayloadByteCount
                    <= maximumPayloadByteCount - requested else {
                return .failure(.payloadByteCount)
            }
            state.reservedEventCount += events.count
            state.reservedPayloadByteCount += requested
            return .success(())
        }
    }

    func release(_ event: WebRTCDataChannelEvent) {
        release(
            eventCount: 1,
            payloadByteCount: Self.payloadByteCount(of: event)
        )
    }

    func release(_ events: [WebRTCDataChannelEvent]) {
        guard let released = Self.payloadByteCount(of: events) else {
            preconditionFailure("Reserved event payload size overflowed")
        }
        release(eventCount: events.count, payloadByteCount: released)
    }

    var reservedEventCount: Int {
        state.withLock { $0.reservedEventCount }
    }

    var reservedPayloadByteCount: Int {
        state.withLock { $0.reservedPayloadByteCount }
    }

    private func release(eventCount: Int, payloadByteCount: Int) {
        state.withLock { state in
            precondition(state.reservedEventCount >= eventCount)
            precondition(
                state.reservedPayloadByteCount >= payloadByteCount
            )
            state.reservedEventCount -= eventCount
            state.reservedPayloadByteCount -= payloadByteCount
        }
    }

    private static func payloadByteCount(
        of events: [WebRTCDataChannelEvent]
    ) -> Int? {
        var total = 0
        for event in events {
            let addition = total.addingReportingOverflow(
                payloadByteCount(of: event)
            )
            guard !addition.overflow else { return nil }
            total = addition.partialValue
        }
        return total
    }

    private static func payloadByteCount(
        of event: WebRTCDataChannelEvent
    ) -> Int {
        switch event {
        case .message(_, _, let payload):
            return payload.count
        case .opened, .closed:
            return 0
        }
    }
}
