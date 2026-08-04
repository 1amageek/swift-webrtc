import Synchronization

/// Mutex-isolated owner for one connection's ordered DataChannel events.
///
/// The queue stores event values whose payload arrays retain their existing COW
/// storage; it never re-materializes payload bytes. Continuations are resumed
/// only after releasing the mutex.
final class WebRTCDataChannelEventConsumer:
    WebRTCDataChannelEventConsuming,
    Sendable {
    enum YieldResult: Sendable {
        case enqueued
        case dropped
        case terminated
    }

    private enum Delivery: Sendable {
        case event(WebRTCDataChannelEvent)
        case finished
        case failure(WebRTCError)
    }

    private struct Waiter: Sendable {
        let readID: UInt64
        let continuation: CheckedContinuation<Delivery, Never>
    }

    private struct ConsumerState: Sendable {
        var events: WebRTCDataChannelEventQueue
        var nextReadID: UInt64? = 0
        var activeReadID: UInt64?
        var waiter: Waiter?
        var didFinish = false
        var terminalFailure: WebRTCError?
    }

    private enum YieldAction {
        case resume(CheckedContinuation<Delivery, Never>)
        case result(YieldResult)
    }

    private let consumerState: Mutex<ConsumerState>
    private let eventBudget: WebRTCDataChannelEventBudget

    init(
        maximumBufferedEventCount: Int,
        eventBudget: WebRTCDataChannelEventBudget
    ) {
        self.eventBudget = eventBudget
        self.consumerState = Mutex(ConsumerState(
            events: WebRTCDataChannelEventQueue(
                maximumCount: maximumBufferedEventCount
            )
        ))
    }

    func next()
        async throws(WebRTCError) -> WebRTCDataChannelEvent? {
        let readIDResult = consumerState.withLock {
            state -> Result<UInt64, WebRTCError> in
            guard let readID = state.nextReadID else {
                return .failure(.dataChannelEventReadIdentifiersExhausted)
            }
            state.nextReadID = readID == UInt64.max
                ? nil
                : readID + 1
            return .success(readID)
        }
        let readID: UInt64
        switch readIDResult {
        case .success(let value):
            readID = value
        case .failure(let error):
            throw error
        }

        let delivery = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                let immediate = consumerState.withLock {
                    state -> Delivery? in
                    guard state.activeReadID == nil else {
                        return .failure(
                            .dataChannelEventReadAlreadyInProgress
                        )
                    }
                    state.activeReadID = readID
                    if Task.isCancelled {
                        return .failure(.dataChannelEventReadCancelled)
                    }
                    if let event = state.events.popFirst() {
                        return .event(event)
                    }
                    if state.didFinish {
                        if let failure = state.terminalFailure {
                            return .failure(failure)
                        }
                        return .finished
                    }
                    state.waiter = Waiter(
                        readID: readID,
                        continuation: continuation
                    )
                    return nil
                }
                if let immediate {
                    continuation.resume(returning: immediate)
                }
            }
        } onCancel: {
            let continuation = consumerState.withLock {
                state -> CheckedContinuation<Delivery, Never>? in
                guard state.waiter?.readID == readID else { return nil }
                let continuation = state.waiter?.continuation
                state.waiter = nil
                return continuation
            }
            continuation?.resume(returning: .failure(
                .dataChannelEventReadCancelled
            ))
        }

        consumerState.withLock { state in
            if state.activeReadID == readID {
                state.activeReadID = nil
            }
        }
        switch delivery {
        case .event(let event):
            eventBudget.release(event)
            return event
        case .finished:
            return nil
        case .failure(let error):
            throw error
        }
    }

    /// Transfers an event whose payload bytes are already reserved in
    /// `eventBudget`. The caller releases that reservation if this method does
    /// not accept the event.
    func yieldReserved(
        _ event: WebRTCDataChannelEvent,
        from budget: WebRTCDataChannelEventBudget
    ) -> YieldResult {
        precondition(budget === eventBudget)
        let action = consumerState.withLock { state -> YieldAction in
            guard !state.didFinish else {
                return .result(.terminated)
            }
            if let waiter = state.waiter {
                state.waiter = nil
                return .resume(waiter.continuation)
            }
            guard state.events.append(event) else {
                return .result(.dropped)
            }
            return .result(.enqueued)
        }
        switch action {
        case .resume(let continuation):
            continuation.resume(returning: .event(event))
            return .enqueued
        case .result(let result):
            return result
        }
    }

    func finish(failure: WebRTCError? = nil) {
        let continuation = consumerState.withLock {
            state -> CheckedContinuation<Delivery, Never>? in
            guard !state.didFinish else { return nil }
            state.didFinish = true
            state.terminalFailure = failure
            let continuation = state.waiter?.continuation
            state.waiter = nil
            return continuation
        }
        if let failure {
            continuation?.resume(returning: .failure(failure))
        } else {
            continuation?.resume(returning: .finished)
        }
    }

    func discardRemainingEvents() {
        let cleanup = consumerState.withLock {
            state -> (
                events: [WebRTCDataChannelEvent],
                continuation: CheckedContinuation<Delivery, Never>?,
                failure: WebRTCError?
            ) in
            state.didFinish = true
            let events = state.events.drain()
            let continuation = state.waiter?.continuation
            state.waiter = nil
            return (events, continuation, state.terminalFailure)
        }

        eventBudget.release(cleanup.events)
        if let failure = cleanup.failure {
            cleanup.continuation?.resume(returning: .failure(failure))
        } else {
            cleanup.continuation?.resume(returning: .finished)
        }
    }

    var hasPendingRead: Bool {
        consumerState.withLock { $0.waiter != nil }
    }
}
