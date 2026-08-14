import NetworkingTime
import Synchronization
import Testing
@testable import WebRTC
@Suite("WebRTC Timer Driver Tests")
struct WebRTCTimerTests {
    @Test("Type erasure preserves both clock readings and the sleep deadline")
    func forwardsClockAndDeadline() async throws {
        let backend = RecordingTimerBackend()
        let timer = WebRTCTimer(backend)

        #expect(try timer.now().nanoseconds == 123)
        try await timer.sleep(
            until: MonotonicInstant(clockIdentifier: 42, nanoseconds: 987)
        )
        #expect(backend.snapshot.deadlines == [987])
    }

    @Test("Type erasure preserves typed cancellation")
    func preservesTypedCancellation() async {
        let backend = RecordingTimerBackend(throwsCancellation: true)
        let timer = WebRTCTimer(backend)

        do {
            try await timer.sleep(
                until: MonotonicInstant(clockIdentifier: 42, nanoseconds: 987)
            )
            Issue.record("Expected typed timer cancellation")
        } catch {
            #expect(backend.snapshot.deadlines == [987])
        }
    }
}

private final class RecordingTimerBackend: AsyncTimer, Sendable {
    struct Snapshot: Sendable {
        var deadlines: [UInt64] = []
    }

    private let state = Mutex(Snapshot())
    private let throwsCancellation: Bool

    init(throwsCancellation: Bool = false) {
        self.throwsCancellation = throwsCancellation
    }

    var snapshot: Snapshot {
        state.withLock { $0 }
    }

    func now() throws(TimeError) -> MonotonicInstant {
        MonotonicInstant(clockIdentifier: 42, nanoseconds: 123)
    }

    func sleep(
        until deadline: MonotonicInstant
    ) async throws(TimeError) {
        guard deadline.clockIdentifier == 42 else {
            throw .clockDomainMismatch(expected: 42, actual: deadline.clockIdentifier)
        }
        state.withLock { $0.deadlines.append(deadline.nanoseconds) }
        if throwsCancellation {
            throw .cancelled
        }
    }
}
