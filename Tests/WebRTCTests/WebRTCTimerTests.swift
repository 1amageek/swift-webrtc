import P2PCoreCrypto
import Synchronization
import Testing
@testable import WebRTC
@Suite("WebRTC Timer Driver Tests")
struct WebRTCTimerTests {
    @Test("Type erasure preserves both clock readings and the sleep deadline")
    func forwardsClockAndDeadline() async throws {
        let backend = RecordingTimerBackend()
        let timer = WebRTCTimer(backend)

        #expect(timer.monotonicNanos() == 123)
        #expect(timer.monotonicMillis() == 45)
        try await timer.sleep(untilNanos: 987)
        #expect(backend.snapshot.deadlines == [987])
    }

    @Test("Type erasure preserves typed cancellation")
    func preservesTypedCancellation() async {
        let backend = RecordingTimerBackend(throwsCancellation: true)
        let timer = WebRTCTimer(backend)

        do {
            try await timer.sleep(untilNanos: 987)
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

    func monotonicNanos() -> UInt64 {
        123
    }

    func monotonicMillis() -> UInt64 {
        45
    }

    func sleep(
        untilNanos deadlineNanos: UInt64
    ) async throws(CancellationError) {
        state.withLock { $0.deadlines.append(deadlineNanos) }
        if throwsCancellation {
            throw CancellationError()
        }
    }
}
