import Foundation
import P2PCoreCrypto
import Synchronization
import Testing
@testable import WebRTC
@Suite("WebRTC DTLS Retransmission Driver Tests")
struct WebRTCDTLSRetransmissionTests {

    @Test(
        "A lost initial ClientHello is retransmitted with a fresh record sequence",
        .timeLimit(.minutes(1))
    )
    func lostInitialClientHelloIsRetransmitted() async throws {
        let clientCertificate = try WebRTCTestIdentity.make()
        let serverCertificate = try WebRTCTestIdentity.make()
        let sent = Mutex<[[UInt8]]>([])
        let connection = try WebRTCConnection.asClient(
            certificate: clientCertificate,
            remoteFingerprint: serverCertificate.fingerprint,
            sendHandler: { datagram in
                sent.withLock { $0.append(datagram) }
                return .success(())
            }
        )
        defer { connection.close() }

        try connection.start()
        #expect(sent.withLock { $0.count } == 1)

        let retransmissionObserved = await waitUntil { sent.withLock { $0.count >= 2 } }
        #expect(retransmissionObserved)
        let flights = sent.withLock { $0 }
        let initial = try #require(flights.first)
        let retransmission = try #require(flights.dropFirst().first)

        #expect(initial.count >= 11)
        #expect(retransmission.count >= 11)
        #expect(Array(initial[5..<11]) != Array(retransmission[5..<11]))
        #expect(connection.state == .dtlsHandshaking)
        #expect(connection.terminalFailure == nil)
    }

    @Test(
        "Transport rejection during a timeout is retained as a typed terminal failure",
        .timeLimit(.minutes(1))
    )
    func retransmissionTransportRejectionIsTerminal() async throws {
        let clientCertificate = try WebRTCTestIdentity.make()
        let serverCertificate = try WebRTCTestIdentity.make()
        let sendCount = Mutex(0)
        let connection = try WebRTCConnection.asClient(
            certificate: clientCertificate,
            remoteFingerprint: serverCertificate.fingerprint,
            sendHandler: { _ in
                let attempt = sendCount.withLock { count -> Int in
                    count += 1
                    return count
                }
                return attempt == 1 ? .success(()) : .failure(.backpressured)
            }
        )
        defer { connection.close() }

        try connection.start()
        let failureObserved = await waitUntil { connection.state.isTerminal }
        #expect(failureObserved)

        #expect(sendCount.withLock { $0 } == 2)
        guard let terminalFailure = connection.terminalFailure else {
            Issue.record("Expected the background send rejection to remain observable")
            return
        }
        guard case .datagramSendFailed(.backpressured) = terminalFailure else {
            Issue.record("Unexpected terminal failure: \(terminalFailure)")
            return
        }
    }

    @Test(
        "Closing before the deadline cancels the initial flight timer",
        .timeLimit(.minutes(1))
    )
    func closeCancelsInitialFlightTimer() async throws {
        let clientCertificate = try WebRTCTestIdentity.make()
        let serverCertificate = try WebRTCTestIdentity.make()
        let sendCount = Mutex(0)
        let connection = try WebRTCConnection.asClient(
            certificate: clientCertificate,
            remoteFingerprint: serverCertificate.fingerprint,
            sendHandler: { _ in
                sendCount.withLock { $0 += 1 }
                return .success(())
            }
        )

        try connection.start()
        connection.close()
        let sendCountAfterClose = sendCount.withLock { $0 }
        try await Task.sleep(for: .milliseconds(1_200))

        #expect(connection.state == .closed)
        #expect(sendCount.withLock { $0 } == sendCountAfterClose)
    }

    @Test(
        "An injected timer parks DTLS scheduling and observes terminal cancellation",
        .timeLimit(.minutes(1))
    )
    func injectedTimerDrivesAndCancelsDTLSScheduling() async throws {
        let clientCertificate = try WebRTCTestIdentity.make()
        let serverCertificate = try WebRTCTestIdentity.make()
        let timer = SuspendingTimerProbe()
        let sendCount = Mutex(0)
        let connection = try WebRTCConnection.asClient(
            certificate: clientCertificate,
            remoteFingerprint: serverCertificate.fingerprint,
            sendHandler: { _ in
                sendCount.withLock { $0 += 1 }
                return .success(())
            },
            timer: WebRTCTimer(timer)
        )

        try connection.start()
        let parked = await waitUntil { timer.snapshot.sleepCount == 1 }
        #expect(parked)
        #expect(timer.snapshot.lastDeadlineNanos == 1_000_000_123)
        let sendCountBeforeClose = sendCount.withLock { $0 }

        connection.close()
        let cancellationObserved = await waitUntil {
            timer.snapshot.cancellationCount == 1
        }

        #expect(cancellationObserved)
        #expect(connection.state == .closed)
        #expect(sendCount.withLock { $0 } == sendCountBeforeClose)
    }

    @Test(
        "A same-generation input preserves the current backed-off deadline",
        .timeLimit(.minutes(1))
    )
    func sameGenerationInputPreservesCurrentDeadline() async throws {
        let clientCertificate = try WebRTCTestIdentity.make()
        let serverCertificate = try WebRTCTestIdentity.make()
        let timer = ControlledTimerProbe()
        let sendCount = Mutex(0)
        let connection = try WebRTCConnection.asClient(
            certificate: clientCertificate,
            remoteFingerprint: serverCertificate.fingerprint,
            sendHandler: { _ in
                sendCount.withLock { $0 += 1 }
                return .success(())
            },
            timer: WebRTCTimer(timer)
        )
        defer { connection.close() }

        try connection.start()
        let firstDeadlineObserved = await waitUntil {
            timer.snapshot.sleepCount == 1
        }
        #expect(firstDeadlineObserved)
        timer.release(sleepOrdinal: 1)
        let secondDeadlineObserved = await waitUntil {
            timer.snapshot.sleepCount == 2
                && sendCount.withLock { $0 } == 2
        }
        #expect(secondDeadlineObserved)
        let backedOffDeadline = try #require(
            timer.snapshot.deadlines.last
        )
        #expect(backedOffDeadline == 2_000_000_123)

        try connection.receive([22])
        for _ in 0..<1_000 {
            await Task.yield()
        }

        #expect(timer.snapshot.sleepCount == 2)
        #expect(timer.snapshot.deadlines.last == backedOffDeadline)
        #expect(timer.snapshot.cancellationCount == 0)
    }

    @Test(
        "Replacing a DTLS timer permits synchronous cancellation re-entry",
        .timeLimit(.minutes(1))
    )
    func timerReplacementCancellationPermitsSynchronousReceiveReentry()
        async throws {
        let clientCertificate = try WebRTCTestIdentity.make()
        let serverCertificate = try WebRTCTestIdentity.make()
        let timer = ReentrantCancellationTimerProbe()
        let clientDatagrams = Mutex<[[UInt8]]>([])
        let serverDatagrams = Mutex<[[UInt8]]>([])
        let deliveryState = Mutex(ReentrantDeliveryState())

        let client = try WebRTCConnection.asClient(
            certificate: clientCertificate,
            remoteFingerprint: serverCertificate.fingerprint,
            sendHandler: { datagram in
                clientDatagrams.withLock { $0.append(datagram) }
                return .success(())
            },
            timer: WebRTCTimer(timer)
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCertificate,
            remoteFingerprint: clientCertificate.fingerprint,
            sendHandler: { datagram in
                serverDatagrams.withLock { $0.append(datagram) }
                return .success(())
            }
        )
        defer {
            timer.clearReentrantCancellation()
            client.close()
            server.close()
        }

        timer.installReentrantCancellation { [weak client] in
            guard let client else { return false }
            do {
                try client.receive([22])
                return true
            } catch {
                return false
            }
        }

        try server.start()
        try client.start()
        let initialTimerParked = await waitUntil {
            timer.snapshot.sleepCount == 1
        }
        #expect(initialTimerParked)

        let clientHello = try #require(
            clientDatagrams.withLock { $0.first }
        )
        try server.receive(clientHello)
        let helloVerification = try #require(
            serverDatagrams.withLock { $0.first }
        )

        let deliveryTask = Task.detached {
            let succeeded: Bool
            do {
                try client.receive(helloVerification)
                succeeded = true
            } catch {
                succeeded = false
            }
            deliveryState.withLock { state in
                state.completed = true
                state.succeeded = succeeded
            }
        }

        let cancellationReentryCompleted = await waitUntil {
            let timerSnapshot = timer.snapshot
            let deliverySnapshot = deliveryState.withLock { $0 }
            return timerSnapshot.reentryCompletionCount == 1
                && deliverySnapshot.completed
                && timerSnapshot.sleepCount == 2
        }
        #expect(cancellationReentryCompleted)

        if cancellationReentryCompleted {
            await deliveryTask.value
        }

        let timerSnapshot = timer.snapshot
        let deliverySnapshot = deliveryState.withLock { $0 }
        #expect(timerSnapshot.cancellationCount == 1)
        #expect(timerSnapshot.reentryStartCount == 1)
        #expect(timerSnapshot.reentryCompletionCount == 1)
        #expect(timerSnapshot.successfulReentryCount == 1)
        #expect(deliverySnapshot.completed)
        #expect(deliverySnapshot.succeeded)
        #expect(!client.state.isTerminal)
        #expect(client.terminalFailure == nil)
    }

    private func waitUntil(
        _ condition: @escaping @Sendable () -> Bool
    ) async -> Bool {
        for _ in 0..<100 {
            if condition() { return true }
            do {
                try await Task.sleep(for: .milliseconds(20))
            } catch {
                return false
            }
        }
        return condition()
    }
}

private struct ReentrantDeliveryState: Sendable {
    var completed = false
    var succeeded = false
}

private final class ReentrantCancellationTimerProbe: AsyncTimer, Sendable {
    struct Snapshot: Sendable {
        var deadlines: [UInt64] = []
        var cancellationCount = 0
        var reentryStartCount = 0
        var reentryCompletionCount = 0
        var successfulReentryCount = 0

        var sleepCount: Int {
            deadlines.count
        }
    }

    private struct State: Sendable {
        var snapshot = Snapshot()
        var reentrantCancellation: (@Sendable () -> Bool)?
    }

    private let state = Mutex(State())

    var snapshot: Snapshot {
        state.withLock { $0.snapshot }
    }

    func installReentrantCancellation(
        _ action: @escaping @Sendable () -> Bool
    ) {
        state.withLock { $0.reentrantCancellation = action }
    }

    func clearReentrantCancellation() {
        state.withLock { $0.reentrantCancellation = nil }
    }

    func monotonicMillis() -> UInt64 {
        0
    }

    func monotonicNanos() -> UInt64 {
        123
    }

    func sleep(
        untilNanos deadlineNanos: UInt64
    ) async throws(CancellationError) {
        state.withLock { $0.snapshot.deadlines.append(deadlineNanos) }
        await withTaskCancellationHandler {
            while !Task.isCancelled {
                await Task.yield()
            }
        } onCancel: {
            runReentrantCancellation()
        }
        throw CancellationError()
    }

    private func runReentrantCancellation() {
        let action = state.withLock {
            state -> (@Sendable () -> Bool)? in
            state.snapshot.cancellationCount += 1
            let current = state.reentrantCancellation
            state.reentrantCancellation = nil
            if current != nil {
                state.snapshot.reentryStartCount += 1
            }
            return current
        }
        guard let action else { return }

        let succeeded = action()
        state.withLock { state in
            state.snapshot.reentryCompletionCount += 1
            if succeeded {
                state.snapshot.successfulReentryCount += 1
            }
        }
    }
}

private final class SuspendingTimerProbe: AsyncTimer, Sendable {
    struct Snapshot: Sendable {
        var sleepCount = 0
        var cancellationCount = 0
        var lastDeadlineNanos: UInt64?
    }

    private let state = Mutex(Snapshot())

    var snapshot: Snapshot {
        state.withLock { $0 }
    }

    func monotonicMillis() -> UInt64 {
        0
    }

    func monotonicNanos() -> UInt64 {
        123
    }

    func sleep(
        untilNanos deadlineNanos: UInt64
    ) async throws(CancellationError) {
        state.withLock { state in
            state.sleepCount += 1
            state.lastDeadlineNanos = deadlineNanos
        }
        while !Task.isCancelled {
            await Task.yield()
        }
        state.withLock { $0.cancellationCount += 1 }
        throw CancellationError()
    }
}

private final class ControlledTimerProbe: AsyncTimer, Sendable {
    struct Snapshot: Sendable {
        var deadlines: [UInt64] = []
        var cancellationCount = 0

        var sleepCount: Int {
            deadlines.count
        }
    }

    private struct State: Sendable {
        var snapshot = Snapshot()
        var releasedSleepOrdinals: Set<Int> = []
    }

    private let state = Mutex(State())

    var snapshot: Snapshot {
        state.withLock { $0.snapshot }
    }

    func release(sleepOrdinal: Int) {
        _ = state.withLock {
            $0.releasedSleepOrdinals.insert(sleepOrdinal)
        }
    }

    func monotonicMillis() -> UInt64 {
        0
    }

    func monotonicNanos() -> UInt64 {
        123
    }

    func sleep(
        untilNanos deadlineNanos: UInt64
    ) async throws(CancellationError) {
        let sleepOrdinal = state.withLock { state -> Int in
            state.snapshot.deadlines.append(deadlineNanos)
            return state.snapshot.deadlines.count
        }
        while true {
            if Task.isCancelled {
                state.withLock { $0.snapshot.cancellationCount += 1 }
                throw CancellationError()
            }
            if state.withLock({
                $0.releasedSleepOrdinals.contains(sleepOrdinal)
            }) {
                return
            }
            await Task.yield()
        }
    }
}
