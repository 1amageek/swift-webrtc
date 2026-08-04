/// Loopback test for the WebRTC DTLS handshake driven over the swift-tls Tier-1
/// `DTLSClient`/`DTLSServer` facade.
///
/// The handshake is pumped manually between client and server connections without
/// any transport layer (no NIO/UDP).
///
/// ## DTLS-SRTP peer authentication (now wired)
///
/// WebRTC's DTLS-SRTP peer authentication binds the peer's leaf-certificate
/// fingerprint to the value advertised in signaling. The swift-tls Tier-1 DTLS
/// facade now surfaces the peer's leaf certificate after the handshake
/// (`DTLSClient`/`DTLSServer.remoteCertificateDER`), so `WebRTCConnection`
/// computes the SHA-256 fingerprint and verifies it against the expected value:
///
/// - A MATCHING expected fingerprint → the handshake completes (authenticated).
/// - A MISMATCHED or ABSENT peer certificate → the verifier fails CLOSED; the
///   client never reaches `.connected`. That fail-closed contract is the security
///   regression guard proving we NEVER accept an unverified peer.

import Testing
import Foundation
import Synchronization
@testable import WebRTC

@Suite("WebRTC Loopback Tests")
struct WebRTCLoopbackTests {

    private final class ManualSCTPClock: SCTPMonotonicClock {
        private let milliseconds = Mutex<UInt64>(0)

        func currentMilliseconds() throws(SCTPError) -> UInt64 {
            milliseconds.withLock { $0 }
        }

        func setMilliseconds(_ value: UInt64) {
            milliseconds.withLock { $0 = value }
        }
    }

    private struct ShutdownGuardSendState: Sendable {
        var isFinalPhase = false
        var rejectFinalDatagram = false
        var finalAttemptCount = 0
        var acceptedFinalDatagramCount = 0
    }

    private struct LifecycleGateState: Sendable {
        var isArmed = false
        var didEnter = false
        var isReleased = false
    }

    private final class LifecycleGate: Sendable {
        private let state = Mutex(LifecycleGateState())

        func arm() {
            state.withLock { value in
                value.isArmed = true
                value.didEnter = false
                value.isReleased = false
            }
        }

        func checkpoint() {
            let shouldWait = state.withLock { value -> Bool in
                guard value.isArmed else { return false }
                value.isArmed = false
                value.didEnter = true
                return true
            }
            guard shouldWait else { return }
            while !state.withLock({ $0.isReleased }) {
                Thread.sleep(forTimeInterval: 0.0005)
            }
        }

        var didEnter: Bool {
            state.withLock { $0.didEnter }
        }

        func release() {
            state.withLock { $0.isReleased = true }
        }
    }

    private struct CallbackCloseState: Sendable {
        var connection: WebRTCConnection?
        var isArmed = false
        var admittedDatagramCount = 0
    }

    private struct BatchRejectionState: Sendable {
        var isArmed = false
        var attemptCount = 0
    }

    private struct EventConsumerTerminationState: Sendable {
        var consumer: WebRTCDataChannelEventConsumer?
        var isArmed = false
    }

    private enum ObservedDataChannelEvent: Equatable, Sendable {
        case opened(channelID: UInt16, direction: WebRTCDataChannelDirection)
        case message(channelID: UInt16, generation: UInt64, payload: [UInt8])
        case closed(channelID: UInt16)
        case closeFailed(channelID: UInt16)
    }

    private func eventsThroughClose(
        from consumer: any WebRTCDataChannelEventConsuming
    ) async throws(WebRTCError) -> [ObservedDataChannelEvent] {
        var observed: [ObservedDataChannelEvent] = []
        while let event = try await consumer.next() {
            switch event {
            case .opened(let channel, let direction):
                observed.append(.opened(
                    channelID: channel.id,
                    direction: direction
                ))
            case .message(let channelID, let generation, let payload):
                observed.append(.message(
                    channelID: channelID,
                    generation: generation,
                    payload: payload
                ))
            case .closed(.closed(let channelID, _)):
                observed.append(.closed(channelID: channelID))
                return observed
            case .closed(.failed(let channelID, _, _)):
                observed.append(.closeFailed(channelID: channelID))
                return observed
            }
        }
        return observed
    }

    /// Pumps the full DTLS handshake flights between a client and server until
    /// both settle or the round budget is exhausted. Returns whether the client
    /// failed closed with a `dtlsHandshakeFailed` error.
    private func pumpHandshake(
        client: WebRTCConnection,
        server: WebRTCConnection,
        clientOutbox: borrowing Mutex<[Data]>,
        serverOutbox: borrowing Mutex<[Data]>
    ) -> (clientFailedClosed: Bool, serverFailedClosed: Bool) {
        var clientFailedClosed = false
        var serverFailedClosed = false
        rounds: for _ in 0..<20 {
            let toServer = clientOutbox.withLock { msgs -> [Data] in
                let copy = msgs; msgs.removeAll(); return copy
            }
            for msg in toServer {
                do {
                    try server.receive(msg)
                } catch {
                    guard case .dtlsHandshakeFailed = error else {
                        Issue.record("Unexpected server failure: \(error)")
                        break rounds
                    }
                    serverFailedClosed = true
                    break rounds
                }
            }

            let toClient = serverOutbox.withLock { msgs -> [Data] in
                let copy = msgs; msgs.removeAll(); return copy
            }
            for msg in toClient {
                do {
                    try client.receive(msg)
                } catch {
                    guard case .dtlsHandshakeFailed = error else {
                        Issue.record("Unexpected client failure: \(error)")
                        break rounds
                    }
                    clientFailedClosed = true
                    break rounds
                }
            }

            if client.state == .connected {
                break
            }
            if toServer.isEmpty && toClient.isEmpty {
                break
            }
        }
        return (clientFailedClosed, serverFailedClosed)
    }

    /// Drain all currently queued DTLS datagrams in both directions.
    private func pumpTraffic(
        client: WebRTCConnection,
        server: WebRTCConnection,
        clientOutbox: borrowing Mutex<[Data]>,
        serverOutbox: borrowing Mutex<[Data]>
    ) throws {
        for _ in 0..<40 {
            let toServer = clientOutbox.withLock { messages -> [Data] in
                let drained = messages
                messages.removeAll(keepingCapacity: true)
                return drained
            }
            for message in toServer {
                // A real transport owner unregisters a terminal connection and
                // drops datagrams that were already queued for its old tuple.
                // Preserve `receive`'s explicit `.closed` contract while making
                // this loopback router model that ownership boundary.
                if !server.state.isTerminal {
                    try server.receive(message)
                }
            }

            let toClient = serverOutbox.withLock { messages -> [Data] in
                let drained = messages
                messages.removeAll(keepingCapacity: true)
                return drained
            }
            for message in toClient {
                if !client.state.isTerminal {
                    try client.receive(message)
                }
            }

            if toServer.isEmpty && toClient.isEmpty {
                return
            }
        }
        Issue.record("Loopback datagrams did not quiesce within the round budget")
    }

    private func waitForTerminalFailure(
        _ connection: WebRTCConnection
    ) async throws {
        for _ in 0..<100 {
            if connection.terminalFailure != nil { return }
            try await Task.sleep(for: .milliseconds(20))
        }
        Issue.record("Connection did not become terminal within the wait budget")
    }

    private func waitForCheckpoint(_ gate: LifecycleGate) async throws {
        for _ in 0..<1_000 {
            if gate.didEnter { return }
            try await Task.sleep(for: .milliseconds(1))
        }
        Issue.record("Lifecycle checkpoint did not run within the wait budget")
    }

    private func verifyShutdownGuardFinalAbort(
        rejectingFinalDatagram: Bool
    ) async throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        let clientClock = ManualSCTPClock()
        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])
        let sendState = Mutex(ShutdownGuardSendState())

        let client = try WebRTCConnection(
            certificate: clientCert,
            isClient: true,
            expectedFingerprint: serverCert.fingerprint,
            mediaConfiguration: nil,
            sendHandler: { bytes in
                let shouldReject = sendState.withLock { state -> Bool in
                    guard state.isFinalPhase else { return false }
                    state.finalAttemptCount += 1
                    if !state.rejectFinalDatagram {
                        state.acceptedFinalDatagramCount += 1
                    }
                    return state.rejectFinalDatagram
                }
                if shouldReject {
                    return .failure(.transportUnavailable)
                }
                clientOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            },
            logger: WebRTCLogger(label: "webrtc.shutdown-guard.client"),
            sctpClock: clientClock
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCert,
            remoteFingerprint: clientCert.fingerprint,
            sendHandler: { bytes in
                serverOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        defer {
            client.close()
            server.close()
        }

        try server.start()
        try client.start()
        _ = pumpHandshake(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        #expect(client.state == .connected)
        #expect(server.state == .connected)

        try client.shutdown()
        #expect(client.state == .closing)
        clientOutbox.withLock { $0.removeAll(keepingCapacity: true) }
        sendState.withLock { state in
            state.isFinalPhase = true
            state.rejectFinalDatagram = rejectingFinalDatagram
        }

        // RFC 9260 T5 is an absolute 5 × RTO.Max guard. The configured
        // RTO.Max is 60 seconds, so the exact terminal boundary is 300 seconds.
        clientClock.setMilliseconds(300_000)
        try await waitForTerminalFailure(client)
        try await Task.sleep(for: .milliseconds(300))

        guard case .sctpProtocolFailed(.shutdownGuardTimeout)? =
                client.terminalFailure else {
            Issue.record("Expected the original SCTP shutdown guard failure")
            return
        }
        let finalSendState = sendState.withLock { $0 }
        #expect(finalSendState.finalAttemptCount == 1)
        #expect(
            finalSendState.acceptedFinalDatagramCount
                == (rejectingFinalDatagram ? 0 : 1)
        )

        let snapshot = client.egressDebugSnapshot
        #expect(snapshot.isTerminal)
        #expect(snapshot.inFlightCount == 0)
        #expect(!snapshot.hasReservedTerminalBatch)
        #expect(snapshot.isOwnerTeardownComplete)
        #expect(snapshot.areEventsFinished)
        #expect(snapshot.isNetworkTeardownComplete)

        let finalDatagrams = clientOutbox.withLock { messages -> [Data] in
            let drained = messages
            messages.removeAll(keepingCapacity: true)
            return drained
        }
        if rejectingFinalDatagram {
            #expect(finalDatagrams.isEmpty)
            guard case .sctpProtocolFailed(.shutdownGuardTimeout)? =
                    client.terminalFailure else {
                Issue.record("Transport rejection replaced the protocol cause")
                return
            }
        } else {
            #expect(finalDatagrams.count == 1)
            var observedAbort = false
            for datagram in finalDatagrams {
                do {
                    try server.receive(datagram)
                } catch WebRTCError.sctpProtocolFailed(let error) {
                    guard case .associationAborted = error else {
                        Issue.record("Unexpected SCTP terminal error: \(error)")
                        continue
                    }
                    observedAbort = true
                } catch {
                    Issue.record("Unexpected final datagram failure: \(error)")
                }
            }
            #expect(observedAbort)
            guard case .sctpProtocolFailed(.associationAborted)? =
                    server.terminalFailure else {
                Issue.record("Peer did not observe the final SCTP ABORT")
                return
            }
        }
    }

    /// With the expected fingerprint set to the server's actual certificate
    /// fingerprint, the authenticated DTLS-SRTP handshake now COMPLETES: the
    /// facade surfaces the server's peer certificate, the client computes the
    /// SHA-256 fingerprint, it matches, and the client reaches `.connected`.
    @Test("Client completes the authenticated DTLS-SRTP handshake when the fingerprint matches", .timeLimit(.minutes(1)))
    func clientVerifiesMatchingFingerprint() throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()

        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])

        let client = try WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: serverCert.fingerprint,
            sendHandler: { data in
                clientOutbox.withLock { $0.append(Data(data)) }
                return .success(())
            }
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCert,
            sendHandler: { data in
                serverOutbox.withLock { $0.append(Data(data)) }
                return .success(())
            }
        )

        try server.start()
        try client.start()
        #expect(client.state == .dtlsHandshaking)
        #expect(server.state == .dtlsHandshaking)
        #expect(client.remoteCertificateDER == nil)

        let result = pumpHandshake(
            client: client, server: server,
            clientOutbox: clientOutbox, serverOutbox: serverOutbox
        )
        #expect(result.clientFailedClosed == false)
        #expect(result.serverFailedClosed == false)

        // The authenticated handshake completes and the verified fingerprint is
        // recorded — matching the value advertised in signaling.
        #expect(client.state == .connected)
        #expect(client.remoteFingerprint == serverCert.fingerprint)
        #expect(client.remoteCertificateDER == serverCert.derEncoded)

        client.close()
        #expect(client.remoteCertificateDER == serverCert.derEncoded)
        server.close()
    }

    @Test(
        "The periodic SCTP driver does not retain an established connection",
        .timeLimit(.minutes(1))
    )
    func establishedRetransmissionDriverDoesNotRetainConnection() async throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])
        let server = try WebRTCConnection.asServer(
            certificate: serverCert,
            remoteFingerprint: clientCert.fingerprint,
            sendHandler: { bytes in
                serverOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        defer { server.close() }

        weak var releasedClient: WebRTCConnection?
        do {
            let client = try WebRTCConnection.asClient(
                certificate: clientCert,
                remoteFingerprint: serverCert.fingerprint,
                sendHandler: { bytes in
                    clientOutbox.withLock { $0.append(Data(bytes)) }
                    return .success(())
                }
            )
            releasedClient = client

            try server.start()
            try client.start()
            let result = pumpHandshake(
                client: client,
                server: server,
                clientOutbox: clientOutbox,
                serverOutbox: serverOutbox
            )
            #expect(!result.clientFailedClosed)
            #expect(!result.serverFailedClosed)
            try pumpTraffic(
                client: client,
                server: server,
                clientOutbox: clientOutbox,
                serverOutbox: serverOutbox
            )
            #expect(client.state == .connected)
            #expect(server.state == .connected)
        }

        for _ in 0..<1_000 {
            if releasedClient == nil {
                break
            }
            await Task.yield()
        }
        #expect(releasedClient == nil)
    }

    @Test(
        "A pending DTLS timeout does not retain an abandoned connection",
        .timeLimit(.minutes(1))
    )
    func pendingDTLSTimeoutDoesNotRetainConnection() async throws {
        let clientCert = try WebRTCTestIdentity.make()
        let remoteCert = try WebRTCTestIdentity.make()
        let outbox = Mutex<[[UInt8]]>([])

        weak var releasedClient: WebRTCConnection?
        do {
            let client = try WebRTCConnection.asClient(
                certificate: clientCert,
                remoteFingerprint: remoteCert.fingerprint,
                sendHandler: { datagram in
                    outbox.withLock { $0.append(datagram) }
                    return .success(())
                }
            )
            releasedClient = client
            try client.start()
            #expect(client.state == .dtlsHandshaking)
            #expect(outbox.withLock { $0.count } == 1)
        }

        for _ in 0..<1_000 {
            if releasedClient == nil {
                break
            }
            await Task.yield()
        }
        #expect(releasedClient == nil)

        try await Task.sleep(for: .milliseconds(1_200))
        #expect(outbox.withLock { $0.count } == 1)
    }

    @Test(
        "A concurrent close fences the handshake commit and SCTP INIT",
        .timeLimit(.minutes(1))
    )
    func closeFencesHandshakeCommit() async throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])
        let handshakeGate = LifecycleGate()

        let client = try WebRTCConnection(
            certificate: clientCert,
            isClient: true,
            expectedFingerprint: serverCert.fingerprint,
            mediaConfiguration: nil,
            sendHandler: { bytes in
                clientOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            },
            logger: WebRTCLogger(label: "webrtc.handshake-fence.client"),
            lifecycleHooks: WebRTCLifecycleHooks(
                beforeHandshakeCommit: { handshakeGate.checkpoint() }
            )
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCert,
            remoteFingerprint: clientCert.fingerprint,
            sendHandler: { bytes in
                serverOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        defer {
            client.close()
            server.close()
        }

        try server.start()
        try client.start()
        handshakeGate.arm()
        let pumpTask = Task { () -> WebRTCError? in
            for _ in 0..<20 {
                let toServer = clientOutbox.withLock { messages -> [Data] in
                    let drained = messages
                    messages.removeAll(keepingCapacity: true)
                    return drained
                }
                for message in toServer {
                    switch Result<Void, WebRTCError>(
                        catching: { () throws(WebRTCError) in
                            try server.receive(message)
                        }
                    ) {
                    case .success:
                        break
                    case .failure(let error):
                        return error
                    }
                }

                let toClient = serverOutbox.withLock { messages -> [Data] in
                    let drained = messages
                    messages.removeAll(keepingCapacity: true)
                    return drained
                }
                for message in toClient {
                    switch Result<Void, WebRTCError>(
                        catching: { () throws(WebRTCError) in
                            try client.receive(message)
                        }
                    ) {
                    case .success:
                        break
                    case .failure(let error):
                        return error
                    }
                }
                if toServer.isEmpty && toClient.isEmpty { return nil }
            }
            return .timeout
        }

        try await waitForCheckpoint(handshakeGate)
        #expect(handshakeGate.didEnter)
        let emittedBeforeClose = clientOutbox.withLock { $0.count }
        client.close()

        let duringCheckpoint = client.egressDebugSnapshot
        #expect(duringCheckpoint.isTerminal)
        #expect(duringCheckpoint.inFlightCount == 1)
        #expect(duringCheckpoint.isOwnerTeardownComplete)
        #expect(duringCheckpoint.areEventsFinished)
        #expect(!duringCheckpoint.isNetworkTeardownComplete)

        handshakeGate.release()
        let pumpFailure = await pumpTask.value
        guard case .closed? = pumpFailure else {
            Issue.record("Expected the handshake path to observe the clean close")
            return
        }

        #expect(client.state == .closed)
        #expect(client.terminalFailure == nil)
        #expect(client.remoteFingerprint == nil)
        #expect(!client.isMediaReady)
        #expect(clientOutbox.withLock { $0.count } == emittedBeforeClose)
        let afterCheckpoint = client.egressDebugSnapshot
        #expect(afterCheckpoint.inFlightCount == 0)
        #expect(afterCheckpoint.isNetworkTeardownComplete)
    }

    @Test("Graceful SCTP shutdown closes both WebRTC peers", .timeLimit(.minutes(1)))
    func gracefulShutdownRoundTrip() throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])

        let client = try WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: serverCert.fingerprint,
            sendHandler: { bytes in
                clientOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCert,
            remoteFingerprint: clientCert.fingerprint,
            sendHandler: { bytes in
                serverOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )

        try server.start()
        try client.start()
        _ = pumpHandshake(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        #expect(client.state == .connected)
        #expect(server.state == .connected)

        try client.shutdown()
        #expect(client.state == .closing)
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )

        #expect(client.state == .closed)
        #expect(server.state == .closed)
        #expect(client.terminalFailure == nil)
        #expect(server.terminalFailure == nil)
        try client.shutdown()
        try server.shutdown()
    }

    @Test(
        "T5 emits one final SCTP ABORT before transport teardown",
        .timeLimit(.minutes(1))
    )
    func shutdownGuardEmitsFinalAbort() async throws {
        try await verifyShutdownGuardFinalAbort(
            rejectingFinalDatagram: false
        )
    }

    @Test(
        "A rejected final ABORT preserves the T5 cause and releases its lease",
        .timeLimit(.minutes(1))
    )
    func rejectedShutdownGuardAbortPreservesProtocolFailure() async throws {
        try await verifyShutdownGuardFinalAbort(
            rejectingFinalDatagram: true
        )
    }

    @Test(
        "An admitted SCTP receive cannot invalidate the final T5 ABORT",
        .timeLimit(.minutes(1))
    )
    func admittedReceivePreservesFinalShutdownGuardAbort() async throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        let clientClock = ManualSCTPClock()
        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])
        let sendState = Mutex(ShutdownGuardSendState())
        let sctpGate = LifecycleGate()

        let client = try WebRTCConnection(
            certificate: clientCert,
            isClient: true,
            expectedFingerprint: serverCert.fingerprint,
            mediaConfiguration: nil,
            sendHandler: { bytes in
                sendState.withLock { state in
                    if state.isFinalPhase {
                        state.finalAttemptCount += 1
                        state.acceptedFinalDatagramCount += 1
                    }
                }
                clientOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            },
            logger: WebRTCLogger(label: "webrtc.shutdown-race.client"),
            sctpClock: clientClock,
            lifecycleHooks: WebRTCLifecycleHooks(
                beforeSCTPTransaction: { sctpGate.checkpoint() }
            )
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCert,
            remoteFingerprint: clientCert.fingerprint,
            sendHandler: { bytes in
                serverOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        defer {
            sctpGate.release()
            client.close()
            server.close()
        }

        try server.start()
        try client.start()
        _ = pumpHandshake(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        let channel = try client.openDataChannel(label: "shutdown-race")
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        #expect(client.state == .connected)
        #expect(server.state == .connected)

        try server.send([0x01], on: channel.id)
        let admittedDatagrams = serverOutbox.withLock {
            messages -> [Data] in
            let drained = messages
            messages.removeAll(keepingCapacity: true)
            return drained
        }
        #expect(!admittedDatagrams.isEmpty)

        sctpGate.arm()
        let receiveTask = Task { () -> WebRTCError? in
            for datagram in admittedDatagrams {
                switch Result<Void, WebRTCError>(
                    catching: { () throws(WebRTCError) in
                        try client.receive(datagram)
                    }
                ) {
                case .success:
                    break
                case .failure(let error):
                    return error
                }
            }
            return nil
        }
        try await waitForCheckpoint(sctpGate)
        #expect(sctpGate.didEnter)

        try client.shutdown()
        clientOutbox.withLock { $0.removeAll(keepingCapacity: true) }
        sendState.withLock { state in
            state.isFinalPhase = true
            state.finalAttemptCount = 0
            state.acceptedFinalDatagramCount = 0
        }
        clientClock.setMilliseconds(300_000)
        try await waitForTerminalFailure(client)

        // The terminal cause is committed before the reserved ABORT is handed
        // to the transport. Wait for that already-running terminal owner to
        // consume its reservation before inspecting the paused receive lease.
        for _ in 0..<100 {
            let snapshot = client.egressDebugSnapshot
            if !snapshot.hasReservedTerminalBatch,
               snapshot.inFlightCount == 1 {
                break
            }
            try await Task.sleep(for: .milliseconds(5))
        }

        let whileReceiveIsPaused = client.egressDebugSnapshot
        #expect(whileReceiveIsPaused.isTerminal)
        #expect(whileReceiveIsPaused.inFlightCount == 1)
        #expect(!whileReceiveIsPaused.hasReservedTerminalBatch)
        #expect(!whileReceiveIsPaused.isNetworkTeardownComplete)
        #expect(sendState.withLock { $0.finalAttemptCount } == 1)
        #expect(sendState.withLock { $0.acceptedFinalDatagramCount } == 1)

        sctpGate.release()
        guard case .sctpProtocolFailed(.shutdownGuardTimeout)? =
                await receiveTask.value else {
            Issue.record("Expected the admitted receive to observe the T5 cause")
            return
        }
        try await Task.sleep(for: .milliseconds(20))

        let finalDatagrams = clientOutbox.withLock { messages -> [Data] in
            let drained = messages
            messages.removeAll(keepingCapacity: true)
            return drained
        }
        #expect(finalDatagrams.count == 1)
        #expect(sendState.withLock { $0.finalAttemptCount } == 1)

        let afterReceive = client.egressDebugSnapshot
        #expect(afterReceive.inFlightCount == 0)
        #expect(!afterReceive.hasReservedTerminalBatch)
        #expect(afterReceive.areEventsFinished)
        #expect(afterReceive.isNetworkTeardownComplete)

        for datagram in finalDatagrams {
            do {
                try server.receive(datagram)
            } catch WebRTCError.sctpProtocolFailed(let error) {
                guard case .associationAborted = error else {
                    Issue.record("Unexpected peer SCTP failure: \(error)")
                    return
                }
            } catch {
                Issue.record("Unexpected final ABORT delivery failure: \(error)")
            }
        }
        guard case .sctpProtocolFailed(.associationAborted)? =
                server.terminalFailure else {
            Issue.record("The peer did not observe the unique final ABORT")
            return
        }
    }

    @Test("Simultaneous graceful shutdown closes both WebRTC peers", .timeLimit(.minutes(1)))
    func simultaneousGracefulShutdown() throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])

        let client = try WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: serverCert.fingerprint,
            sendHandler: { bytes in
                clientOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCert,
            remoteFingerprint: clientCert.fingerprint,
            sendHandler: { bytes in
                serverOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )

        try server.start()
        try client.start()
        _ = pumpHandshake(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )

        try client.shutdown()
        try server.shutdown()
        #expect(client.state == .closing)
        #expect(server.state == .closing)
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )

        #expect(client.state == .closed)
        #expect(server.state == .closed)
        #expect(client.terminalFailure == nil)
        #expect(server.terminalFailure == nil)
    }

    @Test("A synchronous send callback close suppresses the remaining SCTP batch", .timeLimit(.minutes(1)))
    func callbackCloseSuppressesRemainingSCTPBatch() throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])
        let callbackCloseState = Mutex(CallbackCloseState())

        let client = try WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: serverCert.fingerprint,
            sendHandler: { bytes in
                clientOutbox.withLock { $0.append(Data(bytes)) }
                let connection: WebRTCConnection? = callbackCloseState.withLock { state in
                    guard state.isArmed else { return nil }
                    state.admittedDatagramCount += 1
                    guard state.admittedDatagramCount == 1 else { return nil }
                    return state.connection
                }
                connection?.close()
                return .success(())
            }
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCert,
            remoteFingerprint: clientCert.fingerprint,
            sendHandler: { bytes in
                serverOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        callbackCloseState.withLock { $0.connection = client }

        try server.start()
        try client.start()
        _ = pumpHandshake(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )

        let channel = try client.openDataChannel(label: "callback-close")
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        callbackCloseState.withLock { state in
            state.isArmed = true
            state.admittedDatagramCount = 0
        }

        // This payload spans several SCTP packets. The first transport callback
        // hard-closes the connection; the per-packet epoch check must suppress
        // every packet in the already-prepared batch after that callback.
        try client.send([UInt8](repeating: 0x5A, count: 5_000), on: channel.id)

        #expect(client.state == .closed)
        #expect(callbackCloseState.withLock { $0.admittedDatagramCount } == 1)
        #expect(clientOutbox.withLock { $0.count } == 1)
        server.close()
    }

    @Test(
        "A second SCTP packet rejection remains a typed terminal failure",
        .timeLimit(.minutes(1))
    )
    func secondSCTPPacketRejectionIsTerminal() throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])
        let rejectionState = Mutex(BatchRejectionState())

        let client = try WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: serverCert.fingerprint,
            sendHandler: { bytes in
                let attempt = rejectionState.withLock { state -> Int? in
                    guard state.isArmed else { return nil }
                    state.attemptCount += 1
                    return state.attemptCount
                }
                if attempt == 2 {
                    return .failure(.backpressured)
                }
                clientOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCert,
            remoteFingerprint: clientCert.fingerprint,
            sendHandler: { bytes in
                serverOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        defer {
            client.close()
            server.close()
        }

        try server.start()
        try client.start()
        _ = pumpHandshake(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        let channel = try client.openDataChannel(label: "second-rejection")
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        rejectionState.withLock { state in
            state.isArmed = true
            state.attemptCount = 0
        }

        do {
            try client.send(
                [UInt8](repeating: 0xA5, count: 5_000),
                on: channel.id
            )
            Issue.record("Expected the second transport admission to fail")
        } catch WebRTCError.datagramSendFailed(let failure) {
            #expect(failure == .backpressured)
        } catch {
            Issue.record("Unexpected send failure: \(error)")
        }

        #expect(rejectionState.withLock { $0.attemptCount } == 2)
        #expect(client.state.isTerminal)
        guard case .datagramSendFailed(.backpressured)? =
                client.terminalFailure else {
            Issue.record("Expected the second-packet backpressure as terminal cause")
            return
        }
    }

    /// With an expected fingerprint that does NOT match the server's certificate,
    /// the verifier fails CLOSED at handshake completion. The client must NOT
    /// reach `.connected` — accepting an unverified peer would be a security
    /// regression.
    @Test("Client fingerprint verification fails closed on a mismatch", .timeLimit(.minutes(1)))
    func clientFingerprintFailsClosedOnMismatch() throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        // An expected fingerprint that the server's real certificate cannot match.
        let bogusFingerprint = CertificateFingerprint.fromDER(Data(repeating: 0x5A, count: 64))
        #expect(bogusFingerprint != serverCert.fingerprint)

        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])

        let client = try WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: bogusFingerprint,
            sendHandler: { data in
                clientOutbox.withLock { $0.append(Data(data)) }
                return .success(())
            }
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCert,
            sendHandler: { data in
                serverOutbox.withLock { $0.append(Data(data)) }
                return .success(())
            }
        )

        try server.start()
        try client.start()
        #expect(client.state == .dtlsHandshaking)
        #expect(server.state == .dtlsHandshaking)

        let result = pumpHandshake(
            client: client, server: server,
            clientOutbox: clientOutbox, serverOutbox: serverOutbox
        )

        #expect(result.clientFailedClosed)
        // Fail-closed: the client never claims a connection it cannot authenticate.
        #expect(client.state != .connected)
        #expect(client.remoteFingerprint == nil)
    }

    @Test("Data channel close performs reciprocal SCTP resets before ID reuse", .timeLimit(.minutes(1)))
    func dataChannelCloseRoundTrip() async throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])

        let client = try WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: serverCert.fingerprint,
            sendHandler: { bytes in
                clientOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCert,
            remoteFingerprint: clientCert.fingerprint,
            sendHandler: { bytes in
                serverOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        let clientEvents = try client.claimDataChannelEvents()
        let serverEvents = try server.claimDataChannelEvents()
        let clientEventsThroughClose = Task {
            try await eventsThroughClose(from: clientEvents)
        }
        let serverEventsThroughClose = Task {
            try await eventsThroughClose(from: serverEvents)
        }

        try server.start()
        try client.start()
        _ = pumpHandshake(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        #expect(client.state == .connected)
        #expect(server.state == .connected)

        let channel = try client.openDataChannel(label: "close-round-trip")
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )

        let payload: [UInt8] = [1, 2, 3]
        try client.send(payload, on: channel.id)
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )

        try client.closeDataChannel(channel.id)
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )

        #expect(throws: WebRTCError.self) {
            try client.send([1], on: channel.id)
        }

        let reused = try client.openDataChannel(label: "reused")
        #expect(reused.id == channel.id)

        // The channel close event is part of the ordered event contract. Await
        // it before terminating the connection so connection shutdown cannot
        // legitimately drain an event that this assertion is meant to observe.
        let clientObserved = try await clientEventsThroughClose.value
        let serverObserved = try await serverEventsThroughClose.value
        client.close()
        server.close()
        #expect(clientObserved == [
            .opened(channelID: channel.id, direction: .local),
            .closed(channelID: channel.id),
        ])
        #expect(serverObserved == [
            .opened(channelID: channel.id, direction: .remote),
            .message(
                channelID: channel.id,
                generation: channel.generation,
                payload: payload
            ),
            .closed(channelID: channel.id),
        ])
    }

    @Test(
        "Terminal teardown waits for an active DataChannel event handoff",
        .timeLimit(.minutes(1))
    )
    func terminalTeardownWaitsForActiveEventDrain() async throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])
        let eventGate = LifecycleGate()

        let client = try WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: serverCert.fingerprint,
            sendHandler: { bytes in
                clientOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        let server = try WebRTCConnection(
            certificate: serverCert,
            isClient: false,
            expectedFingerprint: clientCert.fingerprint,
            mediaConfiguration: nil,
            sendHandler: { bytes in
                serverOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            },
            logger: WebRTCLogger(label: "webrtc.event-drain.server"),
            lifecycleHooks: WebRTCLifecycleHooks(
                beforeDataChannelEventHandoff: { eventGate.checkpoint() }
            )
        )
        let serverEvents = try server.claimDataChannelEvents()
        defer {
            eventGate.release()
            client.close()
            server.close()
        }

        try server.start()
        try client.start()
        _ = pumpHandshake(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        let channel = try client.openDataChannel(label: "event-drain-race")
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        guard case .opened(let opened, .remote)? =
                try await serverEvents.next() else {
            Issue.record("Expected the remote DataChannel OPEN event")
            return
        }
        #expect(opened.id == channel.id)

        let payload: [UInt8] = [0x10, 0x20, 0x30]
        eventGate.arm()
        try client.send(payload, on: channel.id)
        let inbound = clientOutbox.withLock { messages -> [Data] in
            let drained = messages
            messages.removeAll(keepingCapacity: true)
            return drained
        }
        #expect(!inbound.isEmpty)
        let receiveTask = Task { () -> WebRTCError? in
            for datagram in inbound {
                switch Result<Void, WebRTCError>(
                    catching: { () throws(WebRTCError) in
                        try server.receive(datagram)
                    }
                ) {
                case .success:
                    break
                case .failure(let error):
                    return error
                }
            }
            return nil
        }

        try await waitForCheckpoint(eventGate)
        #expect(eventGate.didEnter)
        server.close()

        let whileHandoffIsBlocked = server.egressDebugSnapshot
        #expect(whileHandoffIsBlocked.isTerminal)
        #expect(whileHandoffIsBlocked.inFlightCount == 1)
        #expect(whileHandoffIsBlocked.isOwnerTeardownComplete)
        #expect(!whileHandoffIsBlocked.areEventsFinished)
        #expect(!whileHandoffIsBlocked.isNetworkTeardownComplete)

        eventGate.release()
        if let receiveFailure = await receiveTask.value {
            guard case .closed = receiveFailure else {
                Issue.record("Unexpected receive outcome after close: \(receiveFailure)")
                return
            }
        }

        guard case .message(
            let channelID,
            let generation,
            let observedPayload
        )? = try await serverEvents.next() else {
            Issue.record("Expected the committed event before stream completion")
            return
        }
        #expect(channelID == channel.id)
        #expect(generation == channel.generation)
        #expect(observedPayload == payload)
        #expect(try await serverEvents.next() == nil)
        #expect(server.terminalFailure == nil)

        let afterHandoff = server.egressDebugSnapshot
        #expect(afterHandoff.inFlightCount == 0)
        #expect(afterHandoff.areEventsFinished)
        #expect(afterHandoff.isNetworkTeardownComplete)
    }

    @Test(
        "A terminated event consumer releases the drain and network owners",
        .timeLimit(.minutes(1))
    )
    func terminatedEventConsumerCompletesTeardown() async throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])
        let terminationState = Mutex(EventConsumerTerminationState())

        let client = try WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: serverCert.fingerprint,
            sendHandler: { bytes in
                clientOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        let server = try WebRTCConnection(
            certificate: serverCert,
            isClient: false,
            expectedFingerprint: clientCert.fingerprint,
            mediaConfiguration: nil,
            sendHandler: { bytes in
                serverOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            },
            logger: WebRTCLogger(label: "webrtc.event-termination.server"),
            lifecycleHooks: WebRTCLifecycleHooks(
                beforeDataChannelEventHandoff: {
                    let consumer = terminationState.withLock {
                        state -> WebRTCDataChannelEventConsumer? in
                        guard state.isArmed else { return nil }
                        state.isArmed = false
                        return state.consumer
                    }
                    consumer?.finish(
                        failure: .dataChannelEventStreamTerminated
                    )
                }
            )
        )
        defer {
            client.close()
            server.close()
        }

        let claimedEvents = try server.claimDataChannelEvents()
        guard let concreteConsumer =
                claimedEvents as? WebRTCDataChannelEventConsumer else {
            Issue.record("Expected the canonical DataChannel event consumer")
            return
        }
        terminationState.withLock { $0.consumer = concreteConsumer }

        try server.start()
        try client.start()
        _ = pumpHandshake(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        let channel = try client.openDataChannel(label: "terminated-consumer")
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        guard case .opened(let opened, .remote)? =
                try await claimedEvents.next() else {
            Issue.record("Expected the remote OPEN event")
            return
        }
        #expect(opened.id == channel.id)

        terminationState.withLock { $0.isArmed = true }
        try client.send([0xCA, 0xFE], on: channel.id)
        let inbound = clientOutbox.withLock { messages -> [Data] in
            let drained = messages
            messages.removeAll(keepingCapacity: true)
            return drained
        }
        #expect(!inbound.isEmpty)

        var receiveFailure: WebRTCError?
        for datagram in inbound {
            switch Result<Void, WebRTCError>(
                catching: { () throws(WebRTCError) in
                    try server.receive(datagram)
                }
            ) {
            case .success:
                break
            case .failure(let error):
                receiveFailure = error
                break
            }
            if receiveFailure != nil { break }
        }
        guard case .dataChannelEventStreamTerminated? = receiveFailure else {
            Issue.record("Expected the consumer termination to fail receive")
            return
        }
        guard case .dataChannelEventStreamTerminated? =
                server.terminalFailure else {
            Issue.record("Expected the event failure as terminal cause")
            return
        }

        do {
            _ = try await claimedEvents.next()
            Issue.record("Expected the terminated consumer failure")
        } catch WebRTCError.dataChannelEventStreamTerminated {
        } catch {
            Issue.record("Unexpected consumer failure: \(error)")
        }

        let snapshot = server.egressDebugSnapshot
        #expect(snapshot.inFlightCount == 0)
        #expect(snapshot.areEventsFinished)
        #expect(snapshot.isOwnerTeardownComplete)
        #expect(snapshot.isNetworkTeardownComplete)
    }

    @Test("Unconsumed DataChannel events fail with typed bounded backpressure", .timeLimit(.minutes(1)))
    func unconsumedDataChannelEventsFailAtBound() throws {
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        let clientOutbox = Mutex<[Data]>([])
        let serverOutbox = Mutex<[Data]>([])

        let client = try WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: serverCert.fingerprint,
            sendHandler: { bytes in
                clientOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCert,
            remoteFingerprint: clientCert.fingerprint,
            sendHandler: { bytes in
                serverOutbox.withLock { $0.append(Data(bytes)) }
                return .success(())
            }
        )

        try server.start()
        try client.start()
        _ = pumpHandshake(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )

        let channel = try client.openDataChannel(label: "bounded-events")
        try pumpTraffic(
            client: client,
            server: server,
            clientOutbox: clientOutbox,
            serverOutbox: serverOutbox
        )

        // The unconsumed remote OPEN occupies one slot. Exactly 1,024 further
        // messages therefore force the bounded 1,024-element event stream to
        // reject the final payload rather than silently discard it.
        for _ in 0..<1_024 {
            try client.send([0x42], on: channel.id)
        }

        do {
            try pumpTraffic(
                client: client,
                server: server,
                clientOutbox: clientOutbox,
                serverOutbox: serverOutbox
            )
            Issue.record("Expected bounded DataChannel event backpressure")
        } catch WebRTCError.dataChannelEventBufferExceeded(let limit) {
            #expect(limit == 1_024)
        } catch {
            Issue.record("Unexpected event-buffer failure: \(error)")
        }

        guard let failure = server.terminalFailure else {
            Issue.record("Expected typed terminal event-buffer failure")
            client.close()
            server.close()
            return
        }
        guard case .dataChannelEventBufferExceeded(let limit) = failure else {
            Issue.record("Unexpected terminal failure: \(failure)")
            client.close()
            server.close()
            return
        }
        #expect(limit == 1_024)
        client.close()
        server.close()
    }
}
