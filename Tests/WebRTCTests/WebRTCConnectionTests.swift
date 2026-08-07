/// Tests for WebRTCConnection new functionality
///
/// Tests demultiplex, DataHandler, server start, close behavior.
/// Fingerprint verification requires full DTLS handshake — tested in integration.

import Testing
import Foundation
import Synchronization
@testable import WebRTC

@Suite("WebRTC Connection Demultiplex Tests")
struct WebRTCConnectionDemultiplexTests {

    @Test("Controlling DTLS cannot start before ICE succeeds")
    func dtlsStartRequiresICE() throws {
        let clientCertificate = try WebRTCTestIdentity.make()
        let serverCertificate = try WebRTCTestIdentity.make()
        let credentials = ICECredentials(
            localUfrag: "clientUfrag",
            localPassword: "clientPassword456789012345",
            remoteUfrag: "serverUfrag",
            remotePassword: "serverPassword456789012345"
        )
        let connection = try WebRTCConnection.asClient(
            certificate: clientCertificate,
            remoteFingerprint: serverCertificate.fingerprint,
            iceConfiguration: .controlling(credentials: credentials),
            sendHandler: { _ in .success(()) }
        )

        #expect(throws: WebRTCError.self) {
            try connection.start()
        }
        #expect(connection.state == WebRTCConnectionState.new)
    }

    @Test("An asynchronous datagram failure preserves its typed cause")
    func asynchronousDatagramFailureIsTerminal() throws {
        let certificate = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: certificate,
            sendHandler: { _ in .success(()) }
        )

        connection.transportDidFail(.systemError(code: 65))

        #expect(connection.state.isTerminal)
        guard let failure = connection.terminalFailure,
              case .datagramSendFailed(.systemError(code: 65)) = failure else {
            Issue.record("Expected the admitted write's typed system error")
            return
        }
    }

    @Test("The first asynchronous terminal failure wins")
    func firstAsynchronousFailureWins() throws {
        let certificate = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: certificate,
            sendHandler: { _ in .success(()) }
        )

        connection.transportDidFail(.destinationUnreachable)
        connection.transportDidFail(.transportUnavailable)

        guard let failure = connection.terminalFailure,
              case .datagramSendFailed(.destinationUnreachable) = failure else {
            Issue.record("Expected the first transport failure to remain authoritative")
            return
        }
    }

    @Test("A late asynchronous failure cannot replace a clean close")
    func cleanCloseWinsTransportFailureRace() throws {
        let certificate = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: certificate,
            sendHandler: { _ in .success(()) }
        )

        connection.close()
        connection.transportDidFail(.transportUnavailable)

        #expect(connection.state == .closed)
        #expect(connection.terminalFailure == nil)
    }

    @Test("Server start initializes handshake without error")
    func serverStartInitializesHandshake() throws {
        let cert = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { _ in .success(()) }
        )

        try connection.start()
        // Server is now in DTLS handshake state, waiting for ClientHello
        #expect(connection.state == .dtlsHandshaking)
    }

    @Test("An inbound ClientHello claims an unstarted server handshake exactly once")
    func inboundClientHelloStartsServerHandshake() throws {
        let clientCertificate = try WebRTCTestIdentity.make()
        let serverCertificate = try WebRTCTestIdentity.make()
        let clientDatagrams = Mutex<[[UInt8]]>([])
        let serverDatagrams = Mutex<[[UInt8]]>([])
        let client = try WebRTCConnection.asClient(
            certificate: clientCertificate,
            remoteFingerprint: serverCertificate.fingerprint,
            sendHandler: { datagram in
                clientDatagrams.withLock { $0.append(datagram) }
                return .success(())
            }
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCertificate,
            remoteFingerprint: clientCertificate.fingerprint,
            sendHandler: { datagram in
                serverDatagrams.withLock { $0.append(datagram) }
                return .success(())
            }
        )

        try client.start()
        let clientHello = try #require(clientDatagrams.withLock { $0.first })
        try server.receive(clientHello)

        #expect(server.state == .dtlsHandshaking)
        #expect(!serverDatagrams.withLock { $0.isEmpty })
        #expect(throws: WebRTCError.self) {
            try server.start()
        }
    }

    @Test("Client start fails terminally when transport rejects the initial flight")
    func clientStartTransportRejectionIsTerminal() throws {
        let clientCertificate = try WebRTCTestIdentity.make()
        let serverCertificate = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asClient(
            certificate: clientCertificate,
            remoteFingerprint: serverCertificate.fingerprint,
            sendHandler: { _ in .failure(.backpressured) }
        )

        do {
            try connection.start()
            Issue.record("Expected the rejected ClientHello to fail")
        } catch WebRTCError.datagramSendFailed(let failure) {
            #expect(failure == .backpressured)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        #expect(connection.state.isTerminal)
        guard let terminalFailure = connection.terminalFailure else {
            Issue.record("Expected a typed terminal failure")
            return
        }
        guard case .datagramSendFailed(.backpressured) = terminalFailure else {
            Issue.record("Unexpected terminal failure: \(terminalFailure)")
            return
        }
    }

    @Test("A rejected DTLS response makes receive terminal")
    func dtlsResponseTransportRejectionIsTerminal() throws {
        let clientCertificate = try WebRTCTestIdentity.make()
        let serverCertificate = try WebRTCTestIdentity.make()
        let clientDatagrams = Mutex<[[UInt8]]>([])
        let client = try WebRTCConnection.asClient(
            certificate: clientCertificate,
            remoteFingerprint: serverCertificate.fingerprint,
            sendHandler: { datagram in
                clientDatagrams.withLock { $0.append(datagram) }
                return .success(())
            }
        )
        let server = try WebRTCConnection.asServer(
            certificate: serverCertificate,
            sendHandler: { _ in .failure(.destinationUnreachable) }
        )
        try server.start()
        try client.start()
        let clientHello = try #require(clientDatagrams.withLock { $0.first })

        do {
            try server.receive(clientHello)
            Issue.record("Expected the rejected DTLS response to fail")
        } catch WebRTCError.datagramSendFailed(let failure) {
            #expect(failure == .destinationUnreachable)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        #expect(server.state.isTerminal)
        guard let terminalFailure = server.terminalFailure else {
            Issue.record("Expected a typed terminal failure")
            return
        }
        guard case .datagramSendFailed(.destinationUnreachable) = terminalFailure else {
            Issue.record("Unexpected terminal failure: \(terminalFailure)")
            return
        }
    }

    @Test("A rejected STUN response makes receive terminal")
    func stunResponseTransportRejectionIsTerminal() throws {
        let certificate = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: certificate,
            sendHandler: { _ in .failure(.closed) }
        )
        try connection.start()
        let request = STUNMessage.bindingRequest().encodeBytes()

        do {
            try connection.receive(request, remoteAddress: [127, 0, 0, 1, 0x13, 0x88])
            Issue.record("Expected the rejected STUN response to fail")
        } catch WebRTCError.datagramSendFailed(let failure) {
            #expect(failure == .closed)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        #expect(connection.state.isTerminal)
        guard let terminalFailure = connection.terminalFailure else {
            Issue.record("Expected a typed terminal failure")
            return
        }
        guard case .datagramSendFailed(.closed) = terminalFailure else {
            Issue.record("Unexpected terminal failure: \(terminalFailure)")
            return
        }
    }

    @Test("Receive empty data is no-op")
    func receiveEmptyDataIsNoop() throws {
        let cert = try WebRTCTestIdentity.make()
        let sentData = Mutex<[Data]>([])
        let connection = try WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { data in
                sentData.withLock { $0.append(Data(data)) }
                return .success(())
            }
        )

        try connection.start()
        try connection.receive(Data())

        let messages = sentData.withLock { $0 }
        #expect(messages.isEmpty)
    }

    @Test("DTLS byte range (20-63) is routed to DTLS processing")
    func receiveDTLSRangeRouted() throws {
        // Create client → capture ClientHello
        let clientCert = try WebRTCTestIdentity.make()
        let serverCert = try WebRTCTestIdentity.make()
        let sentByClient = Mutex<[Data]>([])
        let client = try WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: serverCert.fingerprint,
            sendHandler: { data in
                sentByClient.withLock { $0.append(Data(data)) }
                return .success(())
            }
        )

        try client.start()
        let clientHello = sentByClient.withLock { $0 }
        #expect(!clientHello.isEmpty)
        // ClientHello first byte should be 22 (DTLS Handshake content type)
        #expect(clientHello[0][clientHello[0].startIndex] == 22)

        // Create server → feed ClientHello → expect DTLS response
        let sentByServer = Mutex<[Data]>([])
        let server = try WebRTCConnection.asServer(
            certificate: serverCert,
            sendHandler: { data in
                sentByServer.withLock { $0.append(Data(data)) }
                return .success(())
            }
        )
        try server.start()
        try server.receive(clientHello[0])

        // Server should respond with DTLS handshake messages
        let serverMessages = sentByServer.withLock { $0 }
        #expect(!serverMessages.isEmpty)
    }

    @Test("Unknown byte (>63, non-STUN) is ignored")
    func receiveUnknownByteIgnored() throws {
        let cert = try WebRTCTestIdentity.make()
        let sentData = Mutex<[Data]>([])
        let connection = try WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { data in
                sentData.withLock { $0.append(Data(data)) }
                return .success(())
            }
        )

        try connection.start()

        // Byte 0x80 has first two bits = 10, not STUN (STUN requires 00).
        // Also > 63, so not DTLS.
        let unknownData = Data([0x80, 0x01, 0x02, 0x03])
        try connection.receive(unknownData)

        let messages = sentData.withLock { $0 }
        #expect(messages.isEmpty)
    }

    @Test("remote endpoint decoding extracts IPv4 port")
    func decodeIPv4RemoteEndpoint() {
        let endpoint = WebRTCConnection.decodeRemoteEndpoint(
            [192, 168, 1, 1, 0x13, 0x88]
        )

        #expect(endpoint.address == [192, 168, 1, 1])
        #expect(endpoint.port == 5000)
    }

    @Test("remote endpoint decoding extracts IPv6 port")
    func decodeIPv6RemoteEndpoint() {
        let endpoint = WebRTCConnection.decodeRemoteEndpoint(
            Array(repeating: 0x20, count: 16) + [0x13, 0x88]
        )

        #expect(endpoint.address == Array(repeating: 0x20, count: 16))
        #expect(endpoint.port == 5000)
    }

    @Test("remote endpoint decoding ignores the IPv6 scope suffix for STUN")
    func decodeScopedIPv6RemoteEndpoint() {
        let address = [UInt8](repeating: 0, count: 15) + [1]
        let endpoint = WebRTCConnection.decodeRemoteEndpoint(
            address + [0x13, 0x88, 0, 0, 0, 4]
        )

        #expect(endpoint.address == address)
        #expect(endpoint.port == 5000)
    }

    @Test("remote endpoint decoding falls back to raw address")
    func decodeRemoteEndpointWithoutPort() {
        let endpoint = WebRTCConnection.decodeRemoteEndpoint(
            [192, 168, 1, 1]
        )

        #expect(endpoint.address == [192, 168, 1, 1])
        #expect(endpoint.port == 0)
    }
}

@Suite("WebRTC Connection DataChannel Event Tests")
struct WebRTCConnectionDataChannelEventTests {
    @Test("Claimed event consumer receives the exact terminal failure")
    func claimedEventConsumerReceivesTerminalFailure() async throws {
        let certificate = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: certificate,
            sendHandler: { _ in .success(()) }
        )
        let consumer = try connection.claimDataChannelEvents()

        connection.transportDidFail(.systemError(code: 61))

        do {
            _ = try await consumer.next()
            Issue.record("Expected the connection's terminal failure")
        } catch WebRTCError.datagramSendFailed(.systemError(let code)) {
            #expect(code == 61)
        } catch {
            Issue.record("Unexpected event consumer failure: \(error)")
        }
    }

    @Test("Event consumer and connection retain the same first failure")
    func eventConsumerRetainsFirstTerminalFailure() async throws {
        let certificate = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: certificate,
            sendHandler: { _ in .success(()) }
        )
        let consumer = try connection.claimDataChannelEvents()

        connection.transportDidFail(.destinationUnreachable)
        connection.transportDidFail(.transportUnavailable)

        guard case .datagramSendFailed(.destinationUnreachable)? =
                connection.terminalFailure else {
            Issue.record("Expected the first connection failure")
            return
        }
        do {
            _ = try await consumer.next()
            Issue.record("Expected the first event consumer failure")
        } catch WebRTCError.datagramSendFailed(.destinationUnreachable) {
            // Expected: both public observations expose the same cause.
        } catch {
            Issue.record("Event consumer observed a different failure: \(error)")
        }
    }

    @Test(
        "Concurrent close and transport failures publish one authoritative outcome",
        .timeLimit(.minutes(1))
    )
    func concurrentCloseAndTransportFailurePublishOneOutcome() async throws {
        let certificate = try WebRTCTestIdentity.make()

        for iteration in 0..<32 {
            let connection = try WebRTCConnection.asServer(
                certificate: certificate,
                sendHandler: { _ in .success(()) }
            )
            let claimedConsumer = try connection.claimDataChannelEvents()
            let consumer = try #require(
                claimedConsumer as? WebRTCDataChannelEventConsumer
            )
            let eventRead = Task { try await consumer.next() }

            for _ in 0..<1_000 where !consumer.hasPendingRead {
                await Task.yield()
            }
            #expect(consumer.hasPendingRead)

            let gate = Mutex((readyCount: 0, isReleased: false))
            let closeTask = Task {
                gate.withLock { $0.readyCount += 1 }
                while !gate.withLock({ $0.isReleased }) {
                    await Task.yield()
                }
                connection.close()
            }
            let firstExpectedCode = Int32(6_100 + iteration)
            let firstFailureTask = Task {
                gate.withLock { $0.readyCount += 1 }
                while !gate.withLock({ $0.isReleased }) {
                    await Task.yield()
                }
                connection.transportDidFail(
                    .systemError(code: firstExpectedCode)
                )
            }
            let secondExpectedCode = Int32(7_100 + iteration)
            let secondFailureTask = Task {
                gate.withLock { $0.readyCount += 1 }
                while !gate.withLock({ $0.isReleased }) {
                    await Task.yield()
                }
                connection.transportDidFail(
                    .systemError(code: secondExpectedCode)
                )
            }

            for _ in 0..<1_000
                where gate.withLock({ $0.readyCount }) != 3 {
                await Task.yield()
            }
            #expect(gate.withLock { $0.readyCount } == 3)
            gate.withLock { $0.isReleased = true }
            await closeTask.value
            await firstFailureTask.value
            await secondFailureTask.value

            if let terminalFailure = connection.terminalFailure {
                guard case .datagramSendFailed(.systemError(let code)) =
                        terminalFailure else {
                    Issue.record(
                        "Unexpected connection outcome: \(terminalFailure)"
                    )
                    do {
                        _ = try await eventRead.value
                    } catch {
                        Issue.record(
                            "Consumer outcome after unexpected terminal cause: \(error)"
                        )
                    }
                    continue
                }
                #expect(
                    code == firstExpectedCode
                        || code == secondExpectedCode
                )
                do {
                    _ = try await eventRead.value
                    Issue.record("Expected the consumer's terminal failure")
                } catch WebRTCError.datagramSendFailed(
                    .systemError(let consumerCode)
                ) {
                    #expect(consumerCode == code)
                } catch {
                    Issue.record(
                        "Consumer observed a different outcome: \(error)"
                    )
                }
            } else {
                do {
                    #expect(try await eventRead.value == nil)
                } catch {
                    Issue.record(
                        "Clean close produced a consumer failure: \(error)"
                    )
                }
            }
        }
    }



    @Test("dataChannelEvents after close returns a terminated stream")
    func dataChannelEventsAfterCloseTerminates() async throws {
        let cert = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { _ in .success(()) }
        )

        connection.close()

        let events = try connection.claimDataChannelEvents()
        var receivedCount = 0
        while try await events.next() != nil {
            receivedCount += 1
        }

        #expect(receivedCount == 0)
    }

    @Test("dataChannelEvents permits exactly one consumer claim")
    func dataChannelEventsClaimOnce() throws {
        let certificate = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: certificate,
            sendHandler: { _ in .success(()) }
        )

        _ = try connection.claimDataChannelEvents()
        do {
            _ = try connection.claimDataChannelEvents()
            Issue.record("Expected the second event-stream claim to fail")
        } catch WebRTCError.dataChannelEventStreamAlreadyClaimed {
            // Expected typed failure.
        } catch {
            Issue.record("Unexpected event-stream claim failure: \(error)")
        }
        connection.close()
    }

    @Test(
        "DataChannel event consumer rejects a concurrent read",
        .timeLimit(.minutes(1))
    )
    func dataChannelEventConsumerRejectsConcurrentRead() async throws {
        let budget = WebRTCDataChannelEventBudget(
            maximumEventCount: 4,
            maximumPayloadByteCount: 1_024
        )
        let consumer = WebRTCDataChannelEventConsumer(
            maximumBufferedEventCount: 4,
            eventBudget: budget
        )
        let firstRead = Task { try await consumer.next() }
        for _ in 0..<100 where !consumer.hasPendingRead {
            await Task.yield()
        }
        #expect(consumer.hasPendingRead)

        do {
            _ = try await consumer.next()
            Issue.record("Expected the overlapping event read to fail")
        } catch WebRTCError.dataChannelEventReadAlreadyInProgress {
            // Expected typed failure.
        } catch {
            Issue.record("Unexpected overlapping read failure: \(error)")
        }

        consumer.finish()
        #expect(try await firstRead.value == nil)
    }

    @Test("DataChannel event ring remains bounded while continuously active")
    func dataChannelEventRingReleasesConsumedSlots() throws {
        var queue = WebRTCDataChannelEventQueue(maximumCount: 4)

        for index in 0..<4 {
            let payload = [UInt8(truncatingIfNeeded: index)]
            let appended = queue.append(.message(
                channelID: 1,
                generation: UInt64(index),
                payload: payload
            ))
            #expect(appended)
        }
        let steadyStateSlotCount = queue.allocatedSlotCount

        for index in 4..<4_096 {
            guard case .message(_, let generation, let observed)? =
                    queue.popFirst() else {
                Issue.record("Expected the queued message")
                return
            }
            let expected = index - 4
            #expect(generation == UInt64(expected))
            #expect(observed == [UInt8(truncatingIfNeeded: expected)])

            let payload = [UInt8(truncatingIfNeeded: index)]
            let appended = queue.append(.message(
                channelID: 1,
                generation: UInt64(index),
                payload: payload
            ))
            #expect(appended)
            #expect(queue.count == 4)
            #expect(queue.allocatedSlotCount == steadyStateSlotCount)
        }
    }

    @Test(
        "Large DataChannel payload retains COW storage through both event rings",
        .timeLimit(.minutes(1))
    )
    func largeDataChannelPayloadRetainsStorageIdentity() async throws {
        let payload = [UInt8](repeating: 0xA5, count: 1_048_576)
        let sourceAddress = payload.withUnsafeBufferPointer { buffer in
            buffer.baseAddress.map { UInt(bitPattern: $0) }
        }
        var stagingQueue = WebRTCDataChannelEventQueue(maximumCount: 2)
        let didAppend = stagingQueue.append(.message(
            channelID: 7,
            generation: 11,
            payload: payload
        ))
        #expect(didAppend)
        let poppedEvent = stagingQueue.popFirst()
        let stagedEvent = try #require(poppedEvent)

        let budget = WebRTCDataChannelEventBudget(
            maximumEventCount: 2,
            maximumPayloadByteCount: 2 * 1_048_576
        )
        let consumer = WebRTCDataChannelEventConsumer(
            maximumBufferedEventCount: 2,
            eventBudget: budget
        )
        guard case .success = budget.reserve([stagedEvent]) else {
            Issue.record("Expected the large payload reservation")
            return
        }
        guard case .enqueued = consumer.yieldReserved(
            stagedEvent,
            from: budget
        ) else {
            Issue.record("Expected the large event handoff")
            return
        }
        guard case .message(
            let channelID,
            let generation,
            let deliveredPayload
        )? = try await consumer.next() else {
            Issue.record("Expected the delivered DataChannel message")
            return
        }
        let deliveredAddress = deliveredPayload.withUnsafeBufferPointer {
            buffer in
            buffer.baseAddress.map { UInt(bitPattern: $0) }
        }

        #expect(channelID == 7)
        #expect(generation == 11)
        #expect(deliveredPayload.count == payload.count)
        #expect(deliveredAddress == sourceAddress)
        #expect(budget.reservedEventCount == 0)
        #expect(budget.reservedPayloadByteCount == 0)
        withExtendedLifetime(payload) {}
        consumer.finish()
    }

    @Test("DataChannel event payload reservations share one byte limit")
    func dataChannelEventPayloadBudgetIsBounded() {
        let budget = WebRTCDataChannelEventBudget(
            maximumEventCount: 1,
            maximumPayloadByteCount: 4
        )
        let first = WebRTCDataChannelEvent.message(
            channelID: 1,
            generation: 0,
            payload: [1, 2, 3]
        )
        let second = WebRTCDataChannelEvent.message(
            channelID: 1,
            generation: 0,
            payload: [4, 5]
        )

        guard case .success = budget.reserve([first]) else {
            Issue.record("Expected the first reservation")
            return
        }
        guard case .failure = budget.reserve([second]) else {
            Issue.record("Expected the shared reservation limit")
            return
        }
        #expect(budget.reservedEventCount == 1)
        #expect(budget.reservedPayloadByteCount == 3)
        budget.release(first)
        guard case .success = budget.reserve([second]) else {
            Issue.record("Expected released capacity to be reusable")
            return
        }
        budget.release(second)
        #expect(budget.reservedEventCount == 0)
        #expect(budget.reservedPayloadByteCount == 0)
    }

    @Test("DataChannel event delivery releases its reservation exactly once")
    func dataChannelEventDeliveryReleasesReservation() async throws {
        let budget = WebRTCDataChannelEventBudget(
            maximumEventCount: 1,
            maximumPayloadByteCount: 4
        )
        let consumer = WebRTCDataChannelEventConsumer(
            maximumBufferedEventCount: 1,
            eventBudget: budget
        )
        let event = WebRTCDataChannelEvent.message(
            channelID: 1,
            generation: 0,
            payload: [1, 2, 3]
        )
        guard case .success = budget.reserve([event]) else {
            Issue.record("Expected the event reservation")
            return
        }
        guard case .enqueued = consumer.yieldReserved(
            event,
            from: budget
        ) else {
            Issue.record("Expected the reserved event handoff")
            return
        }

        #expect(try await consumer.next() == event)
        #expect(budget.reservedEventCount == 0)
        #expect(budget.reservedPayloadByteCount == 0)
        consumer.finish()
    }

    @Test("DataChannel terminal drain preserves queued events before failure")
    func dataChannelEventTerminalDrainReleasesReservations() async throws {
        let budget = WebRTCDataChannelEventBudget(
            maximumEventCount: 1,
            maximumPayloadByteCount: 4
        )
        let consumer = WebRTCDataChannelEventConsumer(
            maximumBufferedEventCount: 1,
            eventBudget: budget
        )
        let event = WebRTCDataChannelEvent.message(
            channelID: 1,
            generation: 0,
            payload: [1, 2, 3]
        )
        guard case .success = budget.reserve([event]) else {
            Issue.record("Expected the event reservation")
            return
        }
        guard case .enqueued = consumer.yieldReserved(
            event,
            from: budget
        ) else {
            Issue.record("Expected the reserved event handoff")
            return
        }

        consumer.finish(failure: .timeout)
        #expect(budget.reservedEventCount == 1)
        #expect(budget.reservedPayloadByteCount == 3)
        #expect(try await consumer.next() == event)
        await #expect(throws: WebRTCError.self) {
            _ = try await consumer.next()
        }
        #expect(budget.reservedEventCount == 0)
        #expect(budget.reservedPayloadByteCount == 0)
    }

    @Test("Abandoning terminal DataChannel events releases queued owners")
    func dataChannelEventDiscardReleasesReservations() async throws {
        let budget = WebRTCDataChannelEventBudget(
            maximumEventCount: 1,
            maximumPayloadByteCount: 4
        )
        let consumer = WebRTCDataChannelEventConsumer(
            maximumBufferedEventCount: 1,
            eventBudget: budget
        )
        let event = WebRTCDataChannelEvent.message(
            channelID: 1,
            generation: 0,
            payload: [1, 2, 3]
        )
        guard case .success = budget.reserve([event]) else {
            Issue.record("Expected the event reservation")
            return
        }
        guard case .enqueued = consumer.yieldReserved(
            event,
            from: budget
        ) else {
            Issue.record("Expected the reserved event handoff")
            return
        }

        consumer.finish(failure: .timeout)
        consumer.discardRemainingEvents()
        consumer.discardRemainingEvents()

        #expect(budget.reservedEventCount == 0)
        #expect(budget.reservedPayloadByteCount == 0)
        await #expect(throws: WebRTCError.self) {
            _ = try await consumer.next()
        }
    }

    @Test("Rejected consumer handoff remains caller-owned")
    func rejectedDataChannelEventHandoffReleasesReservation() async throws {
        let budget = WebRTCDataChannelEventBudget(
            maximumEventCount: 2,
            maximumPayloadByteCount: 4
        )
        let consumer = WebRTCDataChannelEventConsumer(
            maximumBufferedEventCount: 1,
            eventBudget: budget
        )
        let first = WebRTCDataChannelEvent.message(
            channelID: 1,
            generation: 0,
            payload: [1, 2]
        )
        let rejected = WebRTCDataChannelEvent.message(
            channelID: 1,
            generation: 0,
            payload: [3, 4]
        )
        guard case .success = budget.reserve([first, rejected]) else {
            Issue.record("Expected both event reservations")
            return
        }
        guard case .enqueued = consumer.yieldReserved(
            first,
            from: budget
        ) else {
            Issue.record("Expected the first handoff")
            return
        }
        guard case .dropped = consumer.yieldReserved(
            rejected,
            from: budget
        ) else {
            Issue.record("Expected the bounded consumer rejection")
            return
        }
        budget.release(rejected)
        consumer.finish()
        #expect(try await consumer.next() == first)
        #expect(try await consumer.next() == nil)

        #expect(budget.reservedEventCount == 0)
        #expect(budget.reservedPayloadByteCount == 0)
    }

    @Test("DataChannel event consumer preserves terminal failure")
    func dataChannelEventConsumerPreservesTerminalFailure() async {
        let budget = WebRTCDataChannelEventBudget(
            maximumEventCount: 4,
            maximumPayloadByteCount: 1_024
        )
        let consumer = WebRTCDataChannelEventConsumer(
            maximumBufferedEventCount: 4,
            eventBudget: budget
        )
        consumer.finish(failure: .datagramSendFailed(.systemError(code: 61)))

        do {
            _ = try await consumer.next()
            Issue.record("Expected the terminal event failure")
        } catch WebRTCError.datagramSendFailed(.systemError(let code)) {
            #expect(code == 61)
        } catch {
            Issue.record("Unexpected terminal event failure: \(error)")
        }
    }

    @Test(
        "A parked DataChannel read resumes with the exact terminal failure",
        .timeLimit(.minutes(1))
    )
    func parkedDataChannelReadReceivesTerminalFailure() async {
        let budget = WebRTCDataChannelEventBudget(
            maximumEventCount: 1,
            maximumPayloadByteCount: 4
        )
        let consumer = WebRTCDataChannelEventConsumer(
            maximumBufferedEventCount: 1,
            eventBudget: budget
        )
        let read = Task { try await consumer.next() }
        for _ in 0..<100 where !consumer.hasPendingRead {
            await Task.yield()
        }
        #expect(consumer.hasPendingRead)

        consumer.finish(failure: .datagramSendFailed(
            .systemError(code: 61)
        ))

        do {
            _ = try await read.value
            Issue.record("Expected the parked read to fail")
        } catch WebRTCError.datagramSendFailed(.systemError(let code)) {
            #expect(code == 61)
        } catch {
            Issue.record("Unexpected parked read failure: \(error)")
        }
    }

    @Test(
        "A pre-cancelled DataChannel read preserves the queued event",
        .timeLimit(.minutes(1))
    )
    func preCancelledDataChannelReadPreservesEvent() async throws {
        let budget = WebRTCDataChannelEventBudget(
            maximumEventCount: 1,
            maximumPayloadByteCount: 4
        )
        let consumer = WebRTCDataChannelEventConsumer(
            maximumBufferedEventCount: 1,
            eventBudget: budget
        )
        let event = WebRTCDataChannelEvent.message(
            channelID: 1,
            generation: 0,
            payload: [1, 2, 3]
        )
        guard case .success = budget.reserve([event]),
              case .enqueued = consumer.yieldReserved(
                event,
                from: budget
              ) else {
            Issue.record("Expected the queued event")
            return
        }

        let gate = Mutex((started: false, released: false))
        let cancelledRead = Task {
            gate.withLock { $0.started = true }
            while !gate.withLock({ $0.released }) {
                await Task.yield()
            }
            return try await consumer.next()
        }
        for _ in 0..<100 where !gate.withLock({ $0.started }) {
            await Task.yield()
        }
        cancelledRead.cancel()
        gate.withLock { $0.released = true }

        do {
            _ = try await cancelledRead.value
            Issue.record("Expected the cancelled read")
        } catch WebRTCError.dataChannelEventReadCancelled {
            // Expected: cancellation occurs before the queued owner is popped.
        } catch {
            Issue.record("Unexpected cancelled read failure: \(error)")
        }

        #expect(budget.reservedEventCount == 1)
        #expect(try await consumer.next() == event)
        #expect(budget.reservedEventCount == 0)
        #expect(budget.reservedPayloadByteCount == 0)
        consumer.finish()
    }

    @Test("Send handler can close connection reentrantly", .timeLimit(.minutes(1)))
    func sendHandlerCanCloseConnectionReentrantly() throws {
        let cert = try WebRTCTestIdentity.make()
        let connectionOwner = Mutex<WebRTCConnection?>(nil)
        let callbackCount = Mutex(0)
        let callbackSnapshot = Mutex<WebRTCConnection.EgressDebugSnapshot?>(nil)
        let connection = try WebRTCConnection.asClient(
            certificate: cert,
            remoteFingerprint: CertificateFingerprint.fromDER(Data(repeating: 0, count: 32)),
            sendHandler: { _ in
                callbackCount.withLock { $0 += 1 }
                let current = connectionOwner.withLock { $0 }
                current?.close()
                if let current {
                    callbackSnapshot.withLock {
                        $0 = current.egressDebugSnapshot
                    }
                }
                return .success(())
            }
        )
        connectionOwner.withLock { $0 = connection }

        try connection.start()

        #expect(callbackCount.withLock { $0 } == 1)
        #expect(connection.state == .closed)
        let duringCallback = try #require(callbackSnapshot.withLock { $0 })
        #expect(duringCallback.isTerminal)
        #expect(duringCallback.inFlightCount == 1)
        #expect(duringCallback.isOwnerTeardownComplete)
        #expect(duringCallback.areEventsFinished)
        #expect(!duringCallback.isNetworkTeardownComplete)

        let afterCallback = connection.egressDebugSnapshot
        #expect(afterCallback.inFlightCount == 0)
        #expect(afterCallback.isNetworkTeardownComplete)
    }

    @Test("Reentrant close is not rewritten as a transport failure")
    func reentrantCloseWinsOverHandlerFailure() throws {
        let certificate = try WebRTCTestIdentity.make()
        let remoteCertificate = try WebRTCTestIdentity.make()
        let connectionOwner = Mutex<WebRTCConnection?>(nil)
        let connection = try WebRTCConnection.asClient(
            certificate: certificate,
            remoteFingerprint: remoteCertificate.fingerprint,
            sendHandler: { _ in
                connectionOwner.withLock { $0 }?.close()
                return .failure(.closed)
            }
        )
        connectionOwner.withLock { $0 = connection }

        do {
            try connection.start()
            Issue.record("Expected the transport rejection")
        } catch WebRTCError.datagramSendFailed(let failure) {
            #expect(failure == .closed)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        #expect(connection.state == .closed)
        #expect(connection.terminalFailure == nil)
    }

    @Test("Start after close does not emit a datagram")
    func startAfterCloseIsRejectedWithoutEmission() throws {
        let certificate = try WebRTCTestIdentity.make()
        let remoteCertificate = try WebRTCTestIdentity.make()
        let callbackCount = Mutex(0)
        let connection = try WebRTCConnection.asClient(
            certificate: certificate,
            remoteFingerprint: remoteCertificate.fingerprint,
            sendHandler: { _ in
                callbackCount.withLock { $0 += 1 }
                return .success(())
            }
        )
        connection.close()

        do {
            try connection.start()
            Issue.record("Expected start after close to fail")
        } catch WebRTCError.closed {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
        #expect(callbackCount.withLock { $0 } == 0)
    }

    @Test("Starting twice is rejected without a second flight")
    func duplicateStartIsRejectedWithoutEmission() throws {
        let certificate = try WebRTCTestIdentity.make()
        let remoteCertificate = try WebRTCTestIdentity.make()
        let callbackCount = Mutex(0)
        let connection = try WebRTCConnection.asClient(
            certificate: certificate,
            remoteFingerprint: remoteCertificate.fingerprint,
            sendHandler: { _ in
                callbackCount.withLock { $0 += 1 }
                return .success(())
            }
        )
        try connection.start()

        do {
            try connection.start()
            Issue.record("Expected duplicate start to fail")
        } catch WebRTCError.invalidState(let reason) {
            #expect(reason.contains("dtlsHandshaking"))
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
        #expect(callbackCount.withLock { $0 } == 1)
    }

    @Test("Incoming channel consumer can reenter close after shutdown", .timeLimit(.minutes(1)))
    func incomingChannelConsumerCanReenterCloseAfterShutdown() async throws {
        let cert = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { _ in .success(()) }
        )
        let events = try connection.claimDataChannelEvents()

        let consumer = Task { () -> WebRTCConnectionState in
            while try await events.next() != nil {}
            connection.close()
            return connection.state
        }

        connection.close()

        #expect(try await consumer.value == .closed)
    }

    @Test("openDataChannel after close is rejected")
    func openDataChannelAfterCloseRejected() throws {
        let cert = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { _ in .success(()) }
        )
        connection.close()

        do {
            _ = try connection.openDataChannel(label: "closed")
            Issue.record("Expected openDataChannel to fail after close")
        } catch WebRTCError.invalidState(let message) {
            #expect(message.contains("closed"))
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("send after close is rejected")
    func sendAfterCloseRejected() throws {
        let cert = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { _ in .success(()) }
        )
        connection.close()

        do {
            try connection.send([0x01], on: 0)
            Issue.record("Expected send to fail after close")
        } catch WebRTCError.invalidState(let message) {
            #expect(message.contains("closed"))
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("close racing with send and openDataChannel is safe", .timeLimit(.minutes(1)))
    func closeRacingWithSendAndOpenDataChannelIsSafe() async throws {
        let cert = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { _ in .success(()) }
        )
        try connection.start()

        await withTaskGroup(of: Void.self) { group in
            for index in 0..<200 {
                group.addTask {
                    switch index % 3 {
                    case 0:
                        connection.close()
                    case 1:
                        do {
                            _ = try connection.openDataChannel(label: "race-\(index)")
                        } catch WebRTCError.invalidState {
                        } catch {
                            Issue.record("Unexpected openDataChannel error: \(error)")
                        }
                    default:
                        do {
                            try connection.send([0x01, 0x02], on: UInt16(index))
                        } catch WebRTCError.invalidState {
                        } catch {
                            Issue.record("Unexpected send error: \(error)")
                        }
                    }
                }
            }
        }

        #expect(connection.state == .closed)
    }
}
