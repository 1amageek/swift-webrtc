/// Tests for WebRTC Integration

import Testing
import Foundation
import Synchronization
@testable import WebRTC
private enum EndpointCloseRaceOutcome: Sendable {
    case connection(WebRTCConnection)
    case listener(WebRTCListener)
    case rejected
    case closeCompleted
    case unexpected(String)
}

@Suite("WebRTC Endpoint Tests")
struct WebRTCEndpointTests {

    @Test("Create endpoint with self-signed certificate")
    func createEndpoint() throws {
        let endpoint = try WebRTCTestIdentity.endpoint()
        #expect(endpoint.localFingerprint.bytes.count == 32)
    }

    @Test("Create client connection via endpoint")
    func createClientConnection() throws {
        let endpoint = try WebRTCTestIdentity.endpoint()
        let remoteFingerprint = CertificateFingerprint.fromDER(Data(repeating: 0xAB, count: 100))

        let connection = try endpoint.connect(
            remoteFingerprint: remoteFingerprint,
            sendHandler: { _ in .success(()) }
        )

        #expect(connection.state == .new)
        #expect(connection.localFingerprint == endpoint.localFingerprint)
    }

    @Test("Create listener via endpoint")
    func createListener() throws {
        let endpoint = try WebRTCTestIdentity.endpoint()
        let listener = try endpoint.listen()

        #expect(listener.localFingerprint == endpoint.localFingerprint)
    }

    @Test("Endpoint close prevents new connections")
    func endpointClose() throws {
        let endpoint = try WebRTCTestIdentity.endpoint()
        endpoint.close()

        let remoteFingerprint = CertificateFingerprint.fromDER(Data(repeating: 0xAB, count: 100))

        #expect(throws: WebRTCError.self) {
            _ = try endpoint.connect(
                remoteFingerprint: remoteFingerprint,
                sendHandler: { _ in .success(()) }
            )
        }

        #expect(throws: WebRTCError.self) {
            _ = try endpoint.listen()
        }
    }

    @Test("Endpoint close linearizes with connection and listener registration", .timeLimit(.minutes(1)))
    func endpointCloseLinearizesWithRegistration() async throws {
        let endpoint = try WebRTCTestIdentity.endpoint()
        let remoteFingerprint = CertificateFingerprint.fromDER(Data(repeating: 0xAB, count: 100))

        let outcomes = await withTaskGroup(of: EndpointCloseRaceOutcome.self) { group in
            for index in 0..<160 {
                group.addTask {
                    if index.isMultiple(of: 8) {
                        // Let some registrations begin constructing their child
                        // before close attempts to take the endpoint lock.
                        await Task.yield()
                        endpoint.close()
                        return .closeCompleted
                    }

                    if index.isMultiple(of: 2) {
                        do {
                            return .connection(try endpoint.connect(
                                remoteFingerprint: remoteFingerprint,
                                sendHandler: { _ in .success(()) }
                            ))
                        } catch WebRTCError.closed {
                            return .rejected
                        } catch {
                            return .unexpected(String(describing: error))
                        }
                    }

                    do {
                        return .listener(try endpoint.listen())
                    } catch WebRTCError.closed {
                        return .rejected
                    } catch {
                        return .unexpected(String(describing: error))
                    }
                }
            }

            var collected: [EndpointCloseRaceOutcome] = []
            for await outcome in group {
                collected.append(outcome)
            }
            return collected
        }

        // Make the postcondition independent of which operation won the race.
        endpoint.close()

        for outcome in outcomes {
            switch outcome {
            case .connection(let connection):
                #expect(connection.state == .closed)
            case .listener(let listener):
                #expect(try listener.acceptConnection(peerID: "after-close", sendHandler: { _ in .success(()) }) == nil)
            case .rejected, .closeCompleted:
                break
            case .unexpected(let message):
                Issue.record("Unexpected endpoint race error: \(message)")
            }
        }
    }
}

@Suite("WebRTC Connection Tests")
struct WebRTCConnectionTests {

    @Test("Client connection initial state")
    func clientConnectionInitialState() throws {
        let cert = try WebRTCTestIdentity.make()
        let remoteFingerprint = CertificateFingerprint.fromDER(Data(repeating: 0xCD, count: 100))

        let connection = try WebRTCConnection.asClient(
            certificate: cert,
            remoteFingerprint: remoteFingerprint,
            sendHandler: { _ in .success(()) }
        )

        #expect(connection.state == .new)
        #expect(connection.localFingerprint == cert.fingerprint)
        #expect(connection.remoteFingerprint == nil)
    }

    @Test("Server connection initial state")
    func serverConnectionInitialState() throws {
        let cert = try WebRTCTestIdentity.make()

        let connection = try WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { _ in .success(()) }
        )

        #expect(connection.state == .new)
        #expect(connection.localFingerprint == cert.fingerprint)
    }

    @Test("Client connection start triggers DTLS handshake")
    func clientStartSendsClientHello() throws {
        let cert = try WebRTCTestIdentity.make()
        let remoteFingerprint = CertificateFingerprint.fromDER(Data(repeating: 0xEF, count: 100))

        let sentData = Mutex<[Data]>([])
        let connection = try WebRTCConnection.asClient(
            certificate: cert,
            remoteFingerprint: remoteFingerprint,
            sendHandler: { data in
                sentData.withLock { $0.append(Data(data)) }
                return .success(())
            }
        )

        try connection.start()

        #expect(connection.state == .dtlsHandshaking)
        let messages = sentData.withLock { $0 }
        #expect(messages.count == 1) // ClientHello
        #expect(!messages[0].isEmpty)
    }

    @Test("Connection close sets state")
    func connectionClose() throws {
        let cert = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { _ in .success(()) }
        )

        connection.close()
        #expect(connection.state == .closed)
    }

    @Test("ICE credentials are generated")
    func iceCredentials() throws {
        let cert = try WebRTCTestIdentity.make()
        let connection = try WebRTCConnection.asClient(
            certificate: cert,
            remoteFingerprint: CertificateFingerprint.fromDER(Data(repeating: 0, count: 32)),
            sendHandler: { _ in .success(()) }
        )

        let creds = connection.iceCredentials
        #expect(!creds.localUfrag.isEmpty)
        #expect(!creds.localPassword.isEmpty)
    }
}

@Suite("WebRTC Listener Tests")
struct WebRTCListenerTests {

    @Test("Listener accepts connections")
    func listenerAcceptsConnections() throws {
        let cert = try WebRTCTestIdentity.make()
        let listener = WebRTCListener(certificate: cert)

        let conn = try listener.acceptConnection(peerID: "127.0.0.1:5000", sendHandler: { _ in .success(()) })
        #expect(conn != nil)
        #expect(conn?.state == .dtlsHandshaking)
    }

    @Test("Listener returns existing connection for same peer")
    func listenerReturnsExistingConnection() throws {
        let cert = try WebRTCTestIdentity.make()
        let listener = WebRTCListener(certificate: cert)

        let conn1 = try listener.acceptConnection(peerID: "127.0.0.1:5000", sendHandler: { _ in .success(()) })
        let conn2 = try listener.acceptConnection(peerID: "127.0.0.1:5000", sendHandler: { _ in .success(()) })

        // Same connection returned for same peer
        #expect(conn1 != nil)
        #expect(conn2 != nil)
        #expect(conn1 === conn2)
    }

    @Test("Listener replaces a terminal connection for the same peer")
    func listenerReplacesTerminalConnection() throws {
        let cert = try WebRTCTestIdentity.make()
        let listener = WebRTCListener(certificate: cert)

        let accepted1 = try listener.acceptConnection(peerID: "127.0.0.1:5000", sendHandler: { _ in .success(()) })
        let conn1 = try #require(accepted1)
        conn1.close()
        #expect(conn1.state.isTerminal)

        // A reconnect attempt from the same address must get a fresh
        // connection, not the dead one
        let accepted2 = try listener.acceptConnection(peerID: "127.0.0.1:5000", sendHandler: { _ in .success(()) })
        let conn2 = try #require(accepted2)
        #expect(conn1 !== conn2)
        #expect(conn2.state == .dtlsHandshaking)
        #expect(listener.connection(for: "127.0.0.1:5000") === conn2)
    }

    @Test("Listener returns nil after close")
    func listenerCloseRejectsConnections() throws {
        let cert = try WebRTCTestIdentity.make()
        let listener = WebRTCListener(certificate: cert)

        listener.close()

        let conn = try listener.acceptConnection(peerID: "127.0.0.1:5000", sendHandler: { _ in .success(()) })
        #expect(conn == nil)
    }

    @Test("Listener shutdown finishes the stream and rejects future connections", .timeLimit(.minutes(1)))
    func listenerShutdownFinishesStreamAndRejectsConnections() async throws {
        let cert = try WebRTCTestIdentity.make()
        let listener = WebRTCListener(certificate: cert)
        var iterator = listener.connections.makeAsyncIterator()

        listener.shutdown()

        let nextConnection = await iterator.next()
        #expect(nextConnection == nil)
        #expect(try listener.acceptConnection(
            peerID: "after-shutdown",
            sendHandler: { _ in .success(()) }
        ) == nil)
    }

    @Test("Listener remove connection")
    func listenerRemoveConnection() throws {
        let cert = try WebRTCTestIdentity.make()
        let listener = WebRTCListener(certificate: cert)

        let _ = try listener.acceptConnection(peerID: "peer1", sendHandler: { _ in .success(()) })
        #expect(listener.connection(for: "peer1") != nil)

        listener.removeConnection(peerID: "peer1")
        #expect(listener.connection(for: "peer1") == nil)
    }

    @Test("Listener closes all connections on close")
    func listenerClosesAllConnections() throws {
        let cert = try WebRTCTestIdentity.make()
        let listener = WebRTCListener(certificate: cert)

        let conn1 = try listener.acceptConnection(peerID: "peer1", sendHandler: { _ in .success(()) })
        let conn2 = try listener.acceptConnection(peerID: "peer2", sendHandler: { _ in .success(()) })

        listener.close()

        #expect(conn1?.state == .closed)
        #expect(conn2?.state == .closed)
    }

    @Test("Listener shutdown closes every active connection", .timeLimit(.minutes(1)))
    func listenerShutdownClosesActiveConnections() throws {
        let cert = try WebRTCTestIdentity.make()
        let listener = WebRTCListener(certificate: cert)
        let first = try #require(try listener.acceptConnection(
            peerID: "shutdown-peer-1",
            sendHandler: { _ in .success(()) }
        ))
        let second = try #require(try listener.acceptConnection(
            peerID: "shutdown-peer-2",
            sendHandler: { _ in .success(()) }
        ))

        listener.shutdown()

        #expect(first.state == .closed)
        #expect(second.state == .closed)
        #expect(listener.connection(for: "shutdown-peer-1") == nil)
        #expect(listener.connection(for: "shutdown-peer-2") == nil)
    }

    @Test("Listener shutdown and close are idempotent in either order", .timeLimit(.minutes(1)))
    func listenerShutdownAndCloseAreIdempotentInEitherOrder() throws {
        let cert = try WebRTCTestIdentity.make()

        let shutdownFirst = WebRTCListener(certificate: cert)
        let shutdownFirstConnection = try #require(
            try shutdownFirst.acceptConnection(
                peerID: "shutdown-first",
                sendHandler: { _ in .success(()) }
            )
        )
        shutdownFirst.shutdown()
        shutdownFirst.close()
        shutdownFirst.shutdown()

        #expect(shutdownFirstConnection.state == .closed)
        #expect(try shutdownFirst.acceptConnection(
            peerID: "after-shutdown-first",
            sendHandler: { _ in .success(()) }
        ) == nil)

        let closeFirst = WebRTCListener(certificate: cert)
        let closeFirstConnection = try #require(
            try closeFirst.acceptConnection(
                peerID: "close-first",
                sendHandler: { _ in .success(()) }
            )
        )
        closeFirst.close()
        closeFirst.shutdown()
        closeFirst.close()

        #expect(closeFirstConnection.state == .closed)
        #expect(try closeFirst.acceptConnection(
            peerID: "after-close-first",
            sendHandler: { _ in .success(()) }
        ) == nil)
    }

    @Test("Connections accepted before subscription are buffered")
    func connectionsBufferedBeforeSubscription() async throws {
        let cert = try WebRTCTestIdentity.make()
        let listener = WebRTCListener(certificate: cert)

        // Accept BEFORE anyone iterates `connections` — the eager stream
        // must buffer the connection instead of dropping it
        let accepted = try listener.acceptConnection(peerID: "peer1", sendHandler: { _ in .success(()) })
        #expect(accepted != nil)

        // Finish the stream so iteration terminates
        listener.close()

        var received: [WebRTCConnection] = []
        for await conn in listener.connections {
            received.append(conn)
        }
        #expect(received.count == 1)
        #expect(received.first === accepted)
    }

    /// Many concurrent `acceptConnection` calls for the SAME peerID must all
    /// observe a single claimed connection — never two. Two accepts both passing
    /// the nil-check would orphan one connection's retransmitTask / DTLS state.
    /// The check-and-claim is one critical section, so every caller that gets a
    /// non-nil result gets the identical object, and the listener holds exactly one.
    @Test("Concurrent accepts for the same peer never orphan a connection", .timeLimit(.minutes(1)))
    func concurrentAcceptsDoNotOrphan() async throws {
        let cert = try WebRTCTestIdentity.make()
        let listener = WebRTCListener(certificate: cert)
        let peerID = "10.0.0.9:7000"

        // Race many tasks claiming the same peerID at once.
        let results: [WebRTCConnection] = try await withThrowingTaskGroup(of: WebRTCConnection?.self) { group in
            for _ in 0..<64 {
                group.addTask {
                    try listener.acceptConnection(peerID: peerID, sendHandler: { _ in .success(()) })
                }
            }
            var collected: [WebRTCConnection] = []
            for try await conn in group {
                if let conn { collected.append(conn) }
            }
            return collected
        }

        // Every successful caller observed the SAME connection object.
        let first = try #require(results.first)
        for conn in results {
            #expect(conn === first)
        }

        // The listener holds exactly that one connection for the peer, and it was
        // started (DTLS handshake state machine engaged), not orphaned.
        #expect(listener.connection(for: peerID) === first)
        #expect(first.state == .dtlsHandshaking)

        listener.close()
    }

    @Test("Listener close never returns an unpublished accepted connection", .timeLimit(.minutes(1)))
    func listenerCloseDoesNotPublishClosedConnection() async throws {
        let cert = try WebRTCTestIdentity.make()
        let listener = WebRTCListener(certificate: cert)
        let stream = listener.connections

        let consumer = Task { () -> [WebRTCConnection] in
            var received: [WebRTCConnection] = []
            for await connection in stream {
                received.append(connection)
            }
            return received
        }

        let returned = try await withThrowingTaskGroup(of: WebRTCConnection?.self) { group in
            for index in 0..<160 {
                group.addTask {
                    if index.isMultiple(of: 8) {
                        await Task.yield()
                        listener.close()
                        return nil
                    }
                    return try listener.acceptConnection(
                        peerID: "race-peer-\(index)",
                        sendHandler: { _ in .success(()) }
                    )
                }
            }

            var accepted: [WebRTCConnection] = []
            for try await connection in group {
                if let connection {
                    accepted.append(connection)
                }
            }
            return accepted
        }

        listener.close()
        let streamed = await consumer.value

        // A non-nil return means yield linearized before stream termination.
        // If close won, acceptConnection must return nil instead of returning a
        // connection whose yield was rejected by the terminated stream.
        for connection in returned {
            #expect(streamed.contains { $0 === connection })
            #expect(connection.state == .closed)
        }
    }

    @Test("Stream consumer can close listener reentrantly", .timeLimit(.minutes(1)))
    func streamConsumerCanCloseListenerReentrantly() async throws {
        let cert = try WebRTCTestIdentity.make()
        let listener = WebRTCListener(certificate: cert)
        let stream = listener.connections

        let consumer = Task { () -> WebRTCConnection? in
            for await connection in stream {
                listener.close()
                return connection
            }
            return nil
        }

        let accepted = try listener.acceptConnection(peerID: "reentrant-peer", sendHandler: { _ in .success(()) })
        let received = await consumer.value

        #expect(received === accepted)
        #expect(try listener.acceptConnection(peerID: "after-close", sendHandler: { _ in .success(()) }) == nil)
    }
}
