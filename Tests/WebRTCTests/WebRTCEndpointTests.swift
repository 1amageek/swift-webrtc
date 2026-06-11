/// Tests for WebRTC Integration

import Testing
import Foundation
import Synchronization
@testable import WebRTC
@testable import DTLSCore

@Suite("WebRTC Endpoint Tests")
struct WebRTCEndpointTests {

    @Test("Create endpoint with self-signed certificate")
    func createEndpoint() throws {
        let endpoint = try WebRTCEndpoint.create()
        #expect(endpoint.localFingerprint.bytes.count == 32)
    }

    @Test("Create client connection via endpoint")
    func createClientConnection() throws {
        let endpoint = try WebRTCEndpoint.create()
        let remoteFingerprint = CertificateFingerprint.fromDER(Data(repeating: 0xAB, count: 100))

        let connection = try endpoint.connect(
            remoteFingerprint: remoteFingerprint,
            sendHandler: { _ in }
        )

        #expect(connection.state == .new)
        #expect(connection.localFingerprint == endpoint.localFingerprint)
    }

    @Test("Create listener via endpoint")
    func createListener() throws {
        let endpoint = try WebRTCEndpoint.create()
        let listener = try endpoint.listen()

        #expect(listener.localFingerprint == endpoint.localFingerprint)
    }

    @Test("Endpoint close prevents new connections")
    func endpointClose() throws {
        let endpoint = try WebRTCEndpoint.create()
        endpoint.close()

        let remoteFingerprint = CertificateFingerprint.fromDER(Data(repeating: 0xAB, count: 100))

        #expect(throws: WebRTCError.self) {
            _ = try endpoint.connect(
                remoteFingerprint: remoteFingerprint,
                sendHandler: { _ in }
            )
        }

        #expect(throws: WebRTCError.self) {
            _ = try endpoint.listen()
        }
    }
}

@Suite("WebRTC Connection Tests")
struct WebRTCConnectionTests {

    @Test("Client connection initial state")
    func clientConnectionInitialState() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let remoteFingerprint = CertificateFingerprint.fromDER(Data(repeating: 0xCD, count: 100))

        let connection = WebRTCConnection.asClient(
            certificate: cert,
            remoteFingerprint: remoteFingerprint,
            sendHandler: { _ in }
        )

        #expect(connection.state == .new)
        #expect(connection.localFingerprint == cert.fingerprint)
        #expect(connection.remoteFingerprint == nil)
    }

    @Test("Server connection initial state")
    func serverConnectionInitialState() throws {
        let cert = try DTLSCertificate.generateSelfSigned()

        let connection = WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { _ in }
        )

        #expect(connection.state == .new)
        #expect(connection.localFingerprint == cert.fingerprint)
    }

    @Test("Client connection start triggers DTLS handshake")
    func clientStartSendsClientHello() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let remoteFingerprint = CertificateFingerprint.fromDER(Data(repeating: 0xEF, count: 100))

        let sentData = Mutex<[Data]>([])
        let connection = WebRTCConnection.asClient(
            certificate: cert,
            remoteFingerprint: remoteFingerprint,
            sendHandler: { data in
                sentData.withLock { $0.append(data) }
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
        let cert = try DTLSCertificate.generateSelfSigned()
        let connection = WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { _ in }
        )

        connection.close()
        #expect(connection.state == .closed)
    }

    @Test("ICE credentials are generated")
    func iceCredentials() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let connection = WebRTCConnection.asClient(
            certificate: cert,
            remoteFingerprint: CertificateFingerprint.fromDER(Data(repeating: 0, count: 32)),
            sendHandler: { _ in }
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
        let cert = try DTLSCertificate.generateSelfSigned()
        let listener = WebRTCListener(certificate: cert)

        let conn = listener.acceptConnection(peerID: "127.0.0.1:5000", sendHandler: { _ in })
        #expect(conn != nil)
        #expect(conn?.state == .dtlsHandshaking)
    }

    @Test("Listener returns existing connection for same peer")
    func listenerReturnsExistingConnection() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let listener = WebRTCListener(certificate: cert)

        let conn1 = listener.acceptConnection(peerID: "127.0.0.1:5000", sendHandler: { _ in })
        let conn2 = listener.acceptConnection(peerID: "127.0.0.1:5000", sendHandler: { _ in })

        // Same connection returned for same peer
        #expect(conn1 != nil)
        #expect(conn2 != nil)
        #expect(conn1 === conn2)
    }

    @Test("Listener replaces a terminal connection for the same peer")
    func listenerReplacesTerminalConnection() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let listener = WebRTCListener(certificate: cert)

        let accepted1 = listener.acceptConnection(peerID: "127.0.0.1:5000", sendHandler: { _ in })
        let conn1 = try #require(accepted1)
        conn1.close()
        #expect(conn1.state.isTerminal)

        // A reconnect attempt from the same address must get a fresh
        // connection, not the dead one
        let accepted2 = listener.acceptConnection(peerID: "127.0.0.1:5000", sendHandler: { _ in })
        let conn2 = try #require(accepted2)
        #expect(conn1 !== conn2)
        #expect(conn2.state == .dtlsHandshaking)
        #expect(listener.connection(for: "127.0.0.1:5000") === conn2)
    }

    @Test("Listener returns nil after close")
    func listenerCloseRejectsConnections() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let listener = WebRTCListener(certificate: cert)

        listener.close()

        let conn = listener.acceptConnection(peerID: "127.0.0.1:5000", sendHandler: { _ in })
        #expect(conn == nil)
    }

    @Test("Listener remove connection")
    func listenerRemoveConnection() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let listener = WebRTCListener(certificate: cert)

        let _ = listener.acceptConnection(peerID: "peer1", sendHandler: { _ in })
        #expect(listener.connection(for: "peer1") != nil)

        listener.removeConnection(peerID: "peer1")
        #expect(listener.connection(for: "peer1") == nil)
    }

    @Test("Listener closes all connections on close")
    func listenerClosesAllConnections() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let listener = WebRTCListener(certificate: cert)

        let conn1 = listener.acceptConnection(peerID: "peer1", sendHandler: { _ in })
        let conn2 = listener.acceptConnection(peerID: "peer2", sendHandler: { _ in })

        listener.close()

        #expect(conn1?.state == .closed)
        #expect(conn2?.state == .closed)
    }

    @Test("Connections accepted before subscription are buffered")
    func connectionsBufferedBeforeSubscription() async throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let listener = WebRTCListener(certificate: cert)

        // Accept BEFORE anyone iterates `connections` — the eager stream
        // must buffer the connection instead of dropping it
        let accepted = listener.acceptConnection(peerID: "peer1", sendHandler: { _ in })
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
}
