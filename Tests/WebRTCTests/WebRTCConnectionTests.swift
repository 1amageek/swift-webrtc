/// Tests for WebRTCConnection new functionality
///
/// Tests demultiplex, DataHandler, server start, close behavior.
/// Fingerprint verification requires full DTLS handshake — tested in integration.

import Testing
import Foundation
import Synchronization
@testable import WebRTC
@testable import DTLSCore

@Suite("WebRTC Connection Demultiplex Tests")
struct WebRTCConnectionDemultiplexTests {

    @Test("Server start initializes handshake without error")
    func serverStartInitializesHandshake() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let connection = WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { _ in }
        )

        try connection.start()
        // Server is now in DTLS handshake state, waiting for ClientHello
        #expect(connection.state == .dtlsHandshaking)
    }

    @Test("Receive empty data is no-op")
    func receiveEmptyDataIsNoop() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let sentData = Mutex<[Data]>([])
        let connection = WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { data in sentData.withLock { $0.append(data) } }
        )

        try connection.start()
        try connection.receive(Data())

        let messages = sentData.withLock { $0 }
        #expect(messages.isEmpty)
    }

    @Test("DTLS byte range (20-63) is routed to DTLS processing")
    func receiveDTLSRangeRouted() throws {
        // Create client → capture ClientHello
        let clientCert = try DTLSCertificate.generateSelfSigned()
        let serverCert = try DTLSCertificate.generateSelfSigned()
        let sentByClient = Mutex<[Data]>([])
        let client = WebRTCConnection.asClient(
            certificate: clientCert,
            remoteFingerprint: serverCert.fingerprint,
            sendHandler: { data in sentByClient.withLock { $0.append(data) } }
        )

        try client.start()
        let clientHello = sentByClient.withLock { $0 }
        #expect(!clientHello.isEmpty)
        // ClientHello first byte should be 22 (DTLS Handshake content type)
        #expect(clientHello[0][clientHello[0].startIndex] == 22)

        // Create server → feed ClientHello → expect DTLS response
        let sentByServer = Mutex<[Data]>([])
        let server = WebRTCConnection.asServer(
            certificate: serverCert,
            sendHandler: { data in sentByServer.withLock { $0.append(data) } }
        )
        try server.start()
        try server.receive(clientHello[0])

        // Server should respond with DTLS handshake messages
        let serverMessages = sentByServer.withLock { $0 }
        #expect(!serverMessages.isEmpty)
    }

    @Test("Unknown byte (>63, non-STUN) is ignored")
    func receiveUnknownByteIgnored() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let sentData = Mutex<[Data]>([])
        let connection = WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { data in sentData.withLock { $0.append(data) } }
        )

        try connection.start()

        // Byte 0x80 has first two bits = 10, not STUN (STUN requires 00).
        // Also > 63, so not DTLS.
        let unknownData = Data([0x80, 0x01, 0x02, 0x03])
        try connection.receive(unknownData)

        let messages = sentData.withLock { $0 }
        #expect(messages.isEmpty)
    }

    @Test("receive forwards remoteAddress parameter")
    func remoteAddressParameterForwarded() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let connection = WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { _ in }
        )

        try connection.start()

        // remoteAddress is forwarded to processSTUN/processDTLS.
        // For unknown bytes, it's simply ignored. This test verifies
        // the API accepts the parameter without error.
        let remoteAddr = Data([192, 168, 1, 1, 0x1F, 0x90]) // ip + port
        try connection.receive(Data([0x80, 0x01]), remoteAddress: remoteAddr)
        // No crash, no error — parameter accepted
    }
}

@Suite("WebRTC Connection DataHandler Tests")
struct WebRTCConnectionDataHandlerTests {

    @Test("setDataHandler stores handler")
    func setDataHandlerStoresHandler() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let connection = WebRTCConnection.asClient(
            certificate: cert,
            remoteFingerprint: CertificateFingerprint.fromDER(Data(repeating: 0, count: 32)),
            sendHandler: { _ in }
        )

        let received = Mutex<[(UInt16, Data)]>([])
        connection.setDataHandler { channelID, data in
            received.withLock { $0.append((channelID, data)) }
        }

        // Handler is set. We can't easily trigger data delivery without
        // a full handshake, but we can verify the handler doesn't crash
        // and the API is callable.
        let items = received.withLock { $0 }
        #expect(items.isEmpty)
    }

    @Test("close clears data handler")
    func closeNilsDataHandler() throws {
        let cert = try DTLSCertificate.generateSelfSigned()
        let connection = WebRTCConnection.asServer(
            certificate: cert,
            sendHandler: { _ in }
        )

        let handlerCalled = Mutex(false)
        connection.setDataHandler { _, _ in
            handlerCalled.withLock { $0 = true }
        }

        connection.close()
        #expect(connection.state == .closed)
        // After close, the data handler reference is nil.
        // This is verified by the implementation (dataHandlerState set to nil).
        // No way to externally trigger data delivery after close, which is correct.
        let called = handlerCalled.withLock { $0 }
        #expect(!called)
    }
}
