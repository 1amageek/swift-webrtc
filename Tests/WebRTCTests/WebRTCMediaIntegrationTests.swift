import Synchronization
import Testing
@testable import WebRTC
@Suite("WebRTC authenticated media integration")
struct WebRTCMediaIntegrationTests {
    @Test("DTLS exporter keys protect and deliver RTP end to end", .timeLimit(.minutes(1)))
    func rtpRoundTrip() throws {
        let pair = try MediaConnectionPair()
        try pair.completeHandshake()

        #expect(pair.client.isMediaReady)
        #expect(pair.server.isMediaReady)

        let received = Mutex<WebRTCRTPPacket?>(nil)
        pair.server.setRTPHandler { packet in
            received.withLock { $0 = packet }
        }

        let plaintext = Self.rtpPacket(sequenceNumber: 1, payload: [0x10, 0x20, 0x30, 0x40])
        try pair.client.sendRTP(plaintext)
        let protected = try #require(pair.nextClientDatagram())

        #expect(protected != plaintext)
        #expect(protected.count == plaintext.count + 10)
        #expect(protected.first.map { (128...191).contains($0) } == true)
        #expect(pair.nextClientDatagram() == nil)
        try pair.server.receive(protected)

        let delivered = try #require(received.withLock { $0 })
        #expect(delivered.bytes == plaintext)
        #expect(Array(delivered.payload) == [0x10, 0x20, 0x30, 0x40])
        #expect(delivered.layout.fixedHeader.payloadType == 96)
    }

    @Test("Tampered SRTP is dropped without consuming replay state", .timeLimit(.minutes(1)))
    func tamperDoesNotConsumeReplayState() throws {
        let pair = try MediaConnectionPair()
        try pair.completeHandshake()

        let deliveryCount = Mutex(0)
        pair.server.setRTPHandler { _ in
            deliveryCount.withLock { $0 += 1 }
        }

        try pair.client.sendRTP(Self.rtpPacket(sequenceNumber: 7, payload: [1, 2, 3, 4]))
        let authentic = try #require(pair.nextClientDatagram())
        var tampered = authentic
        tampered[tampered.count - 1] ^= 0x01

        try pair.server.receive(tampered)
        #expect(deliveryCount.withLock { $0 } == 0)

        try pair.server.receive(authentic)
        #expect(deliveryCount.withLock { $0 } == 1)

        // A replay is a recoverable network condition and is never delivered.
        try pair.server.receive(authentic)
        #expect(deliveryCount.withLock { $0 } == 1)
    }

    @Test("DTLS exporter keys protect and deliver SRTCP end to end", .timeLimit(.minutes(1)))
    func rtcpRoundTrip() throws {
        let pair = try MediaConnectionPair()
        try pair.completeHandshake()

        let received = Mutex<WebRTCRTCPPacket?>(nil)
        pair.server.setRTCPHandler { packet in
            received.withLock { $0 = packet }
        }

        let plaintext: [UInt8] = [
            0x81, 0xCE, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88,
        ]
        try pair.client.sendRTCP(plaintext)
        let protected = try #require(pair.nextClientDatagram())

        #expect(protected.count == plaintext.count + 14)
        try pair.server.receive(protected)

        let delivered = try #require(received.withLock { $0 })
        #expect(delivered.bytes == plaintext)
        #expect(delivered.layout.packetLayouts.count == 1)
        #expect(delivered.layout.packetLayouts[0].commonHeader.packetType == 206)
    }

    @Test("Rejected RTP keeps its SRTP packet index consumed", .timeLimit(.minutes(1)))
    func rejectedRTPDoesNotReusePacketIndex() throws {
        let pair = try MediaConnectionPair()
        try pair.completeHandshake()
        pair.rejectNextClientDatagram(with: .backpressured)

        let rejected = Self.rtpPacket(sequenceNumber: 41, payload: [0xA1, 0xA2])
        do {
            try pair.client.sendRTP(rejected)
            Issue.record("Expected transport backpressure")
        } catch WebRTCError.datagramSendFailed(let failure) {
            #expect(failure == .backpressured)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        do {
            try pair.client.sendRTP(rejected)
            Issue.record("Expected the already-protected SRTP index to be rejected")
        } catch WebRTCError.mediaProtectionFailed(let failure) {
            guard case .outboundIndexReuse(_, let index) = failure else {
                Issue.record("Unexpected SRTP failure: \(failure)")
                return
            }
            #expect(index == 41)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        try pair.client.sendRTP(Self.rtpPacket(sequenceNumber: 42, payload: [0xB1]))
        #expect(pair.nextClientDatagram() != nil)
    }

    @Test("Rejected SRTCP keeps its outbound index consumed", .timeLimit(.minutes(1)))
    func rejectedSRTCPDoesNotReusePacketIndex() throws {
        let pair = try MediaConnectionPair()
        try pair.completeHandshake()
        pair.rejectNextClientDatagram(with: .backpressured)
        let plaintext: [UInt8] = [
            0x81, 0xCE, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88,
        ]

        do {
            try pair.client.sendRTCP(plaintext)
            Issue.record("Expected transport backpressure")
        } catch WebRTCError.datagramSendFailed(let failure) {
            #expect(failure == .backpressured)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        try pair.client.sendRTCP(plaintext)
        let protected = try #require(pair.nextClientDatagram())
        let trailerOffset = protected.count - 14
        let indexWord = UInt32(protected[trailerOffset]) << 24
            | UInt32(protected[trailerOffset + 1]) << 16
            | UInt32(protected[trailerOffset + 2]) << 8
            | UInt32(protected[trailerOffset + 3])
        #expect(indexWord & 0x7FFF_FFFF == 1)
    }

    @Test("Rejected SCTP initial send terminates the committed association", .timeLimit(.minutes(1)))
    func rejectedSCTPSendIsTerminal() throws {
        let pair = try MediaConnectionPair()
        try pair.completeHandshake()
        let channelID = try pair.openClientDataChannel()
        #expect(pair.client.state == .connected)
        pair.rejectNextClientDatagram(with: .backpressured)

        do {
            try pair.client.send([0x01, 0x02], on: channelID)
            Issue.record("Expected transport backpressure")
        } catch WebRTCError.datagramSendFailed(let failure) {
            #expect(failure == .backpressured)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        #expect(pair.client.state.isTerminal)
        guard let terminalFailure = pair.client.terminalFailure else {
            Issue.record("Expected a typed terminal failure")
            return
        }
        guard case .datagramSendFailed(.backpressured) = terminalFailure else {
            Issue.record("Unexpected terminal failure: \(terminalFailure)")
            return
        }
    }

    @Test("Reserved RTP storage reaches the transport without relocation", .timeLimit(.minutes(1)))
    func reservedRTPStorageIsStable() throws {
        let pair = try MediaConnectionPair()
        try pair.completeHandshake()
        var packet = Self.rtpPacket(sequenceNumber: 73, payload: [0x10, 0x20, 0x30])
        packet.reserveCapacity(
            packet.count
                + WebRTCMediaProtectionProfile.aes128CMHMACSHA180
                    .rtpProtectionTrailerByteCount
        )
        let sourceBaseAddress = packet.withUnsafeBytes { buffer in
            buffer.baseAddress.map { UInt(bitPattern: $0) }
        }

        try pair.client.sendRTP(consume packet)

        #expect(pair.clientLastAcceptedBaseAddress() == sourceBaseAddress)
    }

    @Test("Inbound RTP storage reaches the handler without relocation", .timeLimit(.minutes(1)))
    func inboundRTPStorageIsStable() throws {
        let pair = try MediaConnectionPair()
        try pair.completeHandshake()
        let receivedBaseAddress = Mutex<UInt?>(nil)
        pair.server.setRTPHandler { packet in
            receivedBaseAddress.withLock { address in
                address = packet.bytes.withUnsafeBytes { buffer in
                    buffer.baseAddress.map { UInt(bitPattern: $0) }
                }
            }
        }

        try pair.client.sendRTP(
            Self.rtpPacket(sequenceNumber: 74, payload: [0x10, 0x20, 0x30])
        )
        let protected = try #require(pair.nextClientDatagram())
        let protectedBaseAddress = protected.withUnsafeBytes { buffer in
            buffer.baseAddress.map { UInt(bitPattern: $0) }
        }

        try pair.server.receive(consume protected)

        #expect(receivedBaseAddress.withLock { $0 } == protectedBaseAddress)
    }

    @Test("Reserved SRTCP storage reaches the transport without relocation", .timeLimit(.minutes(1)))
    func reservedSRTCPStorageIsStable() throws {
        let pair = try MediaConnectionPair()
        try pair.completeHandshake()
        var packet: [UInt8] = [
            0x81, 0xCE, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88,
        ]
        packet.reserveCapacity(
            packet.count
                + WebRTCMediaProtectionProfile.aes128CMHMACSHA180
                    .rtcpProtectionTrailerByteCount
        )
        let sourceBaseAddress = packet.withUnsafeBytes { buffer in
            buffer.baseAddress.map { UInt(bitPattern: $0) }
        }

        try pair.client.sendRTCP(consume packet)

        #expect(pair.clientLastAcceptedBaseAddress() == sourceBaseAddress)
    }

    @Test("Inbound RTCP storage reaches the handler without relocation", .timeLimit(.minutes(1)))
    func inboundRTCPStorageIsStable() throws {
        let pair = try MediaConnectionPair()
        try pair.completeHandshake()
        let receivedBaseAddress = Mutex<UInt?>(nil)
        pair.server.setRTCPHandler { packet in
            receivedBaseAddress.withLock { address in
                address = packet.bytes.withUnsafeBytes { buffer in
                    buffer.baseAddress.map { UInt(bitPattern: $0) }
                }
            }
        }
        let plaintext: [UInt8] = [
            0x81, 0xCE, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88,
        ]

        try pair.client.sendRTCP(plaintext)
        let protected = try #require(pair.nextClientDatagram())
        let protectedBaseAddress = protected.withUnsafeBytes { buffer in
            buffer.baseAddress.map { UInt(bitPattern: $0) }
        }

        try pair.server.receive(consume protected)

        #expect(receivedBaseAddress.withLock { $0 } == protectedBaseAddress)
    }

    @Test("Rejected SCTP response makes receive terminal", .timeLimit(.minutes(1)))
    func rejectedSCTPResponseIsTerminal() throws {
        let pair = try MediaConnectionPair()
        try pair.completeHandshake()
        let channelID = try pair.openClientDataChannel()
        pair.rejectNextServerDatagram(with: .backpressured)

        try pair.client.send([0xCA, 0xFE], on: channelID)
        let dataDatagram = try #require(pair.nextClientDatagram())
        do {
            try pair.server.receive(dataDatagram)
            Issue.record("Expected the rejected SACK datagram to fail")
        } catch WebRTCError.datagramSendFailed(let failure) {
            #expect(failure == .backpressured)
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        #expect(pair.server.state.isTerminal)
        guard let terminalFailure = pair.server.terminalFailure else {
            Issue.record("Expected a typed terminal failure")
            return
        }
        guard case .datagramSendFailed(.backpressured) = terminalFailure else {
            Issue.record("Unexpected terminal failure: \(terminalFailure)")
            return
        }
    }

    @Test("DCEP open fails terminally after SCTP queue rejection", .timeLimit(.minutes(1)))
    func rejectedDCEPOpenDoesNotLeaveReusableGhostChannel() throws {
        let pair = try MediaConnectionPair()
        try pair.completeHandshake()
        let channelID = try pair.openClientDataChannel()
        let payload = [UInt8](repeating: 0xA5, count: 8_192)
        for _ in 0..<128 {
            try pair.client.send(payload, on: channelID)
        }

        do {
            _ = try pair.client.openDataChannel(label: "must-not-escape")
            Issue.record("Expected the full SCTP queue to reject DCEP OPEN")
        } catch WebRTCError.sctpProtocolFailed {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }

        #expect(pair.client.state.isTerminal)
        guard let terminalFailure = pair.client.terminalFailure else {
            Issue.record("Expected a typed terminal failure")
            return
        }
        guard case .sctpProtocolFailed = terminalFailure else {
            Issue.record("Unexpected terminal failure: \(terminalFailure)")
            return
        }
    }

    @Test("Background SCTP retransmission preserves typed transport failure", .timeLimit(.minutes(1)))
    func backgroundRetransmissionFailureIsObservable() async throws {
        let pair = try MediaConnectionPair()
        try pair.completeHandshake()
        let channelID = try pair.openClientDataChannel()
        try pair.client.send([0xD0, 0x0D], on: channelID)
        _ = try #require(pair.nextClientDatagram())
        pair.rejectNextClientDatagram(with: .destinationUnreachable)

        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !pair.client.state.isTerminal, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(20))
        }

        #expect(pair.client.state.isTerminal)
        guard let terminalFailure = pair.client.terminalFailure else {
            Issue.record("Expected a typed terminal failure")
            return
        }
        guard case .datagramSendFailed(.destinationUnreachable) = terminalFailure else {
            Issue.record("Unexpected terminal failure: \(terminalFailure)")
            return
        }
    }

    @Test("Media server construction requires a signaling-bound peer fingerprint")
    func mediaServerRequiresPeerAuthentication() throws {
        let certificate = try WebRTCTestIdentity.make()
        let configuration = try WebRTCMediaConfiguration(rtpPayloadTypes: [96])

        do {
            _ = try WebRTCConnection.asServer(
                certificate: certificate,
                mediaConfiguration: configuration,
                sendHandler: { _ in .success(()) }
            )
            Issue.record("Expected media construction to require the remote fingerprint")
        } catch WebRTCError.mediaPeerAuthenticationRequired {
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test(
        "Close releases installed media handlers and rejects later registration",
        .timeLimit(.minutes(1))
    )
    func closePermanentlyDetachesMediaHandlers() throws {
        let pair = try MediaConnectionPair()

        weak var installedToken: MediaHandlerLifetimeToken?
        do {
            let token = MediaHandlerLifetimeToken()
            installedToken = token
            switch pair.client.setRTPHandler({ [token] _ in
                withExtendedLifetime(token) {}
            }) {
            case .success:
                break
            case .failure(let error):
                Issue.record("Unexpected registration failure: \(error)")
            }
        }
        #expect(installedToken != nil)

        pair.client.close()
        #expect(installedToken == nil)

        weak var rejectedRTPToken: MediaHandlerLifetimeToken?
        do {
            let token = MediaHandlerLifetimeToken()
            rejectedRTPToken = token
            switch pair.client.setRTPHandler({ [token] _ in
                withExtendedLifetime(token) {}
            }) {
            case .failure(.closed):
                break
            case .success:
                Issue.record("Expected closed RTP registration to fail")
            case .failure(let error):
                Issue.record("Unexpected RTP registration failure: \(error)")
            }
        }
        #expect(rejectedRTPToken == nil)

        weak var rejectedRTCPToken: MediaHandlerLifetimeToken?
        do {
            let token = MediaHandlerLifetimeToken()
            rejectedRTCPToken = token
            switch pair.client.setRTCPHandler({ [token] _ in
                withExtendedLifetime(token) {}
            }) {
            case .failure(.closed):
                break
            case .success:
                Issue.record("Expected closed RTCP registration to fail")
            case .failure(let error):
                Issue.record("Unexpected RTCP registration failure: \(error)")
            }
        }
        #expect(rejectedRTCPToken == nil)
    }

    private static func rtpPacket(
        sequenceNumber: UInt16,
        payload: [UInt8]
    ) -> [UInt8] {
        [
            0x80, 0x60,
            UInt8(truncatingIfNeeded: sequenceNumber >> 8),
            UInt8(truncatingIfNeeded: sequenceNumber),
            0x01, 0x02, 0x03, 0x04,
            0x11, 0x22, 0x33, 0x44,
        ] + payload
    }
}

private final class MediaHandlerLifetimeToken: Sendable {}

private final class MediaConnectionPair {
    let client: WebRTCConnection
    let server: WebRTCConnection

    private let clientOutbox: DatagramOutbox
    private let serverOutbox: DatagramOutbox

    init() throws {
        let clientCertificate = try WebRTCTestIdentity.make()
        let serverCertificate = try WebRTCTestIdentity.make()
        let media = try WebRTCMediaConfiguration(
            rtpPayloadTypes: [96],
            allowsReducedSizeRTCP: true
        )
        let clientOutbox = DatagramOutbox()
        let serverOutbox = DatagramOutbox()
        self.clientOutbox = clientOutbox
        self.serverOutbox = serverOutbox

        self.client = try WebRTCConnection.asClient(
            certificate: clientCertificate,
            remoteFingerprint: serverCertificate.fingerprint,
            mediaConfiguration: media,
            sendHandler: { [clientOutbox] datagram in
                clientOutbox.accept(datagram)
            }
        )
        self.server = try WebRTCConnection.asServer(
            certificate: serverCertificate,
            remoteFingerprint: clientCertificate.fingerprint,
            mediaConfiguration: media,
            sendHandler: { [serverOutbox] datagram in
                serverOutbox.accept(datagram)
            }
        )
    }

    func completeHandshake() throws {
        try server.start()
        try client.start()

        for _ in 0..<32 {
            let toServer = clientOutbox.drain()
            for datagram in toServer {
                try server.receive(datagram)
            }

            let toClient = serverOutbox.drain()
            for datagram in toClient {
                try client.receive(datagram)
            }

            if client.isMediaReady,
               server.isMediaReady,
               client.state == .connected,
               server.state == .connected,
               clientOutbox.isEmpty,
               serverOutbox.isEmpty {
                return
            }
        }

        Issue.record("DTLS-SRTP handshake did not settle within the flight budget")
    }

    func nextClientDatagram() -> [UInt8]? {
        clientOutbox.next()
    }

    func openClientDataChannel() throws -> UInt16 {
        let channel = try client.openDataChannel(label: "media-test")
        for _ in 0..<16 {
            let toServer = clientOutbox.drain()
            for datagram in toServer {
                try server.receive(datagram)
            }
            let toClient = serverOutbox.drain()
            for datagram in toClient {
                try client.receive(datagram)
            }
            if clientOutbox.isEmpty && serverOutbox.isEmpty {
                return channel.id
            }
        }
        Issue.record("Data-channel DCEP handshake did not settle")
        return channel.id
    }

    func rejectNextClientDatagram(with failure: WebRTCDatagramSendFailure) {
        clientOutbox.rejectNext(with: failure)
    }

    func rejectNextServerDatagram(with failure: WebRTCDatagramSendFailure) {
        serverOutbox.rejectNext(with: failure)
    }

    func clientLastAcceptedBaseAddress() -> UInt? {
        clientOutbox.lastAcceptedBaseAddress
    }
}

private final class DatagramOutbox: Sendable {
    private struct State: Sendable {
        var datagrams: [[UInt8]] = []
        var nextFailure: WebRTCDatagramSendFailure?
        var lastAcceptedBaseAddress: UInt?
    }

    private let state = Mutex(State())

    var isEmpty: Bool {
        state.withLock { $0.datagrams.isEmpty }
    }

    var lastAcceptedBaseAddress: UInt? {
        state.withLock { $0.lastAcceptedBaseAddress }
    }

    func accept(_ datagram: [UInt8]) -> Result<Void, WebRTCDatagramSendFailure> {
        state.withLock { state in
            if let failure = state.nextFailure {
                state.nextFailure = nil
                return .failure(failure)
            }
            state.lastAcceptedBaseAddress = datagram.withUnsafeBytes { buffer in
                buffer.baseAddress.map { UInt(bitPattern: $0) }
            }
            state.datagrams.append(datagram)
            return .success(())
        }
    }

    func rejectNext(with failure: WebRTCDatagramSendFailure) {
        state.withLock { $0.nextFailure = failure }
    }

    func drain() -> [[UInt8]] {
        state.withLock { state in
            let pending = state.datagrams
            state.datagrams.removeAll(keepingCapacity: true)
            return pending
        }
    }

    func next() -> [UInt8]? {
        state.withLock { state in
            guard !state.datagrams.isEmpty else { return nil }
            return state.datagrams.removeFirst()
        }
    }
}
