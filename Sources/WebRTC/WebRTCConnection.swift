/// WebRTC Connection
///
/// Integrates the full WebRTC Direct protocol stack:
/// UDP → STUN/ICE Lite → DTLS 1.2 → SCTP → Data Channels
///
/// Transport-agnostic: uses a send closure for outgoing data and
/// a `receive(_:remoteAddress:)` method for incoming data.
///
/// DTLS is fully delegated to `DTLSConnection` (from DTLSRecord).

import Foundation
import Synchronization
import DTLSCore
import DTLSRecord
import STUNCore
import ICELite
import SCTPCore
import DataChannel
import Logging

/// A WebRTC Direct connection over UDP
///
/// ## Concurrency
///
/// All public methods are thread-safe. Datagrams passed to
/// `receive(_:remoteAddress:)` should be delivered from a single task at a
/// time: concurrent calls may reorder DTLS records and SCTP TSNs. SCTP
/// tolerates reordering via SACK and retransmission, so this affects latency
/// rather than correctness. No internal lock is held while invoking
/// `SendHandler` or `DataHandler` callbacks, so synchronous loopback
/// transports cannot deadlock.
public final class WebRTCConnection: Sendable {

    /// Callback to send raw bytes to the remote peer
    public typealias SendHandler = @Sendable (Data) -> Void

    /// Callback to deliver application data (channelID, payload)
    public typealias DataHandler = @Sendable (UInt16, Data) -> Void

    // MARK: - Public properties

    /// Current connection state
    public var state: WebRTCConnectionState {
        connState.withLock { $0.state }
    }

    /// Local certificate fingerprint
    public let localFingerprint: CertificateFingerprint

    /// Remote certificate fingerprint (available after DTLS handshake)
    public var remoteFingerprint: CertificateFingerprint? {
        dtlsConnection.remoteFingerprint
    }

    /// Remote peer's DER-encoded certificate (available after DTLS handshake)
    public var remoteCertificateDER: Data? {
        dtlsConnection.remoteCertificateDER
    }

    /// Stream of incoming data channels opened by the remote peer.
    ///
    /// The stream is created eagerly at init, so channels announced before
    /// the first subscription are buffered rather than dropped. The stream
    /// finishes when the connection closes or fails.
    public var incomingChannels: AsyncStream<DataChannel> {
        channelState.withLock { $0.incomingStream }
    }

    // MARK: - Private state

    private let dtlsConnection: DTLSConnection
    private let connState: Mutex<ConnState>
    private let channelState: Mutex<ChannelState>
    private let dataHandlerState: Mutex<DataHandler?>
    private let sendHandler: SendHandler
    private let expectedFingerprint: CertificateFingerprint?
    private let logger: Logger

    /// Periodic driver for SCTP T3-rtx retransmissions
    private let retransmitTask: Mutex<Task<Void, Never>?>

    /// Interval between retransmission timer checks
    private static let retransmitTickInterval: Duration = .milliseconds(250)

    private struct ConnState: Sendable {
        var stateMachine: ConnectionStateMachine = ConnectionStateMachine()
        var iceAgent: ICELiteAgent
        var sctpAssociation: SCTPAssociation
        var channelManager: DataChannelManager
        var isClient: Bool

        var state: WebRTCConnectionState {
            stateMachine.state
        }
    }

    private struct ChannelState: Sendable {
        var incomingStream: AsyncStream<DataChannel>
        var incomingContinuation: AsyncStream<DataChannel>.Continuation?
    }

    // MARK: - Init

    /// Create a client-side connection
    public static func asClient(
        certificate: DTLSCertificate,
        remoteFingerprint expectedFingerprint: CertificateFingerprint,
        sendHandler: @escaping SendHandler,
        logger: Logger = Logger(label: "webrtc.connection")
    ) -> WebRTCConnection {
        WebRTCConnection(
            certificate: certificate,
            isClient: true,
            expectedFingerprint: expectedFingerprint,
            sendHandler: sendHandler,
            logger: logger
        )
    }

    /// Create a server-side connection
    public static func asServer(
        certificate: DTLSCertificate,
        sendHandler: @escaping SendHandler,
        logger: Logger = Logger(label: "webrtc.connection")
    ) -> WebRTCConnection {
        WebRTCConnection(
            certificate: certificate,
            isClient: false,
            expectedFingerprint: nil,
            sendHandler: sendHandler,
            logger: logger
        )
    }

    private init(
        certificate: DTLSCertificate,
        isClient: Bool,
        expectedFingerprint: CertificateFingerprint?,
        sendHandler: @escaping SendHandler,
        logger: Logger
    ) {
        self.localFingerprint = certificate.fingerprint
        self.dtlsConnection = DTLSConnection(certificate: certificate)
        self.expectedFingerprint = expectedFingerprint
        self.sendHandler = sendHandler
        self.logger = logger
        self.connState = Mutex(ConnState(
            iceAgent: ICELiteAgent(),
            sctpAssociation: SCTPAssociation(),
            channelManager: DataChannelManager(isInitiator: isClient),
            isClient: isClient
        ))
        // Create the stream eagerly so channels arriving before the first
        // subscription are buffered rather than dropped
        let (incomingStream, incomingContinuation) = AsyncStream<DataChannel>.makeStream()
        self.channelState = Mutex(ChannelState(
            incomingStream: incomingStream,
            incomingContinuation: incomingContinuation
        ))
        self.dataHandlerState = Mutex(nil)
        self.retransmitTask = Mutex(nil)
    }

    // MARK: - Connection lifecycle

    /// ICE credentials for this connection
    public var iceCredentials: ICECredentials {
        connState.withLock { $0.iceAgent.credentials }
    }

    /// Set remote ICE credentials (from signaling)
    public func setRemoteICECredentials(ufrag: String, password: String) {
        connState.withLock { state in
            state.iceAgent.setRemoteCredentials(ufrag: ufrag, password: password)
        }
    }

    /// Set a handler to receive application data from data channels.
    ///
    /// The handler receives `(channelID, payload)` for each non-DCEP data chunk.
    public func setDataHandler(_ handler: @escaping DataHandler) {
        dataHandlerState.withLock { $0 = handler }
    }

    /// Start the connection process (client-side: initiates DTLS handshake)
    public func start() throws {
        let isClient = connState.withLock { state -> Bool in
            state.stateMachine.process(.dtlsHandshakeStarted)
            return state.isClient
        }

        if isClient {
            let datagrams = try dtlsConnection.startHandshake(isClient: true)
            for datagram in datagrams {
                sendHandler(datagram)
            }
        } else {
            _ = try dtlsConnection.startHandshake(isClient: false)
        }
    }

    /// Process incoming raw UDP data
    ///
    /// Demultiplexes STUN, DTLS, and other data based on the first byte:
    /// - STUN: detected via `STUNMessage.isSTUN()` (RFC 5389)
    /// - DTLS (first byte 20-63): content type range for DTLS records
    /// - Other: logged and ignored
    ///
    /// - Throws: `WebRTCError.closed` if the connection has been closed
    public func receive(_ data: Data, remoteAddress: Data = Data()) throws {
        // P2.4: Check for closed/failed state before processing
        let isClosed = connState.withLock { state in
            state.stateMachine.isTerminal
        }
        if isClosed {
            throw WebRTCError.closed
        }

        guard !data.isEmpty else { return }

        let firstByte = data[data.startIndex]

        // RFC 5764 §5.1.2 demultiplex by first byte value:
        //   0-3:     STUN
        //   20-63:   DTLS
        //   128-191: RTP/RTCP (not used in WebRTC Direct)
        //
        // DTLS must be checked BEFORE STUNMessage.isSTUN() because
        // isSTUN() only checks `data[0] & 0xC0 == 0`, which is true
        // for DTLS content types 20-63 as well.

        if firstByte >= 20 && firstByte <= 63 {
            // P1.5: Validate ICE state before DTLS processing
            let (shouldProcess, currentState) = connState.withLock { state in
                (state.stateMachine.shouldProcessDTLS(), state.stateMachine.state)
            }
            if !shouldProcess {
                logger.warning("Ignoring DTLS packet (\(data.count)B): state=\(currentState)")
                return
            }
            try processDTLS(data, remoteAddress: remoteAddress)
            return
        }

        if STUNMessage.isSTUN(data) {
            try processSTUN(data, remoteAddress: remoteAddress)
            return
        }

        // Unknown protocol — log and ignore
        logger.debug("Ignoring unknown protocol byte: \(firstByte)")
    }

    /// Open a new outgoing data channel
    /// - Parameters:
    ///   - label: Channel label
    ///   - ordered: Whether messages should be delivered in order
    /// - Returns: The opened data channel
    /// - Throws: `WebRTCError.invalidState` if the connection is not established
    public func openDataChannel(label: String, ordered: Bool = true) throws -> DataChannel {
        let (channel, sctpPacket) = try connState.withLock { state -> (DataChannel, SCTPPacket) in
            guard state.stateMachine.isConnected else {
                throw WebRTCError.invalidState("Cannot open data channel in state \(state.stateMachine.state)")
            }
            let (channel, dcepData) = state.channelManager.openChannel(label: label, ordered: ordered)
            let sctpPacket = state.sctpAssociation.sendData(
                streamID: channel.id,
                payloadProtocolIdentifier: DataChannelPPID.dcep.rawValue,
                data: dcepData
            )
            return (channel, sctpPacket)
        }

        try encryptAndSend(sctpPacket.encode())
        return channel
    }

    /// Send data on a data channel
    /// - Parameters:
    ///   - data: The data to send
    ///   - channelID: The data channel stream ID
    ///   - binary: Whether data is binary (true) or string (false)
    /// - Throws: `WebRTCError.invalidState` if the connection is not established
    public func send(_ data: Data, on channelID: UInt16, binary: Bool = true) throws {
        let ppid: UInt32
        if data.isEmpty {
            ppid = binary ? DataChannelPPID.binaryEmpty.rawValue : DataChannelPPID.stringEmpty.rawValue
        } else {
            ppid = binary ? DataChannelPPID.binary.rawValue : DataChannelPPID.string.rawValue
        }

        let sctpPacket = try connState.withLock { state -> SCTPPacket in
            guard state.stateMachine.isConnected else {
                throw WebRTCError.invalidState("Cannot send data in state \(state.stateMachine.state)")
            }
            return state.sctpAssociation.sendData(
                streamID: channelID,
                payloadProtocolIdentifier: ppid,
                data: data
            )
        }

        try encryptAndSend(sctpPacket.encode())
    }

    /// Close the connection
    public func close() {
        retransmitTask.withLock { task in
            task?.cancel()
            task = nil
        }
        connState.withLock { state in
            state.stateMachine.process(.userClose)
            state.iceAgent.close()
            state.channelManager.shutdown()
        }
        finishIncomingChannels()
        dataHandlerState.withLock { $0 = nil }
    }

    /// Finish the incoming-channels stream so `for await` consumers terminate
    private func finishIncomingChannels() {
        channelState.withLock { state in
            state.incomingContinuation?.finish()
            state.incomingContinuation = nil
        }
    }

    // MARK: - Private protocol processing

    private func processSTUN(_ data: Data, remoteAddress: Data) throws {
        let endpoint = Self.decodeRemoteEndpoint(remoteAddress)

        // Single lock for ICE processing + state transition (fixes race condition)
        let response = connState.withLock { state -> Data? in
            let stunResponse = state.iceAgent.processSTUN(
                data: data,
                sourceAddress: endpoint.address,
                sourcePort: endpoint.port
            )

            // Update state machine based on ICE state
            if state.iceAgent.state == .connected {
                state.stateMachine.process(.iceConnected)
            } else if state.iceAgent.state == .failed {
                state.stateMachine.process(.iceFailed)
            }

            return stunResponse
        }

        if let response {
            sendHandler(response)
        }
    }

    static func decodeRemoteEndpoint(_ remoteAddress: Data) -> (address: Data, port: UInt16) {
        switch remoteAddress.count {
        case 6:
            let address = Data(remoteAddress.prefix(4))
            let portBytes = remoteAddress.suffix(2)
            let port = UInt16(portBytes[portBytes.startIndex]) << 8 |
                UInt16(portBytes[portBytes.index(after: portBytes.startIndex)])
            return (address, port)
        case 18:
            let address = Data(remoteAddress.prefix(16))
            let portBytes = remoteAddress.suffix(2)
            let port = UInt16(portBytes[portBytes.startIndex]) << 8 |
                UInt16(portBytes[portBytes.index(after: portBytes.startIndex)])
            return (address, port)
        default:
            return (remoteAddress, 0)
        }
    }

    private func processDTLS(_ data: Data, remoteAddress: Data) throws {
        let output: DTLSConnectionOutput
        do {
            output = try dtlsConnection.processReceivedDatagram(data, remoteAddress: remoteAddress)
        } catch {
            // P2.2: Propagate DTLS errors to state machine
            let reason = String(describing: error)
            connState.withLock { state in
                _ = state.stateMachine.process(.dtlsHandshakeFailed(reason))
            }
            finishIncomingChannels()
            throw WebRTCError.dtlsHandshakeFailed(reason)
        }

        // Send response datagrams
        for datagram in output.datagramsToSend {
            sendHandler(datagram)
        }

        // Handle handshake completion
        if output.handshakeComplete {
            try onHandshakeComplete()
        }

        // Process application data (already decrypted by DTLSConnection)
        if !output.applicationData.isEmpty {
            try processSCTP(output.applicationData)
        }
    }

    private func onHandshakeComplete() throws {
        // Verify remote fingerprint if expected
        if let expected = expectedFingerprint {
            guard let actual = dtlsConnection.remoteFingerprint else {
                connState.withLock { state in
                    _ = state.stateMachine.process(.dtlsHandshakeFailed("No remote certificate after handshake"))
                }
                throw WebRTCError.dtlsHandshakeFailed("No remote certificate")
            }
            guard actual == expected else {
                let reason = "Remote fingerprint mismatch: expected \(expected.sdpFormat), got \(actual.sdpFormat)"
                connState.withLock { state in
                    _ = state.stateMachine.process(.dtlsHandshakeFailed(reason))
                }
                throw WebRTCError.dtlsHandshakeFailed(reason)
            }
        }

        connState.withLock { state in
            _ = state.stateMachine.process(.dtlsHandshakeComplete)
        }
        logger.info("DTLS handshake complete, establishing SCTP")

        // Initiate SCTP association (client side)
        let isClient = connState.withLock { $0.isClient }
        if isClient {
            connState.withLock { state in
                _ = state.stateMachine.process(.sctpAssociating)
            }
            let initPacket = connState.withLock { $0.sctpAssociation.generateInit() }
            try encryptAndSend(initPacket.encode())
        }
    }

    private func processSCTP(_ plaintext: Data) throws {
        // Parse SCTP packet (already decrypted)
        let packet: SCTPPacket
        do {
            packet = try SCTPPacket.decode(from: plaintext)
        } catch {
            // P2.2: Propagate SCTP decode errors
            let reason = String(describing: error)
            connState.withLock { state in
                _ = state.stateMachine.process(.sctpFailed(reason))
            }
            finishIncomingChannels()
            throw WebRTCError.sctpFailed(reason)
        }

        let responses: [SCTPPacket]
        let receivedData: [(streamID: UInt16, ppid: UInt32, data: Data)]
        do {
            let result = try connState.withLock { state in
                try state.sctpAssociation.processPacket(packet)
            }
            responses = result.responses
            receivedData = result.receivedData
        } catch let error as SCTPError {
            if case .verificationTagMismatch(let expected, let actual) = error {
                // RFC 4960 §8.5: a packet with an invalid verification tag is
                // silently discarded. Failing the association here would let an
                // attacker who can inject a single datagram kill the connection.
                logger.warning("Discarding SCTP packet: verification tag mismatch (expected \(expected), got \(actual))")
                return
            }
            // P2.2: Propagate SCTP processing errors
            let reason = String(describing: error)
            connState.withLock { state in
                _ = state.stateMachine.process(.sctpFailed(reason))
            }
            finishIncomingChannels()
            throw WebRTCError.sctpFailed(reason)
        } catch {
            let reason = String(describing: error)
            connState.withLock { state in
                _ = state.stateMachine.process(.sctpFailed(reason))
            }
            finishIncomingChannels()
            throw WebRTCError.sctpFailed(reason)
        }

        // Check if SCTP became established
        let didBecomeConnected = connState.withLock { state -> Bool in
            let sctpState = state.sctpAssociation.state
            if sctpState == .established && !state.stateMachine.isSCTPEstablished {
                state.stateMachine.process(.sctpEstablished)
                return true
            }
            return false
        }
        if didBecomeConnected {
            logger.info("WebRTC connection established")
            startRetransmissionDriver()
        }

        // Send SCTP responses
        for response in responses {
            try encryptAndSend(response.encode())
        }

        // Process received data (DCEP or application data)
        var newChannels: [DataChannel] = []
        let dataHandler = dataHandlerState.withLock { $0 }

        for (streamID, ppid, payload) in receivedData {
            if ppid == DataChannelPPID.dcep.rawValue {
                let (response, channel) = try connState.withLock { state in
                    try state.channelManager.processIncomingDCEP(streamID: streamID, data: payload)
                }
                if let response {
                    let sctpPacket = connState.withLock { state in
                        state.sctpAssociation.sendData(
                            streamID: streamID,
                            payloadProtocolIdentifier: DataChannelPPID.dcep.rawValue,
                            data: response
                        )
                    }
                    try encryptAndSend(sctpPacket.encode())
                }
                if let channel {
                    newChannels.append(channel)
                }
            } else {
                // Application data — deliver via data handler
                dataHandler?(streamID, payload)
            }
        }

        // Emit new incoming channels
        if !newChannels.isEmpty {
            let continuation = channelState.withLock { $0.incomingContinuation }
            for channel in newChannels {
                continuation?.yield(channel)
            }
        }
    }

    // MARK: - Retransmission driver

    /// Start the periodic SCTP retransmission driver (RFC 4960 §6.3 T3-rtx).
    ///
    /// `SCTPAssociation` is purely reactive — it only acts when a packet
    /// arrives — so a periodic driver is required for lost DATA chunks to
    /// ever be retransmitted.
    private func startRetransmissionDriver() {
        retransmitTask.withLock { task in
            guard task == nil else { return }
            task = Task { [weak self] in
                while !Task.isCancelled {
                    do {
                        try await Task.sleep(for: Self.retransmitTickInterval)
                    } catch {
                        return // task cancelled during sleep
                    }
                    guard let self else { return }
                    if self.driveRetransmissions() { return }
                }
            }
        }
    }

    /// Perform one retransmission tick.
    /// - Returns: true when the driver should stop (terminal state or failure)
    private func driveRetransmissions() -> Bool {
        let isTerminal = connState.withLock { $0.stateMachine.isTerminal }
        if isTerminal {
            return true
        }

        let result = connState.withLock { $0.sctpAssociation.getPendingRetransmissions() }
        switch result {
        case .success(let packets):
            do {
                for packet in packets {
                    try encryptAndSend(packet.encode())
                }
            } catch {
                let reason = "Retransmission send failed: \(String(describing: error))"
                logger.error("\(reason)")
                connState.withLock { state in
                    _ = state.stateMachine.process(.sctpFailed(reason))
                }
                finishIncomingChannels()
                return true
            }
            return false

        case .failure(let error):
            let reason = String(describing: error)
            logger.error("SCTP retransmission limit exceeded: \(reason)")
            connState.withLock { state in
                _ = state.stateMachine.process(.sctpFailed(reason))
            }
            finishIncomingChannels()
            return true
        }
    }

    @discardableResult
    private func encryptAndSend(_ plaintext: Data) throws -> Data {
        let encrypted = try dtlsConnection.writeApplicationData(plaintext)
        sendHandler(encrypted)
        return encrypted
    }
}
