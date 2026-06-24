/// WebRTC Connection
///
/// Integrates the full WebRTC Direct protocol stack:
/// UDP → STUN/ICE Lite → DTLS 1.2 → SCTP → Data Channels
///
/// Transport-agnostic: uses a send closure for outgoing data and
/// a `receive(_:remoteAddress:)` method for incoming data.
///
/// DTLS is driven over the swift-tls Tier-1 `DTLSClient`/`DTLSServer` facade via
/// the local ``DTLSEndpoint`` wrapper.

import Foundation
import Synchronization
import TLS
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

    /// Remote certificate fingerprint (available after DTLS handshake).
    ///
    /// NOTE: the swift-tls Tier-1 DTLS facade (`DTLSClient`/`DTLSServer`) does not
    /// surface the peer certificate, so this is currently always `nil`. See
    /// ``DTLSEndpoint`` for the reported facade gap. The fail-closed verifier in
    /// ``onHandshakeComplete()`` rejects the handshake when an expected fingerprint
    /// is configured and the peer fingerprint cannot be obtained.
    public var remoteFingerprint: CertificateFingerprint? {
        connState.withLock { $0.verifiedRemoteFingerprint }
    }

    /// Remote peer's DER-encoded leaf certificate (available after the DTLS
    /// handshake completes).
    ///
    /// The swift-tls Tier-1 DTLS facade surfaces the peer certificate, which the
    /// internal ``DTLSEndpoint`` exposes; this delegates to it. `nil` while the
    /// handshake is incomplete or no certificate was presented — never a silent
    /// stub.
    public var remoteCertificateDER: Data? {
        dtlsEndpoint.remoteCertificateDER.map { Data($0) }
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

    private let dtlsEndpoint: DTLSEndpoint
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
        /// The peer fingerprint verified at handshake completion, if obtainable.
        var verifiedRemoteFingerprint: CertificateFingerprint?

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
        certificate: WebRTCCertificate,
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

    /// Create a server-side connection.
    ///
    /// The server always requires the client to present a certificate and prove
    /// possession of its private key (mutual DTLS authentication). The verified
    /// remote certificate's fingerprint is available via `remoteFingerprint` after
    /// the handshake so an upper layer (e.g. libp2p WebRTC Direct) can bind it to
    /// the peer identity.
    ///
    /// - Parameter remoteFingerprint: When the dialer's certificate fingerprint is
    ///   known ahead of time (e.g. from signaling / a `/certhash` multiaddr), pass it
    ///   to have the handshake fail on mismatch. Pass `nil` when the identity is bound
    ///   by a subsequent layer instead.
    public static func asServer(
        certificate: WebRTCCertificate,
        remoteFingerprint expectedFingerprint: CertificateFingerprint? = nil,
        sendHandler: @escaping SendHandler,
        logger: Logger = Logger(label: "webrtc.connection")
    ) -> WebRTCConnection {
        WebRTCConnection(
            certificate: certificate,
            isClient: false,
            expectedFingerprint: expectedFingerprint,
            sendHandler: sendHandler,
            logger: logger
        )
    }

    private init(
        certificate: WebRTCCertificate,
        isClient: Bool,
        expectedFingerprint: CertificateFingerprint?,
        sendHandler: @escaping SendHandler,
        logger: Logger
    ) {
        self.localFingerprint = certificate.fingerprint
        // The DTLS server (this endpoint when !isClient) MUST require the client to
        // present a certificate and prove possession of its private key. Otherwise an
        // attacker could complete the handshake presenting a victim's (public) WebRTC
        // certificate without holding its key — full inbound peer impersonation.
        //
        // DTLSEndpoint.make can throw only on a malformed identity; this connection
        // owns the certificate it just generated/validated, so a failure here is a
        // programmer error in certificate construction, not a runtime peer input.
        do {
            self.dtlsEndpoint = try DTLSEndpoint.make(
                certificate: certificate,
                isClient: isClient,
                requireClientCertificate: !isClient
            )
        } catch {
            preconditionFailure("WebRTC local DTLS identity is invalid: \(error)")
        }
        self.expectedFingerprint = expectedFingerprint
        self.sendHandler = sendHandler
        self.logger = logger
        self.connState = Mutex(ConnState(
            iceAgent: ICELiteAgent(),
            sctpAssociation: SCTPAssociation(),
            channelManager: DataChannelManager(isInitiator: isClient),
            isClient: isClient,
            verifiedRemoteFingerprint: nil
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

        // Both roles start the handshake FSM; the client emits its ClientHello,
        // the server has nothing to send until the first ClientHello arrives.
        let datagrams: [[UInt8]]
        do {
            datagrams = try dtlsEndpoint.startHandshake()
        } catch {
            throw WebRTCError.dtlsHandshakeFailed(String(describing: error))
        }
        _ = isClient
        for datagram in datagrams {
            sendHandler(Data(datagram))
        }
    }

    /// Process incoming raw UDP data
    ///
    /// Demultiplexes STUN, DTLS, and other data based on the first byte:
    /// - STUN: detected via `STUNMessage.isSTUN()` (RFC 5389)
    /// - DTLS (first byte 20-63): content type range for DTLS records
    /// - Other: logged and ignored
    ///
    /// Contract: every throw from this method means the connection is
    /// terminal (`state.isTerminal == true`). The connection has already
    /// transitioned to `.failed`/`.closed` and `incomingChannels` has been
    /// finished before the error propagates — callers should stop feeding
    /// data, drop their routing entry, and dispose of the connection.
    /// Recoverable conditions (unknown protocol bytes, packets that fail
    /// SCTP verification-tag validation per RFC 4960 §8.5, DTLS packets
    /// arriving in a non-DTLS state) are discarded internally and do NOT
    /// throw.
    ///
    /// - Throws: `WebRTCError.closed` if the connection has been closed,
    ///   `WebRTCError.dtlsHandshakeFailed` on a fatal DTLS failure,
    ///   `WebRTCError.sctpFailed` on a fatal SCTP failure
    public func receive(_ data: Data, remoteAddress: Data = Data()) throws {
        // P2.4: Check for closed/failed state before processing
        let isClosed = connState.withLock { state in
            state.stateMachine.isTerminal
        }
        if isClosed {
            throw WebRTCError.closed
        }

        guard !data.isEmpty else { return }

        do {
            try demultiplex(data, remoteAddress: remoteAddress)
        } catch {
            // Enforce the terminal contract: any error escaping receive()
            // leaves the connection failed and the incoming-channels stream
            // finished, including paths whose handlers did not transition
            // explicitly (e.g. send failures while emitting responses).
            connState.withLock { state in
                if !state.stateMachine.isTerminal {
                    _ = state.stateMachine.process(.error(String(describing: error)))
                }
            }
            finishIncomingChannels()
            throw error
        }
    }

    private func demultiplex(_ data: Data, remoteAddress: Data) throws {
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
            let (channel, dcepData) = try state.channelManager.openChannel(label: label, ordered: ordered)
            let sctpPacket = try state.sctpAssociation.sendData(
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
            return try state.sctpAssociation.sendData(
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
        let output: DTLSOutput
        do {
            output = try dtlsEndpoint.receive([UInt8](data), remoteAddress: [UInt8](remoteAddress))
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
            sendHandler(Data(datagram))
        }

        // Handle handshake completion
        if output.handshakeComplete {
            try onHandshakeComplete()
        }

        // Process application data (already decrypted by the DTLS facade)
        if !output.applicationData.isEmpty {
            try processSCTP(Data(output.applicationData))
        }
    }

    private func onHandshakeComplete() throws {
        // Verify remote fingerprint if expected.
        //
        // FAIL-CLOSED: WebRTC's DTLS-SRTP peer authentication binds the peer's
        // leaf-certificate fingerprint to the value advertised in signaling. The
        // swift-tls Tier-1 DTLS facade does not yet expose the peer certificate
        // (see ``DTLSEndpoint``), so when an expected fingerprint is configured we
        // CANNOT verify it and MUST reject — never silently accept an unverified
        // peer. When no expected fingerprint is set (e.g. a server whose peer
        // identity is bound by a subsequent layer), the handshake proceeds.
        if let expected = expectedFingerprint {
            guard let actual = peerFingerprintIfAvailable() else {
                let reason = "Cannot verify remote fingerprint: the DTLS facade does not expose the peer certificate (expected \(expected.sdpFormat))"
                connState.withLock { state in
                    _ = state.stateMachine.process(.dtlsHandshakeFailed(reason))
                }
                finishIncomingChannels()
                throw WebRTCError.dtlsHandshakeFailed(reason)
            }
            guard actual == expected else {
                let reason = "Remote fingerprint mismatch: expected \(expected.sdpFormat), got \(actual.sdpFormat)"
                connState.withLock { state in
                    _ = state.stateMachine.process(.dtlsHandshakeFailed(reason))
                }
                finishIncomingChannels()
                throw WebRTCError.dtlsHandshakeFailed(reason)
            }
            connState.withLock { $0.verifiedRemoteFingerprint = actual }
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
                    let sctpPacket = try connState.withLock { state in
                        try state.sctpAssociation.sendData(
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
        let encrypted: [UInt8]
        do {
            encrypted = try dtlsEndpoint.send([UInt8](plaintext))
        } catch {
            throw WebRTCError.dtlsHandshakeFailed(String(describing: error))
        }
        let datagram = Data(encrypted)
        sendHandler(datagram)
        return datagram
    }

    /// The peer's certificate fingerprint, if the DTLS layer can supply it.
    ///
    /// The swift-tls Tier-1 DTLS facade now surfaces the peer's leaf certificate
    /// after the handshake (see ``DTLSEndpoint``). We compute the SHA-256
    /// fingerprint from that DER here, restoring full fail-closed DTLS-SRTP
    /// verification (RFC 8122). Returns `nil` only when no peer certificate is
    /// available (handshake incomplete / no cert), in which case the verifier
    /// rejects — it never silently accepts an unverified peer.
    private func peerFingerprintIfAvailable() -> CertificateFingerprint? {
        guard let der = dtlsEndpoint.remoteCertificateDER else { return nil }
        return CertificateFingerprint.fromDER(Data(der))
    }
}
