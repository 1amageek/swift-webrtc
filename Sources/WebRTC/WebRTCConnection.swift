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

import TLS
import STUNCore
import ICELite
import SCTPCore
import DataChannel
// REQUIRED under Embedded for `AsyncStream` / `Task` / `async` (probe P10); the
// host build picks these up from the implicit stdlib import, but the Embedded
// build needs the explicit `_Concurrency` import to bring them into scope.
import _Concurrency
#if !hasFeature(Embedded)
import Foundation
import Logging
#endif

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

    /// Callback to send raw bytes to the remote peer.
    ///
    /// The currency is `[UInt8]` (Embedded-clean). Host callers that work in
    /// `Data` can pass a `{ data in ... }` closure that accepts `[UInt8]` (e.g.
    /// `ByteBuffer.writeBytes` consumes a `Sequence<UInt8>` either way), or use
    /// the host-only `Data` overloads on `receive`/`send`/`setDataHandler`.
    public typealias SendHandler = @Sendable ([UInt8]) -> Void

    /// Callback to deliver application data (channelID, payload). `[UInt8]`
    /// currency; a host-only `Data`-closure overload of `setDataHandler` wraps it.
    public typealias DataHandler = @Sendable (UInt16, [UInt8]) -> Void

    // MARK: - Public properties

    /// Current connection state
    public var state: WebRTCConnectionState {
        connState.withLock { $0.state }
    }

    /// Local certificate fingerprint
    public let localFingerprint: CertificateFingerprint

    /// Remote certificate fingerprint, verified after the DTLS handshake.
    ///
    /// The swift-tls Tier-1 DTLS facade surfaces the peer certificate via
    /// `remoteCertificateDER`; ``onHandshakeComplete()`` computes this fingerprint
    /// from it and only stores it once verified. It is `nil` until the handshake
    /// completes, or if the peer presented no certificate. The fail-closed verifier
    /// rejects the handshake when an expected fingerprint is configured and the
    /// peer fingerprint mismatches or cannot be obtained.
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
    public var remoteCertificateDER: [UInt8]? {
        dtlsEndpoint.remoteCertificateDER
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
    private let connState: FacadeLock<ConnState>
    private let channelState: FacadeLock<ChannelState>
    private let dataHandlerState: FacadeLock<DataHandler?>
    private let sendHandler: SendHandler
    private let expectedFingerprint: CertificateFingerprint?
    private let logger: WebRTCLogger

    /// Time + deadline-sleep seam for the SCTP retransmission driver
    /// (`AsyncTimer.sleep(untilNanos:)`, never `Task.sleep` / `ContinuousClock`).
    private let timer: WebRTCDefaultTimer

    /// Periodic driver for SCTP T3-rtx retransmissions
    private let retransmitTask: FacadeLock<Task<Void, Never>?>

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

    private enum OpenDataChannelResult {
        case success(DataChannel, SCTPPacket)
        case invalidState(WebRTCConnectionState)
        case dataChannelError(DataChannelError)
        case sctpError(SCTPError)
    }

    private enum SendDataResult {
        case success(SCTPPacket)
        case invalidState(WebRTCConnectionState)
        case sctpError(SCTPError)
    }

    // MARK: - Init

    /// Create a client-side connection
    public static func asClient(
        certificate: WebRTCCertificate,
        remoteFingerprint expectedFingerprint: CertificateFingerprint,
        sendHandler: @escaping SendHandler,
        logger: WebRTCLogger = WebRTCLogger(label: "webrtc.connection")
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
        logger: WebRTCLogger = WebRTCLogger(label: "webrtc.connection")
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
        logger: WebRTCLogger
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
            // `String(describing:)` is unavailable under Embedded; the static
            // precondition message names the invariant (a locally-owned identity
            // must be valid) without interpolating the error value.
            preconditionFailure("WebRTC local DTLS identity is invalid")
        }
        self.expectedFingerprint = expectedFingerprint
        self.sendHandler = sendHandler
        self.logger = logger
        self.timer = WebRTCDefaultTimer()
        self.connState = FacadeLock(ConnState(
            iceAgent: ICELiteAgent(),
            sctpAssociation: SCTPAssociation(),
            channelManager: DataChannelManager(isInitiator: isClient),
            isClient: isClient,
            verifiedRemoteFingerprint: nil
        ))
        // Create the stream eagerly so channels arriving before the first
        // subscription are buffered rather than dropped
        let (incomingStream, incomingContinuation) = AsyncStream<DataChannel>.makeStream()
        self.channelState = FacadeLock(ChannelState(
            incomingStream: incomingStream,
            incomingContinuation: incomingContinuation
        ))
        self.dataHandlerState = FacadeLock(nil)
        self.retransmitTask = FacadeLock(nil)
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
    /// The payload currency is `[UInt8]` (Embedded-clean).
    public func setDataHandler(_ handler: @escaping DataHandler) {
        dataHandlerState.withLock { $0 = handler }
    }

    #if !hasFeature(Embedded)
    /// Host-only `Data` convenience: set a `(channelID, Data)` handler. Wraps the
    /// `[UInt8]` core so existing host callers keep their `Data`-based closures.
    ///
    /// The bridge closure is explicitly typed `DataHandler`
    /// (`(UInt16, [UInt8]) -> Void`) so overload resolution binds the `[UInt8]`
    /// core method, not this `Data` overload (which would recurse).
    public func setDataHandler(_ handler: @escaping @Sendable (UInt16, Data) -> Void) {
        let bridge: DataHandler = { channelID, payload in
            handler(channelID, Data(payload))
        }
        setDataHandler(bridge)
    }
    #endif

    /// Start the connection process (client-side: initiates DTLS handshake)
    public func start() throws(WebRTCError) {
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
            throw WebRTCError.dtlsHandshakeFailed(
                Self.failureReason(error, context: "DTLS handshake start failed")
            )
        }
        _ = isClient
        for datagram in datagrams {
            sendHandler(datagram)
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
    public func receive(_ data: [UInt8], remoteAddress: [UInt8] = []) throws(WebRTCError) {
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
                    _ = state.stateMachine.process(
                        .error(Self.failureReason(error, context: "receive() processing failed"))
                    )
                }
            }
            finishIncomingChannels()
            throw error
        }
    }

    #if !hasFeature(Embedded)
    /// Host-only `Data` convenience: process an incoming UDP datagram. Wraps the
    /// `[UInt8]` core so existing host callers keep passing `Data`.
    public func receive(_ data: Data, remoteAddress: Data = Data()) throws {
        try receive([UInt8](data), remoteAddress: [UInt8](remoteAddress))
    }
    #endif

    private func demultiplex(_ data: [UInt8], remoteAddress: [UInt8]) throws(WebRTCError) {
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
            processSTUN(data, remoteAddress: remoteAddress)
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
    public func openDataChannel(label: String, ordered: Bool = true) throws(WebRTCError) -> DataChannel {
        let result = connState.withLock { state -> OpenDataChannelResult in
            guard state.stateMachine.isConnected else {
                return .invalidState(state.stateMachine.state)
            }

            let opened = Result { () throws(DataChannelError) -> (DataChannel, [UInt8]) in
                try state.channelManager.openChannelBytes(label: label, ordered: ordered)
            }
            let channel: DataChannel
            let dcepData: [UInt8]
            switch opened {
            case .success(let value):
                (channel, dcepData) = value
            case .failure(let error):
                return .dataChannelError(error)
            }

            let sent = Result { () throws(SCTPError) -> SCTPPacket in
                try state.sctpAssociation.sendDataBytes(
                    streamID: channel.id,
                    payloadProtocolIdentifier: DataChannelPPID.dcep.rawValue,
                    data: dcepData
                )
            }
            switch sent {
            case .success(let packet):
                return .success(channel, packet)
            case .failure(let error):
                return .sctpError(error)
            }
        }

        let channel: DataChannel
        let sctpPacket: SCTPPacket
        switch result {
        case .success(let openedChannel, let packet):
            channel = openedChannel
            sctpPacket = packet
        case .invalidState(let state):
            throw WebRTCError.invalidState("Cannot open data channel in state \(state.label)")
        case .dataChannelError(let error):
            throw WebRTCError.sctpFailed(
                Self.failureReason(error, context: "DCEP open-channel encode failed")
            )
        case .sctpError(let error):
            throw WebRTCError.sctpFailed(
                Self.failureReason(error, context: "SCTP send (DCEP open) failed")
            )
        }
        try encryptAndSend(sctpPacket.encodeBytes())
        return channel
    }

    /// Send data on a data channel
    /// - Parameters:
    ///   - data: The data to send
    ///   - channelID: The data channel stream ID
    ///   - binary: Whether data is binary (true) or string (false)
    /// - Throws: `WebRTCError.invalidState` if the connection is not established
    public func send(_ data: [UInt8], on channelID: UInt16, binary: Bool = true) throws(WebRTCError) {
        let ppid: UInt32
        if data.isEmpty {
            ppid = binary ? DataChannelPPID.binaryEmpty.rawValue : DataChannelPPID.stringEmpty.rawValue
        } else {
            ppid = binary ? DataChannelPPID.binary.rawValue : DataChannelPPID.string.rawValue
        }

        let result = connState.withLock { state -> SendDataResult in
            guard state.stateMachine.isConnected else {
                return .invalidState(state.stateMachine.state)
            }

            let sent = Result { () throws(SCTPError) -> SCTPPacket in
                try state.sctpAssociation.sendDataBytes(
                    streamID: channelID,
                    payloadProtocolIdentifier: ppid,
                    data: data
                )
            }
            switch sent {
            case .success(let packet):
                return .success(packet)
            case .failure(let error):
                return .sctpError(error)
            }
        }

        let sctpPacket: SCTPPacket
        switch result {
        case .success(let packet):
            sctpPacket = packet
        case .invalidState(let state):
            throw WebRTCError.invalidState("Cannot send data in state \(state.label)")
        case .sctpError(let error):
            throw WebRTCError.sctpFailed(
                Self.failureReason(error, context: "SCTP send failed")
            )
        }

        try encryptAndSend(sctpPacket.encodeBytes())
    }

    #if !hasFeature(Embedded)
    /// Host-only `Data` convenience: send data on a data channel. Wraps the
    /// `[UInt8]` core so existing host callers keep passing `Data`.
    public func send(_ data: Data, on channelID: UInt16, binary: Bool = true) throws {
        try send([UInt8](data), on: channelID, binary: binary)
    }
    #endif

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

    private func processSTUN(_ data: [UInt8], remoteAddress: [UInt8]) {
        let endpoint = Self.decodeRemoteEndpoint(remoteAddress)

        // Single lock for ICE processing + state transition (fixes race condition)
        let response = connState.withLock { state -> [UInt8]? in
            let stunResponse = state.iceAgent.processSTUNBytes(
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

    static func decodeRemoteEndpoint(_ remoteAddress: [UInt8]) -> (address: [UInt8], port: UInt16) {
        switch remoteAddress.count {
        case 6:
            let address = Array(remoteAddress[0..<4])
            let port = UInt16(remoteAddress[4]) << 8 | UInt16(remoteAddress[5])
            return (address, port)
        case 18:
            let address = Array(remoteAddress[0..<16])
            let port = UInt16(remoteAddress[16]) << 8 | UInt16(remoteAddress[17])
            return (address, port)
        default:
            return (remoteAddress, 0)
        }
    }

    private func processDTLS(_ data: [UInt8], remoteAddress: [UInt8]) throws(WebRTCError) {
        let output: DTLSOutput
        do {
            output = try dtlsEndpoint.receive(data, remoteAddress: remoteAddress)
        } catch {
            // P2.2: Propagate DTLS errors to state machine
            let reason = Self.failureReason(error, context: "DTLS receive failed")
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

        // Process application data (already decrypted by the DTLS facade)
        if !output.applicationData.isEmpty {
            try processSCTP(output.applicationData)
        }
    }

    private func onHandshakeComplete() throws(WebRTCError) {
        // Verify remote fingerprint if expected.
        //
        // FAIL-CLOSED: WebRTC's DTLS-SRTP peer authentication binds the peer's
        // leaf-certificate fingerprint to the value advertised in signaling. The
        // swift-tls Tier-1 DTLS facade surfaces the peer certificate (see
        // ``DTLSEndpoint``), so when an expected fingerprint is configured we
        // compute the peer's fingerprint and accept ONLY on an exact match —
        // rejecting on mismatch, or when the peer presented no certificate. Never
        // silently accept an unverified peer. When no expected fingerprint is set
        // (e.g. a server whose peer identity is bound by a subsequent layer), the
        // handshake proceeds.
        if let expected = expectedFingerprint {
            guard let actual = peerFingerprintIfAvailable() else {
                let reason = "Cannot verify remote fingerprint: the peer presented no certificate (expected \(expected.sdpFormat))"
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
            try encryptAndSend(initPacket.encodeBytes())
        }
    }

    private func processSCTP(_ plaintext: [UInt8]) throws(WebRTCError) {
        // Parse SCTP packet (already decrypted)
        let packet: SCTPPacket
        do {
            packet = try SCTPPacket.decode(from: plaintext)
        } catch {
            // P2.2: Propagate SCTP decode errors
            let reason = Self.failureReason(error, context: "SCTP packet decode failed")
            connState.withLock { state in
                _ = state.stateMachine.process(.sctpFailed(reason))
            }
            finishIncomingChannels()
            throw WebRTCError.sctpFailed(reason)
        }

        let responses: [SCTPPacket]
        let receivedData: [SCTPReceivedMessage]
        do {
            let result = try connState.withLock { state throws(SCTPError) in
                try state.sctpAssociation.processPacketBytes(packet)
            }
            responses = result.responses
            receivedData = result.receivedData
        } catch {
            // `processPacketBytes` is `throws(SCTPError)`, so `error` is a typed
            // `SCTPError` here. A typed `catch ... as SCTPError` clause SILGen-crashes
            // under Embedded, so the type narrowing is done via a plain `catch` plus
            // an `if case` switch on the already-typed error instead.
            if case .verificationTagMismatch(let expected, let actual) = error {
                // RFC 4960 §8.5: a packet with an invalid verification tag is
                // silently discarded. Failing the association here would let an
                // attacker who can inject a single datagram kill the connection.
                logger.warning("Discarding SCTP packet: verification tag mismatch (expected \(expected), got \(actual))")
                return
            }
            // P2.2: Propagate SCTP processing errors
            let reason = Self.failureReason(error, context: "SCTP packet processing failed")
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
            try encryptAndSend(response.encodeBytes())
        }

        // Process received data (DCEP or application data)
        var newChannels: [DataChannel] = []
        let dataHandler = dataHandlerState.withLock { $0 }

        for message in receivedData {
            let streamID = message.streamID
            let ppid = message.ppid
            let payload = message.data
            if ppid == DataChannelPPID.dcep.rawValue {
                // `processIncomingDCEPBytes` is `throws(DataChannelError)` and
                // `sendDataBytes` is `throws(SCTPError)`; both are converted to
                // `WebRTCError` so this `throws(WebRTCError)` function has a single
                // concrete thrown type (Embedded requirement).
                let response: [UInt8]?
                let channel: DataChannel?
                do {
                    (response, channel) = try connState.withLock { state throws(DataChannelError) in
                        try state.channelManager.processIncomingDCEPBytes(streamID: streamID, data: payload)
                    }
                } catch {
                    throw WebRTCError.sctpFailed(
                        Self.failureReason(error, context: "DCEP message processing failed")
                    )
                }
                if let response {
                    let sctpPacket: SCTPPacket
                    do {
                        sctpPacket = try connState.withLock { state throws(SCTPError) in
                            try state.sctpAssociation.sendDataBytes(
                                streamID: streamID,
                                payloadProtocolIdentifier: DataChannelPPID.dcep.rawValue,
                                data: response
                            )
                        }
                    } catch {
                        throw WebRTCError.sctpFailed(
                            Self.failureReason(error, context: "SCTP send (DCEP ack) failed")
                        )
                    }
                    try encryptAndSend(sctpPacket.encodeBytes())
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
            // The retransmission tick is scheduled through the injected
            // `AsyncTimer` seam (`timer.sleep(untilNanos:)`), NOT `Task.sleep` /
            // `ContinuousClock`, both of which are unavailable under Embedded.
            let tickNanos = Self.retransmitTickInterval.facadeNanoseconds
            let timer = self.timer
            // `weak`/`unowned` are forbidden under Embedded; the host build keeps
            // the weak capture (so dropping the connection without `close()` does
            // not leak via the task→self→task cycle). Under Embedded the strong
            // capture is broken by `close()` cancelling the task (or the loop
            // self-terminating on a terminal state), so no live cycle persists.
            //
            // The tick suspension goes through `parkForTick(_:on:)`, a NON-throwing
            // helper that swallows the timer's typed `CancellationError` internally.
            // The Task closure therefore contains no throwing call, so Embedded does
            // not have to infer a thrown type across the `await` boundary (a bare
            // `catch` there widens to `any Error`, which Embedded rejects).
            #if !hasFeature(Embedded)
            task = Task { [weak self] in
                while !Task.isCancelled {
                    if !(await Self.parkForTick(tickNanos, on: timer)) { return }
                    guard let self else { return }
                    if self.driveRetransmissions() { return }
                }
            }
            #else
            task = Task { [self] in
                while !Task.isCancelled {
                    if !(await Self.parkForTick(tickNanos, on: timer)) { return }
                    if self.driveRetransmissions() { return }
                }
            }
            #endif
        }
    }

    /// Suspend for one retransmission tick via the injected `AsyncTimer`,
    /// swallowing the timer's typed `CancellationError`.
    ///
    /// - Returns: `true` if the tick elapsed normally, `false` if the task was
    ///   cancelled during the suspension (the caller stops the loop).
    private static func parkForTick(_ tickNanos: UInt64, on timer: WebRTCDefaultTimer) async -> Bool {
        let deadline = timer.monotonicNanos() &+ tickNanos
        do {
            try await timer.sleep(untilNanos: deadline)
            return true
        } catch {
            return false
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
                    try encryptAndSend(packet.encodeBytes())
                }
            } catch {
                let reason = Self.failureReason(error, context: "SCTP retransmission send failed")
                logger.error("\(reason)")
                connState.withLock { state in
                    _ = state.stateMachine.process(.sctpFailed(reason))
                }
                finishIncomingChannels()
                return true
            }
            return false

        case .failure(let error):
            let reason = Self.failureReason(error, context: "SCTP retransmission limit exceeded")
            logger.error("\(reason)")
            connState.withLock { state in
                _ = state.stateMachine.process(.sctpFailed(reason))
            }
            finishIncomingChannels()
            return true
        }
    }

    /// Render a caught error into the human-readable reason string carried by
    /// `WebRTCError` / the connection state machine.
    ///
    /// `String(describing:)` is unavailable under Embedded Swift, so the rich
    /// per-error description is host-only. Under Embedded the caller's stable
    /// static `context` (a plain `String` literal, the only Embedded-legal
    /// reason source) describes WHICH operation failed — the failing subsystem is
    /// the actionable signal; the inner error's text is not reconstructible
    /// without Foundation reflection. Fail-closed behavior is preserved either
    /// way: the connection still transitions to the same terminal state.
    private static func failureReason(_ error: some Error, context: String) -> String {
        #if !hasFeature(Embedded)
        return String(describing: error)
        #else
        return context
        #endif
    }

    @discardableResult
    private func encryptAndSend(_ plaintext: [UInt8]) throws(WebRTCError) -> [UInt8] {
        let encrypted: [UInt8]
        do {
            encrypted = try dtlsEndpoint.send(plaintext)
        } catch {
            throw WebRTCError.dtlsHandshakeFailed(
                Self.failureReason(error, context: "DTLS encrypt/send failed")
            )
        }
        sendHandler(encrypted)
        return encrypted
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
        return CertificateFingerprint.fromDER(der)
    }
}
