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

    /// Stream of incoming data channels opened by the remote peer
    public var incomingChannels: AsyncStream<DataChannel> {
        channelState.withLock { state in
            if let existing = state.incomingStream { return existing }
            let (stream, continuation) = AsyncStream<DataChannel>.makeStream()
            state.incomingStream = stream
            state.incomingContinuation = continuation
            return stream
        }
    }

    // MARK: - Private state

    private let dtlsConnection: DTLSConnection
    private let connState: Mutex<ConnState>
    private let channelState: Mutex<ChannelState>
    private let dataHandlerState: Mutex<DataHandler?>
    private let sendHandler: SendHandler
    private let expectedFingerprint: CertificateFingerprint?
    private let logger: Logger

    private struct ConnState: Sendable {
        var state: WebRTCConnectionState = .new
        var iceAgent: ICELiteAgent
        var sctpAssociation: SCTPAssociation
        var channelManager: DataChannelManager
        var isClient: Bool
    }

    private struct ChannelState: Sendable {
        var incomingStream: AsyncStream<DataChannel>?
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
        self.channelState = Mutex(ChannelState())
        self.dataHandlerState = Mutex(nil)
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
            state.state = .connecting
            return state.isClient
        }

        if isClient {
            let datagrams = try dtlsConnection.startHandshake(isClient: true)
            connState.withLock { $0.state = .dtlsHandshaking }
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
    public func receive(_ data: Data, remoteAddress: Data = Data()) throws {
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
    public func openDataChannel(label: String, ordered: Bool = true) throws -> DataChannel {
        let (channel, sctpPacket) = connState.withLock { state -> (DataChannel, SCTPPacket) in
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
    public func send(_ data: Data, on channelID: UInt16, binary: Bool = true) throws {
        let ppid: UInt32
        if data.isEmpty {
            ppid = binary ? DataChannelPPID.binaryEmpty.rawValue : DataChannelPPID.stringEmpty.rawValue
        } else {
            ppid = binary ? DataChannelPPID.binary.rawValue : DataChannelPPID.string.rawValue
        }

        let sctpPacket = connState.withLock { state in
            state.sctpAssociation.sendData(
                streamID: channelID,
                payloadProtocolIdentifier: ppid,
                data: data
            )
        }

        try encryptAndSend(sctpPacket.encode())
    }

    /// Close the connection
    public func close() {
        connState.withLock { state in
            state.state = .closed
            state.iceAgent.close()
        }
        channelState.withLock { state in
            state.incomingContinuation?.finish()
            state.incomingContinuation = nil
            state.incomingStream = nil
        }
        dataHandlerState.withLock { $0 = nil }
    }

    // MARK: - Private protocol processing

    private func processSTUN(_ data: Data, remoteAddress: Data) throws {
        // Single lock for ICE processing + state transition (fixes race condition)
        let response = connState.withLock { state -> Data? in
            let stunResponse = state.iceAgent.processSTUN(
                data: data,
                sourceAddress: remoteAddress,
                sourcePort: 0
            )

            // Check if ICE just became connected while still holding the lock
            if state.iceAgent.state == .connected && state.state == .connecting {
                state.state = .dtlsHandshaking
                logger.debug("ICE connectivity check succeeded")
            }

            return stunResponse
        }

        if let response {
            sendHandler(response)
        }
    }

    private func processDTLS(_ data: Data, remoteAddress: Data) throws {
        let output = try dtlsConnection.processReceivedDatagram(data, remoteAddress: remoteAddress)

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
                connState.withLock { $0.state = .failed("No remote certificate after handshake") }
                throw WebRTCError.dtlsHandshakeFailed("No remote certificate")
            }
            guard actual == expected else {
                connState.withLock { $0.state = .failed("Fingerprint mismatch") }
                throw WebRTCError.dtlsHandshakeFailed(
                    "Remote fingerprint mismatch: expected \(expected.sdpFormat), got \(actual.sdpFormat)"
                )
            }
        }

        connState.withLock { $0.state = .sctpConnecting }
        logger.info("DTLS handshake complete, establishing SCTP")

        // Initiate SCTP association (client side)
        let isClient = connState.withLock { $0.isClient }
        if isClient {
            let initPacket = connState.withLock { $0.sctpAssociation.generateInit() }
            try encryptAndSend(initPacket.encode())
        }
    }

    private func processSCTP(_ plaintext: Data) throws {
        // Parse SCTP packet (already decrypted)
        let packet = try SCTPPacket.decode(from: plaintext)
        let (responses, receivedData) = try connState.withLock { state in
            try state.sctpAssociation.processPacket(packet)
        }

        // Check if SCTP became established
        let previousState = connState.withLock { state -> WebRTCConnectionState in
            let sctpState = state.sctpAssociation.state
            let prev = state.state
            if sctpState == .established && prev == .sctpConnecting {
                state.state = .connected
            }
            return prev
        }
        if previousState == .sctpConnecting {
            let currentState = connState.withLock { $0.state }
            if currentState == .connected {
                logger.info("WebRTC connection established")
            }
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

    @discardableResult
    private func encryptAndSend(_ plaintext: Data) throws -> Data {
        let encrypted = try dtlsConnection.writeApplicationData(plaintext)
        sendHandler(encrypted)
        return encrypted
    }
}
