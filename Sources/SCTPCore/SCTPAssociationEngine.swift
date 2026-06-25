/// SCTP Association orchestration engine (RFC 4960) — Embedded-clean, sans-IO,
/// caller-locked value type.
///
/// This is the cored orchestration the host `SCTPAssociation` adapter drives. It
/// mirrors the PROVEN engine pattern (tls `TLSClientEngine`, quic
/// `QUICConnectionEngine`, SWIM `MembershipState`):
///
/// - **Value type, caller-locked**: a `struct` with `mutating` methods. It holds
///   NO `Synchronization.Mutex` / actor; the adapter (`SCTPAssociation`) holds it
///   behind a `FacadeLock` and serialises every call. No `any`, no Foundation.
/// - **Sans-IO**: it consumes/produces `SCTPPacket` values (over `[UInt8]`) and
///   returns response packets + received data. It performs no socket I/O.
/// - **Time injected**: T3-rtx retransmission and cookie expiry/replay eviction are
///   caller-driven via `nowMillis: UInt64` parameters — no `ContinuousClock`,
///   `Date`, or `ProcessInfo`.
/// - **Crypto via seam**: the COOKIE HMAC routes through the
///   `MessageAuthenticationCode` seam (the generic `M`), so the same engine signs
///   with swift-crypto on host and BoringSSL under Embedded.
///
/// All security/correctness invariants are preserved verbatim from the historical
/// `SCTPAssociation`: RFC 1982 serial arithmetic (in `TSNTracker`), capped
/// reassembly/reorder buffers (in `FragmentReassembler`/`TSNTracker`), COOKIE
/// replay protection, INIT/COOKIE state validation (an INIT on a live association
/// does not mutate it; only a validated COOKIE-ECHO commits peer parameters), and
/// the verification-tag checks (RFC 4960 §8.5).

import P2PCoreBytes
import P2PCoreCrypto
@_exported import SCTPWireCore

/// SCTP association state.
public enum SCTPAssociationState: Sendable, Equatable {
    case closed
    case cookieWait
    case cookieEchoed
    case established
    case shutdownPending
    case shutdownSent
    case shutdownReceived
    case shutdownAckSent
}

/// A received application message surfaced from a processed packet.
public struct SCTPReceivedMessage: Sendable {
    public let streamID: UInt16
    public let ppid: UInt32
    public let data: [UInt8]

    public init(streamID: UInt16, ppid: UInt32, data: [UInt8]) {
        self.streamID = streamID
        self.ppid = ppid
        self.data = data
    }
}

/// The Embedded-clean SCTP association FSM.
///
/// Generic over the COOKIE HMAC seam `M`. The adapter specialises `M` at the
/// concrete provider for the build (host: `FoundationHMACSHA256`; Embedded:
/// `BoringHMACSHA256`).
public struct SCTPAssociationEngine<M: MessageAuthenticationCode>: Sendable {
    // MARK: - Stored state

    public private(set) var state: SCTPAssociationState = .closed

    private var localPort: UInt16
    private var remotePort: UInt16
    private var localVerificationTag: UInt32
    private var remoteVerificationTag: UInt32 = 0
    private var nextTSN: UInt32
    private var advertisedReceiverWindowCredit: UInt32 = 65535
    private var nextStreamSeqNumber: [UInt16: UInt16] = [:]

    /// Secret key for cookie HMAC (generated once per association, supplied by
    /// the adapter from the `RandomSource` seam).
    private let cookieSecretKey: [UInt8]

    /// Maximum number of inbound streams this endpoint will accept.
    private let localMaxInboundStreams: UInt16

    /// Maximum number of outbound streams this endpoint will open.
    private let localMaxOutboundStreams: UInt16

    // Cookie data from INIT-ACK (for client).
    private var receivedCookie: [UInt8]?

    // Peer's parameters (from INIT/INIT-ACK).
    private var peerInitialTSN: UInt32 = 0
    private var peerARWC: UInt32 = 65535
    private var negotiatedOutboundStreams: UInt16 = 65535
    private var negotiatedInboundStreams: UInt16 = 65535

    // TSN tracking.
    private var tsnTracker: TSNTracker?

    // Fragment reassembly.
    private var fragmentAssembler: FragmentReassembler = FragmentReassembler()

    // Retransmission queue (Embedded-clean millis-domain accounting).
    private var retransmissionState: RetransmissionState = RetransmissionState()

    /// Consumed COOKIE-ECHO cache (RFC 4960 §5.1.5): maps a consumed cookie's
    /// HMAC to the millisecond timestamp at which it was consumed, so a captured
    /// valid COOKIE-ECHO cannot be replayed for the rest of its validity window.
    private var consumedCookies: [[UInt8]: UInt64] = [:]

    /// Cookie validity window in milliseconds (matches the historical 60s).
    public static var cookieMaxAgeMillis: UInt64 { 60_000 }

    // MARK: - Init

    /// Creates the engine. The random handshake material (initiate tag, initial
    /// TSN, cookie secret) is supplied by the adapter from the `RandomSource`
    /// seam so the engine itself stays deterministic and Embedded-clean.
    public init(
        localPort: UInt16,
        remotePort: UInt16,
        maxInboundStreams: UInt16,
        maxOutboundStreams: UInt16,
        initiateTag: UInt32,
        initialTSN: UInt32,
        cookieSecretKey: [UInt8]
    ) {
        self.localPort = localPort
        self.remotePort = remotePort
        self.localVerificationTag = initiateTag
        self.nextTSN = initialTSN
        self.cookieSecretKey = cookieSecretKey
        // RFC 4960 §3.3.2: at least one stream in each direction.
        self.localMaxInboundStreams = max(1, maxInboundStreams)
        self.localMaxOutboundStreams = max(1, maxOutboundStreams)
    }

    // MARK: - Read-only queries

    public var hasUnacknowledgedData: Bool { !retransmissionState.isEmpty }

    // MARK: - Handshake initiation

    /// Generate an INIT chunk to start the association.
    public mutating func generateInit() -> SCTPPacket {
        state = .cookieWait
        let initChunk = SCTPInitChunk(
            initiateTag: localVerificationTag,
            numberOfOutboundStreams: localMaxOutboundStreams,
            numberOfInboundStreams: localMaxInboundStreams,
            initialTSN: nextTSN
        )
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: 0,
            chunks: [initChunk.toChunk()]
        )
    }

    // MARK: - Packet processing

    /// Process an incoming SCTP packet.
    ///
    /// - Parameter nowMillis: the current time on the caller's monotonic clock,
    ///   used for cookie expiry checks and consumed-cookie eviction.
    /// - Returns: response packets to send and any received application data.
    /// - Throws: `SCTPError.verificationTagMismatch` for spoofed/stale packets,
    ///   `SCTPError.associationAborted` when the peer aborts, decode/buffer-limit
    ///   errors from chunk processing.
    public mutating func processPacket(
        _ packet: SCTPPacket,
        nowMillis: UInt64
    ) throws(SCTPError) -> (responses: [SCTPPacket], receivedData: [SCTPReceivedMessage]) {
        try validateVerificationTag(packet)

        var responses: [SCTPPacket] = []
        var receivedData: [SCTPReceivedMessage] = []
        var receivedDataChunk = false

        chunkLoop: for chunk in packet.chunks {
            guard let chunkType = SCTPChunkType(rawValue: chunk.chunkType) else {
                // RFC 4960 §3.2: the upper two bits of an unrecognized chunk type
                // select the action.
                switch chunk.chunkType >> 6 {
                case 0b00, 0b01:
                    break chunkLoop
                default:
                    continue
                }
            }

            switch chunkType {
            case .initChunk:
                let initChunk = try decodeInit(chunk.value)
                responses.append(handleInit(initChunk, sourcePort: packet.sourcePort, nowMillis: nowMillis))

            case .initAck:
                try handleInitAck(chunk)
                responses.append(try generateCookieEcho())

            case .cookieEcho:
                responses.append(try handleCookieEcho(chunk, nowMillis: nowMillis))

            case .cookieAck:
                state = .established

            case .data:
                let dataChunk = try decodeData(chunk.value, flags: chunk.flags)
                receivedDataChunk = true

                guard var tracker = tsnTracker else {
                    throw SCTPError.invalidState("DATA chunk received before TSN tracking was initialized")
                }
                // RFC 4960 §6.5: a DATA chunk for a stream ID beyond the
                // negotiated inbound stream count is invalid.
                guard dataChunk.streamIdentifier < negotiatedInboundStreams else {
                    throw SCTPError.invalidStreamIdentifier(
                        streamID: dataChunk.streamIdentifier,
                        negotiated: negotiatedInboundStreams
                    )
                }
                let isNew = tracker.receive(tsn: dataChunk.tsn)
                tsnTracker = tracker
                if isNew {
                    let assembled = try processFragment(dataChunk)
                    for msg in assembled {
                        receivedData.append(SCTPReceivedMessage(streamID: msg.streamID, ppid: msg.ppid, data: msg.data))
                    }
                }

            case .sack:
                let sackChunk = try decodeSack(chunk.value)
                _ = retransmissionState.acknowledge(
                    cumulativeTSN: sackChunk.cumulativeTSNAck,
                    gapBlocks: sackChunk.gapAckBlocks,
                    receivedMillis: nowMillis
                )

            case .shutdown:
                responses.append(generateShutdownAck())

            case .shutdownAck:
                state = .closed

            case .heartbeat:
                responses.append(handleHeartbeat(chunk))

            case .heartbeatAck:
                break

            case .abort:
                // RFC 4960 §9.1: the association is destroyed immediately.
                state = .closed
                throw SCTPError.associationAborted

            case .error:
                // Operation Error is advisory (RFC 4960 §3.3.10).
                break

            case .forwardTSN, .reConfig:
                // Recognized extension chunks, not yet implemented — skip.
                break
            }
        }

        // RFC 4960 §6.2: send at most one SACK per packet, after all DATA chunks.
        if receivedDataChunk {
            guard let sack = generateSack() else {
                throw SCTPError.invalidState("SACK requested before TSN tracking was initialized")
            }
            responses.append(sack)
            if let tracker = tsnTracker {
                fragmentAssembler.cleanup(currentTSN: tracker.cumulativeTSN)
            }
        }

        return (responses, receivedData)
    }

    // MARK: - Sending

    /// Send data on a stream.
    ///
    /// - Throws: `SCTPError.sendQueueFull` when the retransmission queue's
    ///   send-window ceiling is reached (backpressure). The TSN/stream sequence
    ///   are only advanced once the chunk is enqueued, so a rejected send leaves
    ///   no gap in the sequence space.
    public mutating func sendData(
        streamID: UInt16,
        payloadProtocolIdentifier: UInt32,
        data: [UInt8],
        unordered: Bool,
        nowMillis: UInt64
    ) throws(SCTPError) -> SCTPPacket {
        let tsn = nextTSN
        let seqNum = nextStreamSeqNumber[streamID, default: 0]

        let dataChunk = SCTPDataChunk(
            tsn: tsn,
            streamIdentifier: streamID,
            streamSequenceNumber: seqNum,
            payloadProtocolIdentifier: payloadProtocolIdentifier,
            userData: data,
            unordered: unordered
        )

        // Enqueue first; only advance the sequence space if admitted.
        do {
            try retransmissionState.enqueue(dataChunk, sentMillis: nowMillis)
        } catch {
            throw error.asSCTPError
        }

        nextTSN = nextTSN &+ 1
        if !unordered {
            nextStreamSeqNumber[streamID] = seqNum &+ 1
        }

        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [dataChunk.toChunk()]
        )
    }

    /// Get pending retransmissions.
    ///
    /// - Parameter nowMillis: the current time on the caller's monotonic clock.
    /// - Returns: packets to retransmit, or `.maxRetransmitsExceeded` once the
    ///   per-chunk retransmit limit is exceeded (RFC 4960 §8.2), in which case the
    ///   association transitions to `.closed`.
    public mutating func getPendingRetransmissions(
        nowMillis: UInt64
    ) -> Result<[SCTPPacket], SCTPError> {
        switch retransmissionState.pendingRetransmissions(nowMillis: nowMillis) {
        case .success(let chunks):
            guard !chunks.isEmpty else { return .success([]) }
            let packets = chunks.map { chunk in
                SCTPPacket(
                    sourcePort: localPort,
                    destinationPort: remotePort,
                    verificationTag: remoteVerificationTag,
                    chunks: [chunk.toChunk()]
                )
            }
            return .success(packets)
        case .failure:
            // RFC 4960 §8.2: exceeding the per-DATA retransmit limit destroys the
            // association.
            state = .closed
            return .failure(.maxRetransmitsExceeded)
        }
    }

    // MARK: - Verification tag (RFC 4960 §8.5)

    private func validateVerificationTag(_ packet: SCTPPacket) throws(SCTPError) {
        // RFC 4960 §8.5.1 (A): packets carrying INIT must use tag 0.
        let containsInit = packet.chunks.contains { $0.chunkType == SCTPChunkType.initChunk.rawValue }
        if containsInit {
            guard packet.verificationTag == 0 else {
                throw SCTPError.verificationTagMismatch(expected: 0, actual: packet.verificationTag)
            }
            return
        }

        if packet.verificationTag == localVerificationTag {
            return
        }

        // We deliberately do NOT accept a packet bearing the peer's own (remote)
        // verification tag: that tag travels in cleartext on every packet, so an
        // off-path attacker who observes one datagram could otherwise forge a
        // reflected-tag ABORT and tear down the association. Origin authenticity
        // for in-association control is provided by the verified DTLS layer.
        throw SCTPError.verificationTagMismatch(expected: localVerificationTag, actual: packet.verificationTag)
    }

    // MARK: - Private handlers

    private mutating func handleInit(
        _ initChunk: SCTPInitChunk,
        sourcePort: UInt16,
        nowMillis: UInt64
    ) -> SCTPPacket {
        // RFC 4960 §5.2.1/§5.2.2: an INIT received while the association is not
        // CLOSED must NOT tear down or mutate the live association. We reply with
        // an INIT-ACK carrying a fresh cookie that encodes the peer's *new*
        // parameters, but defer committing them until a valid COOKIE-ECHO arrives.
        let isCold = (state == .closed)

        // Negotiate stream counts (RFC 4960 §5.1.1).
        let negotiatedOutbound = min(localMaxOutboundStreams, initChunk.numberOfInboundStreams)
        let negotiatedInbound = min(localMaxInboundStreams, initChunk.numberOfOutboundStreams)

        if isCold {
            remoteVerificationTag = initChunk.initiateTag
            remotePort = sourcePort
            peerInitialTSN = initChunk.initialTSN
            peerARWC = initChunk.advertisedReceiverWindowCredit
            negotiatedOutboundStreams = negotiatedOutbound
            negotiatedInboundStreams = negotiatedInbound
            tsnTracker = TSNTracker(initialTSN: initChunk.initialTSN)
        }

        // Generate the secure cookie encoding the peer's parameters from THIS
        // INIT. The cookie — not live state — is the source of truth that
        // handleCookieEcho commits.
        let cookie = SCTPCookieCore.generate(
            secretKey: cookieSecretKey,
            timestamp: nowMillis,
            peerTag: initChunk.initiateTag,
            localTag: localVerificationTag,
            peerInitialTSN: initChunk.initialTSN,
            peerARWC: initChunk.advertisedReceiverWindowCredit,
            outboundStreams: negotiatedOutbound,
            inboundStreams: negotiatedInbound,
            as: M.self
        )

        // Build INIT-ACK with cookie, advertising our local stream maxima.
        let initAck = SCTPInitChunk(
            initiateTag: localVerificationTag,
            numberOfOutboundStreams: localMaxOutboundStreams,
            numberOfInboundStreams: localMaxInboundStreams,
            initialTSN: nextTSN
        )

        var initAckValue = initAck.encodeBytes()
        initAckValue.append(contentsOf: encodeCookieParameter(cookie.encode()))

        let ackChunk = SCTPChunk(chunkType: SCTPChunkType.initAck.rawValue, value: initAckValue)
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: sourcePort,
            verificationTag: initChunk.initiateTag,
            chunks: [ackChunk]
        )
    }

    private mutating func handleInitAck(_ chunk: SCTPChunk) throws(SCTPError) {
        let value = chunk.value
        guard value.count >= 16 else {
            throw SCTPError.invalidFormat("INIT-ACK too short")
        }

        let initAck = try decodeInit(value)

        // Extract State Cookie parameter (type=7).
        var offset = 16
        var cookieData: [UInt8]?

        while offset + 4 <= value.count {
            let paramType = readUInt16(value, offset: offset)
            let paramLength = Int(readUInt16(value, offset: offset + 2))

            guard paramLength >= 4 else {
                throw SCTPError.invalidFormat("Invalid parameter length in INIT-ACK")
            }

            if paramType == 7 {
                guard offset + paramLength <= value.count else {
                    throw SCTPError.invalidFormat("Cookie parameter truncated")
                }
                cookieData = Array(value[(offset + 4)..<(offset + paramLength)])
                break
            }

            // RFC 4960 §3.2.1: the top two bits of an unrecognized parameter type
            // select the action.
            switch paramType >> 14 {
            case 0b00, 0b01:
                offset = value.count
            default:
                offset += (paramLength + 3) & ~3
            }
        }

        guard let cookie = cookieData else {
            throw SCTPError.invalidFormat("No State Cookie in INIT-ACK")
        }

        remoteVerificationTag = initAck.initiateTag
        peerInitialTSN = initAck.initialTSN
        peerARWC = initAck.advertisedReceiverWindowCredit
        negotiatedOutboundStreams = min(localMaxOutboundStreams, initAck.numberOfInboundStreams)
        negotiatedInboundStreams = min(localMaxInboundStreams, initAck.numberOfOutboundStreams)
        receivedCookie = cookie
        tsnTracker = TSNTracker(initialTSN: initAck.initialTSN)
        state = .cookieEchoed
    }

    private func generateCookieEcho() throws(SCTPError) -> SCTPPacket {
        guard let cookie = receivedCookie else {
            throw SCTPError.invalidState("COOKIE-ECHO requested before INIT-ACK delivered a cookie")
        }
        let chunk = SCTPChunk(chunkType: SCTPChunkType.cookieEcho.rawValue, value: cookie)
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [chunk]
        )
    }

    private mutating func handleCookieEcho(
        _ chunk: SCTPChunk,
        nowMillis: UInt64
    ) throws(SCTPError) -> SCTPPacket {
        // Validate cookie (HMAC + expiry) via the core's fail-closed binding check.
        let cookie: SCTPCookieCore
        do {
            cookie = try SCTPCookieCore.decode(from: chunk.value)
        } catch {
            throw SCTPError.invalidFormat("Malformed COOKIE-ECHO")
        }

        guard cookie.validateBinding(
            secretKey: cookieSecretKey,
            nowMillis: nowMillis,
            maxAgeMillis: Self.cookieMaxAgeMillis,
            as: M.self
        ) else {
            throw SCTPError.cookieValidationFailed
        }

        // RFC 4960 §5.1.5: reject a replayed COOKIE-ECHO. The cookie's HMAC
        // (which includes the creation timestamp) uniquely identifies it, so
        // consuming it once is sufficient. Evict entries older than the validity
        // window first so the cache cannot grow without bound.
        let maxAge = Self.cookieMaxAgeMillis
        consumedCookies = consumedCookies.filter { _, consumedAt in
            nowMillis >= consumedAt && (nowMillis - consumedAt) <= maxAge
        }
        if consumedCookies[cookie.hmac] != nil {
            throw SCTPError.cookieValidationFailed
        }
        consumedCookies[cookie.hmac] = nowMillis

        // Commit the peer parameters carried by the validated cookie — the only
        // path that mutates TSN tracking / verification tags for an inbound peer.
        remoteVerificationTag = cookie.peerTag
        peerInitialTSN = cookie.peerInitialTSN
        peerARWC = cookie.peerARWC
        negotiatedOutboundStreams = cookie.outboundStreams
        negotiatedInboundStreams = cookie.inboundStreams
        tsnTracker = TSNTracker(initialTSN: cookie.peerInitialTSN)
        state = .established

        let ackChunk = SCTPChunk(chunkType: SCTPChunkType.cookieAck.rawValue, value: [])
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [ackChunk]
        )
    }

    private func handleHeartbeat(_ chunk: SCTPChunk) -> SCTPPacket {
        let ackChunk = SCTPChunk(
            chunkType: SCTPChunkType.heartbeatAck.rawValue,
            value: chunk.value
        )
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [ackChunk]
        )
    }

    /// Generate a SACK for the current receive state.
    ///
    /// The advertised receiver window reflects the bytes currently held by the
    /// fragment assembler. Returns nil when TSN tracking has not been initialized.
    private mutating func generateSack() -> SCTPPacket? {
        guard var tracker = tsnTracker else { return nil }
        let dups = tracker.takeDuplicates()
        let gaps = tracker.gapBlocks
        let cumulativeTSN = tracker.cumulativeTSN
        tsnTracker = tracker

        let buffered = UInt32(clamping: fragmentAssembler.bufferedBytes)
        let available = advertisedReceiverWindowCredit >= buffered
            ? advertisedReceiverWindowCredit - buffered
            : 0

        let sack = SCTPSackChunk(
            cumulativeTSNAck: cumulativeTSN,
            advertisedReceiverWindowCredit: available,
            gapAckBlocks: gaps,
            duplicateTSNs: dups
        )
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [sack.toChunk()]
        )
    }

    private mutating func generateShutdownAck() -> SCTPPacket {
        state = .shutdownAckSent
        let chunk = SCTPChunk(chunkType: SCTPChunkType.shutdownAck.rawValue, value: [])
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [chunk]
        )
    }

    // MARK: - Decode helpers (bridge SCTPWireError -> SCTPError)

    private func decodeInit(_ value: [UInt8]) throws(SCTPError) -> SCTPInitChunk {
        do {
            return try SCTPInitChunk.decode(from: value)
        } catch {
            try error.rethrowUnwrapped()
        }
    }

    private func decodeData(_ value: [UInt8], flags: UInt8) throws(SCTPError) -> SCTPDataChunk {
        do {
            return try SCTPDataChunk.decode(from: value, flags: flags)
        } catch {
            try error.rethrowUnwrapped()
        }
    }

    private func decodeSack(_ value: [UInt8]) throws(SCTPError) -> SCTPSackChunk {
        do {
            return try SCTPSackChunk.decode(from: value)
        } catch {
            try error.rethrowUnwrapped()
        }
    }

    private mutating func processFragment(_ chunk: SCTPDataChunk) throws(SCTPError) -> [AssembledMessage] {
        do {
            return try fragmentAssembler.process(chunk: chunk)
        } catch {
            throw error.asSCTPError
        }
    }

    // MARK: - Cookie parameter framing ([UInt8])

    private func encodeCookieParameter(_ cookie: [UInt8]) -> [UInt8] {
        var param = [UInt8]()
        // Parameter Type = 7 (State Cookie).
        param.append(0x00)
        param.append(0x07)
        let length = UInt16(4 + cookie.count)
        param.append(UInt8(length >> 8))
        param.append(UInt8(length & 0xFF))
        param.append(contentsOf: cookie)
        let padding = (4 - (cookie.count % 4)) % 4
        for _ in 0..<padding {
            param.append(0)
        }
        return param
    }

    private func readUInt16(_ data: [UInt8], offset: Int) -> UInt16 {
        UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
    }
}
