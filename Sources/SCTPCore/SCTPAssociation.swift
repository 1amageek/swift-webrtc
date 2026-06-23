/// SCTP Association (RFC 4960)
///
/// Manages an SCTP association over DTLS for WebRTC data channels.
/// Includes secure cookie handling, TSN tracking, fragment reassembly,
/// and retransmission support.

import Foundation
import Synchronization
import Crypto

/// SCTP association state
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

/// SCTP association managing streams and TSN tracking
public final class SCTPAssociation: Sendable {
    private let assocState: Mutex<AssocState>

    /// Secret key for cookie HMAC (generated once per association)
    private let cookieSecretKey: Data

    /// Maximum number of inbound streams this endpoint is willing to accept.
    /// Advertised in INIT/INIT-ACK and used to bound the negotiated inbound
    /// stream count. DATA for a stream ID at or above the negotiated count is
    /// rejected (RFC 4960 §3.3.2 / §6.5).
    private let localMaxInboundStreams: UInt16

    /// Maximum number of outbound streams this endpoint will open.
    private let localMaxOutboundStreams: UInt16

    private struct AssocState: Sendable {
        var state: SCTPAssociationState = .closed
        var localPort: UInt16
        var remotePort: UInt16
        var localVerificationTag: UInt32
        var remoteVerificationTag: UInt32 = 0
        var nextTSN: UInt32
        var advertisedReceiverWindowCredit: UInt32 = 65535
        var nextStreamSeqNumber: [UInt16: UInt16] = [:]

        // Cookie data from INIT-ACK (for client)
        var receivedCookie: Data?

        // Peer's parameters (from INIT/INIT-ACK)
        var peerInitialTSN: UInt32 = 0
        var peerARWC: UInt32 = 65535
        var negotiatedOutboundStreams: UInt16 = 65535
        var negotiatedInboundStreams: UInt16 = 65535

        // TSN tracking
        var tsnTracker: TSNTracker?

        // Fragment reassembly
        var fragmentAssembler: FragmentAssembler = FragmentAssembler()

        // Retransmission queue
        var retransmissionQueue: RetransmissionQueue = RetransmissionQueue()

        // Consumed COOKIE-ECHO cache (RFC 4960 §5.1.5): maps a consumed
        // cookie's HMAC to the system-uptime millisecond timestamp at which it
        // was consumed, so a captured valid COOKIE-ECHO cannot be replayed for
        // the remainder of the cookie's validity window.
        var consumedCookies: [Data: UInt64] = [:]
    }

    public init(
        localPort: UInt16 = 5000,
        remotePort: UInt16 = 5000,
        maxInboundStreams: UInt16 = 65535,
        maxOutboundStreams: UInt16 = 65535
    ) {
        // RFC 4960 §3.3.2: the initiate tag must not be 0
        let tag = SCTPSecureRandom.uint32NonZero()
        let initialTSN = SCTPSecureRandom.uint32()
        let secretKey = SCTPSecureRandom.data(count: 32)
        self.cookieSecretKey = secretKey
        // RFC 4960 §3.3.2: at least one stream in each direction.
        self.localMaxInboundStreams = max(1, maxInboundStreams)
        self.localMaxOutboundStreams = max(1, maxOutboundStreams)

        self.assocState = Mutex(AssocState(
            localPort: localPort,
            remotePort: remotePort,
            localVerificationTag: tag,
            nextTSN: initialTSN
        ))
    }

    /// Current association state
    public var state: SCTPAssociationState {
        assocState.withLock { $0.state }
    }

    /// Generate an INIT chunk to start association
    public func generateInit() -> SCTPPacket {
        let (localPort, remotePort, tag, tsn) = assocState.withLock { s -> (UInt16, UInt16, UInt32, UInt32) in
            s.state = .cookieWait
            return (s.localPort, s.remotePort, s.localVerificationTag, s.nextTSN)
        }

        let initChunk = SCTPInitChunk(
            initiateTag: tag,
            numberOfOutboundStreams: localMaxOutboundStreams,
            numberOfInboundStreams: localMaxInboundStreams,
            initialTSN: tsn
        )

        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: 0,
            chunks: [initChunk.toChunk()]
        )
    }

    /// Process incoming SCTP packet
    /// - Returns: Response packets to send, and any received data
    /// - Throws: `SCTPError.verificationTagMismatch` for spoofed/stale packets,
    ///   `SCTPError.associationAborted` when the peer aborts the association,
    ///   decode and buffer-limit errors from chunk processing
    public func processPacket(_ packet: SCTPPacket) throws -> (responses: [SCTPPacket], receivedData: [(streamID: UInt16, ppid: UInt32, data: Data)]) {
        try validateVerificationTag(packet)

        var responses: [SCTPPacket] = []
        var receivedData: [(streamID: UInt16, ppid: UInt32, data: Data)] = []
        var receivedDataChunk = false

        chunkLoop: for chunk in packet.chunks {
            guard let chunkType = SCTPChunkType(rawValue: chunk.chunkType) else {
                // RFC 4960 §3.2: the upper two bits of an unrecognized chunk
                // type select the action.
                switch chunk.chunkType >> 6 {
                case 0b00, 0b01:
                    // 00/01: stop processing the rest of this packet
                    break chunkLoop
                default:
                    // 10/11: skip this chunk, continue processing
                    continue
                }
            }

            switch chunkType {
            case .initChunk:
                let initChunk = try SCTPInitChunk.decode(from: chunk.value)
                let response = handleInit(initChunk, sourcePort: packet.sourcePort)
                responses.append(response)

            case .initAck:
                try handleInitAck(chunk)
                // Send COOKIE-ECHO
                let cookieEcho = try generateCookieEcho()
                responses.append(cookieEcho)

            case .cookieEcho:
                let response = try handleCookieEcho(chunk)
                responses.append(response)

            case .cookieAck:
                handleCookieAck()

            case .data:
                let dataChunk = try SCTPDataChunk.decode(from: chunk.value, flags: chunk.flags)
                // Duplicates must also trigger a SACK (with duplicate report)
                receivedDataChunk = true

                let assembled = try assocState.withLock { s -> [AssembledMessage] in
                    guard var tracker = s.tsnTracker else {
                        throw SCTPError.invalidState("DATA chunk received before TSN tracking was initialized")
                    }
                    // RFC 4960 §6.5: a DATA chunk for a stream ID beyond the
                    // negotiated inbound stream count is invalid. Reject it
                    // instead of letting per-stream maps grow for all 65535 IDs.
                    guard dataChunk.streamIdentifier < s.negotiatedInboundStreams else {
                        throw SCTPError.invalidStreamIdentifier(
                            streamID: dataChunk.streamIdentifier,
                            negotiated: s.negotiatedInboundStreams
                        )
                    }
                    let isNew = tracker.receive(tsn: dataChunk.tsn)
                    s.tsnTracker = tracker
                    guard isNew else { return [] }
                    return try s.fragmentAssembler.process(chunk: dataChunk)
                }

                for msg in assembled {
                    // AssembledMessage.data is [UInt8] in the Embedded-clean
                    // core; bridge to Data at this adapter-side boundary.
                    receivedData.append((msg.streamID, msg.ppid, Data(msg.data)))
                }

            case .sack:
                let sackChunk = try SCTPSackChunk.decode(from: chunk.value)
                handleSack(sackChunk)

            case .shutdown:
                let ack = generateShutdownAck()
                responses.append(ack)

            case .shutdownAck:
                assocState.withLock { $0.state = .closed }

            case .heartbeat:
                // Echo heartbeat back
                let response = handleHeartbeat(chunk)
                responses.append(response)

            case .heartbeatAck:
                // Heartbeat acknowledged - update RTT if needed
                break

            case .abort:
                // RFC 4960 §9.1: the association is destroyed immediately
                assocState.withLock { $0.state = .closed }
                throw SCTPError.associationAborted

            case .error:
                // Operation Error is advisory and does not change association
                // state (RFC 4960 §3.3.10)
                break

            case .forwardTSN, .reConfig:
                // Recognized extension chunks, not yet implemented — skip
                break
            }
        }

        // RFC 4960 §6.2: send at most one SACK per packet, after all DATA
        // chunks in the packet have been processed
        if receivedDataChunk {
            guard let sack = generateSack() else {
                throw SCTPError.invalidState("SACK requested before TSN tracking was initialized")
            }
            responses.append(sack)

            // Garbage-collect abandoned fragment groups now that the
            // cumulative TSN has advanced
            assocState.withLock { s in
                if let tracker = s.tsnTracker {
                    s.fragmentAssembler.cleanup(currentTSN: tracker.cumulativeTSN)
                }
            }
        }

        return (responses, receivedData)
    }

    /// Validate the packet's verification tag (RFC 4960 §8.5)
    private func validateVerificationTag(_ packet: SCTPPacket) throws {
        // RFC 4960 §8.5.1 (A): packets carrying INIT must use tag 0
        let containsInit = packet.chunks.contains { $0.chunkType == SCTPChunkType.initChunk.rawValue }
        if containsInit {
            guard packet.verificationTag == 0 else {
                throw SCTPError.verificationTagMismatch(expected: 0, actual: packet.verificationTag)
            }
            return
        }

        let (localTag, remoteTag) = assocState.withLock {
            ($0.localVerificationTag, $0.remoteVerificationTag)
        }

        if packet.verificationTag == localTag {
            return
        }

        // A legitimate peer that wants to abort an established association sends
        // the ABORT carrying OUR local verification tag (handled above), which
        // it learned during the handshake. We deliberately do NOT accept an
        // ABORT bearing the peer's own (remote) verification tag: that tag
        // travels in cleartext on every packet, so an off-path attacker who can
        // observe one datagram could otherwise forge a reflected-tag ABORT and
        // tear down the association (RFC 4960 §8.5.1 reflected-tag ABORTs are
        // only meaningful for out-of-the-blue packets, not for destroying a
        // live association). Origin authenticity for in-association control is
        // provided by the verified DTLS layer beneath SCTP.
        _ = remoteTag
        throw SCTPError.verificationTagMismatch(expected: localTag, actual: packet.verificationTag)
    }

    /// Send data on a stream
    /// - Throws: `SCTPError.sendQueueFull` when the retransmission queue's
    ///   send-window ceiling is reached (backpressure); the caller must retry
    ///   later rather than dropping data. The TSN/stream sequence are only
    ///   advanced once the chunk is successfully enqueued, so a rejected send
    ///   leaves no gap in the sequence space.
    public func sendData(
        streamID: UInt16,
        payloadProtocolIdentifier: UInt32,
        data: Data,
        unordered: Bool = false
    ) throws -> SCTPPacket {
        return try assocState.withLock { s -> SCTPPacket in
            let tsn = s.nextTSN
            let seqNum = s.nextStreamSeqNumber[streamID, default: 0]

            let dataChunk = SCTPDataChunk(
                tsn: tsn,
                streamIdentifier: streamID,
                streamSequenceNumber: seqNum,
                payloadProtocolIdentifier: payloadProtocolIdentifier,
                userData: data,
                unordered: unordered
            )

            // Enqueue first; only advance the sequence space if it is admitted,
            // so backpressure never burns a TSN or stream sequence number.
            try s.retransmissionQueue.enqueue(dataChunk)

            s.nextTSN = s.nextTSN &+ 1
            if !unordered {
                s.nextStreamSeqNumber[streamID] = seqNum &+ 1
            }

            return SCTPPacket(
                sourcePort: s.localPort,
                destinationPort: s.remotePort,
                verificationTag: s.remoteVerificationTag,
                chunks: [dataChunk.toChunk()]
            )
        }
    }

    /// Get pending retransmissions
    /// - Parameter now: Current time; injectable for deterministic testing of
    ///   timer-driven retransmission and abort behavior.
    /// - Returns: Packets to retransmit, or error if max retransmits exceeded
    public func getPendingRetransmissions(now: ContinuousClock.Instant = .now) -> Result<[SCTPPacket], SCTPError> {
        assocState.withLock { s in
            switch s.retransmissionQueue.pendingRetransmissions(now: now) {
            case .success(let chunks):
                guard !chunks.isEmpty else { return .success([]) }
                let packets = chunks.map { chunk in
                    SCTPPacket(
                        sourcePort: s.localPort,
                        destinationPort: s.remotePort,
                        verificationTag: s.remoteVerificationTag,
                        chunks: [chunk.toChunk()]
                    )
                }
                return .success(packets)
            case .failure:
                // RFC 4960 §8.2: exceeding 'Association.Max.Retrans' for a DATA
                // chunk destroys the association. Transition to closed so the
                // association cannot continue to be used after the peer is
                // considered unreachable.
                s.state = .closed
                return .failure(.maxRetransmitsExceeded)
            }
        }
    }

    /// Check if retransmission queue is empty
    public var hasUnacknowledgedData: Bool {
        assocState.withLock { !$0.retransmissionQueue.isEmpty }
    }

    // MARK: - Private handlers

    private func handleInit(_ initChunk: SCTPInitChunk, sourcePort: UInt16) -> SCTPPacket {
        let (localPort, remotePort, localTag, localTSN, cookie) = assocState.withLock { s -> (UInt16, UInt16, UInt32, UInt32, SCTPCookie) in
            // RFC 4960 §5.2.1/§5.2.2: an INIT received while the association is
            // not CLOSED must NOT tear down or mutate the live association. We
            // reply with an INIT-ACK carrying a fresh cookie that encodes the
            // peer's *new* parameters, but defer committing them until a valid
            // COOKIE-ECHO for that cookie arrives (handled in handleCookieEcho).
            // This prevents a spoofed/duplicate INIT from resetting TSN tracking
            // and verification tags on an established association.
            let isCold = (s.state == .closed)

            // Negotiate stream counts as a true minimum of our local maxima and
            // the peer's request (RFC 4960 §5.1.1):
            //  - outbound (we send) = min(our OS, peer's MIS)
            //  - inbound  (we recv) = min(our MIS, peer's OS)
            let negotiatedOutbound = min(localMaxOutboundStreams, initChunk.numberOfInboundStreams)
            let negotiatedInbound = min(localMaxInboundStreams, initChunk.numberOfOutboundStreams)

            if isCold {
                s.remoteVerificationTag = initChunk.initiateTag
                s.remotePort = sourcePort
                s.peerInitialTSN = initChunk.initialTSN
                s.peerARWC = initChunk.advertisedReceiverWindowCredit
                s.negotiatedOutboundStreams = negotiatedOutbound
                s.negotiatedInboundStreams = negotiatedInbound

                // Initialize TSN tracker with peer's initial TSN
                s.tsnTracker = TSNTracker(initialTSN: initChunk.initialTSN)
            }

            // Generate secure cookie (P0.1) encoding the peer's parameters from
            // THIS INIT. The cookie — not live state — is the source of truth
            // that handleCookieEcho commits.
            let cookie = SCTPCookie.generate(
                secretKey: cookieSecretKey,
                peerTag: initChunk.initiateTag,
                localTag: s.localVerificationTag,
                peerInitialTSN: initChunk.initialTSN,
                peerARWC: initChunk.advertisedReceiverWindowCredit,
                outboundStreams: negotiatedOutbound,
                inboundStreams: negotiatedInbound
            )

            return (s.localPort, sourcePort, s.localVerificationTag, s.nextTSN, cookie)
        }

        // Build INIT-ACK with cookie, advertising our local stream maxima.
        let initAck = SCTPInitChunk(
            initiateTag: localTag,
            numberOfOutboundStreams: localMaxOutboundStreams,
            numberOfInboundStreams: localMaxInboundStreams,
            initialTSN: localTSN
        )

        var initAckValue = initAck.encode()

        // Append State Cookie parameter (type=7, length=60+4=64)
        let cookieData = cookie.encode()
        let cookieParam = encodeCookieParameter(cookieData)
        initAckValue.append(cookieParam)

        let ackChunk = SCTPChunk(chunkType: SCTPChunkType.initAck.rawValue, value: initAckValue)

        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: initChunk.initiateTag,
            chunks: [ackChunk]
        )
    }

    private func handleInitAck(_ chunk: SCTPChunk) throws {
        // Parse INIT-ACK and extract cookie
        let value = chunk.value
        guard value.count >= 16 else {
            throw SCTPError.invalidFormat("INIT-ACK too short")
        }

        let initAck = try SCTPInitChunk.decode(from: value)

        // Extract State Cookie parameter
        var offset = 16 // Skip fixed INIT-ACK fields
        var cookieData: Data?

        while offset + 4 <= value.count {
            let paramType = readUInt16(value, offset: offset)
            let paramLength = Int(readUInt16(value, offset: offset + 2))

            // Parameter length includes its own 4-byte header; anything
            // smaller is malformed and would stall the scan
            guard paramLength >= 4 else {
                throw SCTPError.invalidFormat("Invalid parameter length in INIT-ACK")
            }

            if paramType == 7 { // State Cookie
                guard paramLength >= 4, offset + paramLength <= value.count else {
                    throw SCTPError.invalidFormat("Cookie parameter truncated")
                }
                // chunk.value is a slice — index relative to startIndex
                let base = value.startIndex
                cookieData = Data(value[(base + offset + 4)..<(base + offset + paramLength)])
                break
            }

            // RFC 4960 §3.2.1: the top two bits of an unrecognized parameter
            // type select the action. We don't recognize any non-cookie
            // parameter here, so honor a stop-action (00/01) by halting the
            // scan; skip-actions (10/11) fall through to the advance below.
            switch paramType >> 14 {
            case 0b00, 0b01:
                // Stop parameter processing. The cookie (if absent) is caught
                // by the guard after the loop, surfacing a typed error rather
                // than silently continuing.
                offset = value.count
            default:
                // Move to next parameter (padded to 4 bytes)
                offset += (paramLength + 3) & ~3
            }
        }

        guard let cookie = cookieData else {
            throw SCTPError.invalidFormat("No State Cookie in INIT-ACK")
        }

        assocState.withLock { s in
            s.remoteVerificationTag = initAck.initiateTag
            s.peerInitialTSN = initAck.initialTSN
            s.peerARWC = initAck.advertisedReceiverWindowCredit
            s.negotiatedOutboundStreams = min(localMaxOutboundStreams, initAck.numberOfInboundStreams)
            s.negotiatedInboundStreams = min(localMaxInboundStreams, initAck.numberOfOutboundStreams)
            s.receivedCookie = cookie
            s.tsnTracker = TSNTracker(initialTSN: initAck.initialTSN)
            s.state = .cookieEchoed
        }
    }

    private func generateCookieEcho() throws -> SCTPPacket {
        let (localPort, remotePort, remoteTag, cookie) = try assocState.withLock { s -> (UInt16, UInt16, UInt32, Data) in
            guard let cookie = s.receivedCookie else {
                throw SCTPError.invalidState("COOKIE-ECHO requested before INIT-ACK delivered a cookie")
            }
            return (s.localPort, s.remotePort, s.remoteVerificationTag, cookie)
        }

        let chunk = SCTPChunk(chunkType: SCTPChunkType.cookieEcho.rawValue, value: cookie)
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteTag,
            chunks: [chunk]
        )
    }

    private func handleCookieEcho(_ chunk: SCTPChunk) throws -> SCTPPacket {
        // Validate cookie (HMAC + expiry). chunk.value is [UInt8] in the
        // Embedded-clean core; bridge to Data for the Foundation cookie codec.
        let cookie = try SCTPCookie.decode(from: Data(chunk.value))

        guard cookie.validate(secretKey: cookieSecretKey) else {
            throw SCTPError.cookieValidationFailed
        }

        // RFC 4960 §5.1.5: reject a replayed COOKIE-ECHO. A captured valid
        // cookie is otherwise replayable for the whole validity window, which
        // would let an attacker re-establish / reset the association. The
        // cookie's HMAC (which includes the creation timestamp) uniquely
        // identifies it, so consuming it once is sufficient.
        let (localPort, remotePort, remoteTag) = try assocState.withLock { s -> (UInt16, UInt16, UInt32) in
            // Evict consumed-cookie entries older than the cookie validity
            // window so the cache cannot grow without bound.
            let now = SCTPCookie.nowMilliseconds()
            let maxAgeMillis = UInt64(SCTPCookie.defaultMaxAge * 1000)
            s.consumedCookies = s.consumedCookies.filter { _, consumedAt in
                now >= consumedAt && (now - consumedAt) <= maxAgeMillis
            }

            if s.consumedCookies[cookie.hmac] != nil {
                throw SCTPError.cookieValidationFailed
            }
            s.consumedCookies[cookie.hmac] = now

            // Commit the peer parameters carried by the validated cookie. This
            // is the only path that mutates TSN tracking / verification tags
            // for an inbound peer — handleInit no longer does so for a live
            // association (RFC 4960 §5.2).
            s.remoteVerificationTag = cookie.peerTag
            s.peerInitialTSN = cookie.peerInitialTSN
            s.peerARWC = cookie.peerARWC
            s.negotiatedOutboundStreams = cookie.outboundStreams
            s.negotiatedInboundStreams = cookie.inboundStreams
            s.tsnTracker = TSNTracker(initialTSN: cookie.peerInitialTSN)
            s.state = .established
            return (s.localPort, s.remotePort, s.remoteVerificationTag)
        }

        let ackChunk = SCTPChunk(chunkType: SCTPChunkType.cookieAck.rawValue, value: Data())
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteTag,
            chunks: [ackChunk]
        )
    }

    private func handleCookieAck() {
        assocState.withLock { $0.state = .established }
    }

    private func handleSack(_ sack: SCTPSackChunk) {
        assocState.withLock { s in
            _ = s.retransmissionQueue.acknowledge(
                cumulativeTSN: sack.cumulativeTSNAck,
                gapBlocks: sack.gapAckBlocks
            )
        }
    }

    private func handleHeartbeat(_ chunk: SCTPChunk) -> SCTPPacket {
        let (localPort, remotePort, remoteTag) = assocState.withLock { s in
            (s.localPort, s.remotePort, s.remoteVerificationTag)
        }

        // Echo heartbeat info back
        let ackChunk = SCTPChunk(
            chunkType: SCTPChunkType.heartbeatAck.rawValue,
            value: chunk.value
        )

        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteTag,
            chunks: [ackChunk]
        )
    }

    /// Generate a SACK for the current receive state.
    ///
    /// The advertised receiver window reflects the bytes currently held by
    /// the fragment assembler (incomplete fragments and out-of-order
    /// messages). Fully assembled in-order data is delivered to the
    /// application immediately and no longer counts against the window.
    /// - Returns: nil when TSN tracking has not been initialized yet
    ///   (no DATA can legitimately have been received)
    private func generateSack() -> SCTPPacket? {
        let snapshot = assocState.withLock { s -> (UInt16, UInt16, UInt32, UInt32, [(start: UInt16, end: UInt16)], [UInt32], UInt32)? in
            guard var tracker = s.tsnTracker else {
                return nil
            }
            let dups = tracker.takeDuplicates()
            let gaps = tracker.gapBlocks
            let cumulativeTSN = tracker.cumulativeTSN
            s.tsnTracker = tracker
            let buffered = UInt32(clamping: s.fragmentAssembler.bufferedBytes)
            let available = s.advertisedReceiverWindowCredit >= buffered
                ? s.advertisedReceiverWindowCredit - buffered
                : 0
            return (s.localPort, s.remotePort, s.remoteVerificationTag, cumulativeTSN, gaps, dups, available)
        }

        guard let (localPort, remotePort, remoteTag, cumulativeTSN, gaps, dups, availableWindow) = snapshot else {
            return nil
        }

        let sack = SCTPSackChunk(
            cumulativeTSNAck: cumulativeTSN,
            advertisedReceiverWindowCredit: availableWindow,
            gapAckBlocks: gaps,
            duplicateTSNs: dups
        )

        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteTag,
            chunks: [sack.toChunk()]
        )
    }

    private func generateShutdownAck() -> SCTPPacket {
        let (localPort, remotePort, remoteTag) = assocState.withLock { s in
            s.state = .shutdownAckSent
            return (s.localPort, s.remotePort, s.remoteVerificationTag)
        }

        let chunk = SCTPChunk(chunkType: SCTPChunkType.shutdownAck.rawValue, value: Data())
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteTag,
            chunks: [chunk]
        )
    }

    // MARK: - Helpers

    private func encodeCookieParameter(_ cookie: Data) -> Data {
        var param = Data()
        // Parameter Type = 7 (State Cookie)
        param.append(0x00)
        param.append(0x07)
        // Parameter Length (including type and length fields)
        let length = UInt16(4 + cookie.count)
        param.append(UInt8(length >> 8))
        param.append(UInt8(length & 0xFF))
        // Cookie value
        param.append(cookie)
        // Pad to 4-byte boundary
        let padding = (4 - (cookie.count % 4)) % 4
        if padding > 0 {
            param.append(Data(repeating: 0, count: padding))
        }
        return param
    }
}
