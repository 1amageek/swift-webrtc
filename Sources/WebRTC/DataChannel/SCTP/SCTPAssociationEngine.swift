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
/// - **Crypto via context**: the COOKIE HMAC routes through one immutable,
///   non-generic `SCTPCookieCryptoContext`, so the same engine signs through
///   the package-selected default provider without runtime associated-type
///   dispatch.
///
/// All security/correctness invariants are preserved verbatim from the historical
/// `SCTPAssociation`: RFC 1982 serial arithmetic (in `TSNTracker`), capped
/// reassembly/reorder buffers (in `FragmentReassembler`/`TSNTracker`), COOKIE
/// authenticated restart classification, INIT/COOKIE state validation (an INIT on a live association
/// does not mutate it; only a validated COOKIE-ECHO commits peer parameters), and
/// the verification-tag checks (RFC 4960 §8.5).

import P2PCoreBytes

/// SCTP association state.
enum SCTPAssociationState: Sendable, Equatable {
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
struct SCTPReceivedMessage: Sendable {
    let streamID: UInt16
    let ppid: UInt32
    let data: [UInt8]

    init(streamID: UInt16, ppid: UInt32, data: [UInt8]) {
        self.streamID = streamID
        self.ppid = ppid
        self.data = data
    }
}

private enum SCTPCookieEchoAction: Equatable {
    case establish
    case restart
    case collision
    case discardLate
    case acknowledge
    case discardUnlisted
}

private enum SCTPCookieEchoDisposition {
    /// Continue processing chunks bundled after the authenticated COOKIE-ECHO.
    case proceed(responses: [SCTPPacket], restartEvent: Bool)

    /// Stop processing the complete packet. Responses can contain a Stale Cookie
    /// error, while protocol-mandated silent discards carry an empty array.
    case stop(responses: [SCTPPacket])
}

private struct SCTPInitParameters {
    let supportsStreamReconfiguration: Bool
    let supportsPartialReliability: Bool
    let reportableParameters: [[UInt8]]
}

private struct SCTPInitAckParameters {
    let cookie: [UInt8]
    let supportsStreamReconfiguration: Bool
    let supportsPartialReliability: Bool
    let reportableParameters: [[UInt8]]
}

/// The Embedded-clean SCTP association FSM.
///
/// Cookie authentication is injected as one immutable, non-generic operation
/// owner. The adapter resolves `P2PCrypto.DefaultHMACSHA256` for every build.
struct SCTPAssociationEngine: Sendable {
    // MARK: - Stored state

    private(set) var state: SCTPAssociationState = .closed

    private var localPort: UInt16
    private var remotePort: UInt16
    private var localVerificationTag: UInt32
    private var remoteVerificationTag: UInt32 = 0
    private var nextTSN: UInt32
    /// The advertised window and the actual bounded reassembly capacity must
    /// describe the same resource. Advertising the historical 64 KiB default
    /// while accepting 1 MiB user messages deadlocks reassembly once an
    /// incomplete message consumes that smaller window: the sender cannot put
    /// the ending fragment on the wire and the receiver cannot release the
    /// partial message. The assembler's bounded capacity is therefore the
    /// authoritative initial credit.
    private var advertisedReceiverWindowCredit: UInt32 = UInt32(
        FragmentReassembler.defaultMaxBufferedBytes
    )
    private var nextStreamSeqNumber: [UInt16: UInt16] = [:]

    /// Secret key for cookie HMAC (generated once per association, supplied by
    /// the adapter from the `RandomSource` seam).
    private let cookieSecretKey: [UInt8]

    /// Strongly retains the concrete cookie-MAC operations for at least the
    /// complete lifetime of this engine value.
    private let cookieCrypto: SCTPCookieCryptoContext

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

    /// RFC 6525 state is kept beside DATA retransmission state because the
    /// extension has its own one-request-in-flight timer and response cache.
    private var reconfigurationState: SCTPReconfigurationState

    /// RFC 9260 T2 is independent from the DATA T3 timer.
    private var shutdownTimerState: SCTPShutdownTimerState?

    /// Negotiated from the HMAC-bound cookie (server) or INIT-ACK (client).
    private var peerSupportsStreamReconfiguration = false

    /// RFC 3758 capability negotiated from INIT/INIT-ACK and authenticated in
    /// the server's State Cookie.
    private var peerSupportsPartialReliability = false

    /// Cookie validity window in milliseconds (matches the historical 60s).
    static var cookieMaxAgeMillis: UInt64 { 60_000 }

    // MARK: - Init

    /// Creates the engine. The random handshake material (initiate tag, initial
    /// TSN, cookie secret) is supplied by the adapter from the `RandomSource`
    /// seam so the engine itself stays deterministic and Embedded-clean.
    init(
        localPort: UInt16,
        remotePort: UInt16,
        maxInboundStreams: UInt16,
        maxOutboundStreams: UInt16,
        initiateTag: UInt32,
        initialTSN: UInt32,
        cookieSecretKey: [UInt8],
        cookieCrypto: SCTPCookieCryptoContext
    ) {
        self.localPort = localPort
        self.remotePort = remotePort
        self.localVerificationTag = initiateTag
        self.nextTSN = initialTSN
        self.retransmissionState = RetransmissionState(initialTSN: initialTSN)
        self.reconfigurationState = SCTPReconfigurationState(
            localInitialTSN: initialTSN
        )
        self.cookieSecretKey = cookieSecretKey
        self.cookieCrypto = cookieCrypto
        // RFC 4960 §3.3.2: at least one stream in each direction.
        self.localMaxInboundStreams = max(1, maxInboundStreams)
        self.localMaxOutboundStreams = max(1, maxOutboundStreams)
    }

    // MARK: - Read-only queries

    var hasUnacknowledgedData: Bool {
        !retransmissionState.isEmpty
            || reconfigurationState.hasQueuedUserMessages
    }

    /// User payload bytes retained by send, reassembly, or deferred-reset state.
    var retainedUserDataByteCount: Int {
        let deferred = reconfigurationState.deferredIncomingReset?.heldByteCount ?? 0
        let (receiveBytes, receiveOverflow) = fragmentAssembler.bufferedBytes
            .addingReportingOverflow(deferred)
        let boundedReceiveBytes = receiveOverflow ? Int.max : receiveBytes
        let (sendBytes, sendOverflow) = retransmissionState.retainedPayloadByteCount
            .addingReportingOverflow(reconfigurationState.queuedUserDataByteCount)
        let boundedSendBytes = sendOverflow ? Int.max : sendBytes
        let (total, totalOverflow) = boundedSendBytes
            .addingReportingOverflow(boundedReceiveBytes)
        return totalOverflow ? Int.max : total
    }

    var supportsStreamReconfiguration: Bool {
        peerSupportsStreamReconfiguration
    }

    var supportsPartialReliability: Bool {
        peerSupportsPartialReliability
    }

    /// Conservative SCTP plaintext packet budget used until PMTU discovery is
    /// surfaced by the lower transport. RFC 8261 recommends a safe path MTU no
    /// larger than 1,200 bytes when DF control is unavailable; this bound keeps
    /// every encoded SCTP packet at or below that value.
    static var defaultMaximumPacketByteCount: Int {
        SCTPAssociationLimits.defaultMaximumPacketByteCount
    }

    /// Maximum user-data bytes carried by one DATA chunk under the default
    /// packet budget. Upper layers can use this value to avoid turning every
    /// application frame into two SCTP packets at a boundary mismatch.
    static var defaultMaximumDataPayloadByteCount: Int {
        SCTPAssociationLimits.defaultMaximumDataPayloadByteCount
    }

    /// Smallest packet budget that can carry the common header, one DATA chunk,
    /// one payload byte, and RFC 4960 four-byte padding.
    static var minimumMaximumPacketByteCount: Int {
        SCTPAssociationLimits.minimumMaximumPacketByteCount
    }

    // MARK: - Handshake initiation

    /// Generate an INIT chunk to start the association.
    mutating func generateInit() -> SCTPPacket {
        state = .cookieWait
        let initChunk = SCTPInitChunk(
            initiateTag: localVerificationTag,
            advertisedReceiverWindowCredit: advertisedReceiverWindowCredit,
            numberOfOutboundStreams: localMaxOutboundStreams,
            numberOfInboundStreams: localMaxInboundStreams,
            initialTSN: nextTSN
        )
        var value = initChunk.encodeBytes()
        value.append(contentsOf: Self.initializationExtensionParameters)
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: 0,
            chunks: [SCTPChunk(
                validatedChunkType: SCTPChunkType.initChunk.rawValue,
                value: value
            )]
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
    mutating func processPacket(
        _ packet: SCTPPacket,
        nowMillis: UInt64,
        restartEntropy: SCTPAssociationRestartEntropy? = nil
    ) throws(SCTPError) -> (responses: [SCTPPacket], receivedData: [SCTPReceivedMessage]) {
        let result = try processPacketWithEvents(
            packet,
            nowMillis: nowMillis,
            restartEntropy: restartEntropy
        )
        return (result.responses, result.receivedData)
    }

    /// Process a packet while preserving the ordering between application
    /// messages and stream-reset boundary events.
    mutating func processPacketWithEvents(
        _ packet: SCTPPacket,
        nowMillis: UInt64,
        restartEntropy: SCTPAssociationRestartEntropy? = nil
    ) throws(SCTPError) -> SCTPProcessResult {
        switch try processPacketOutcome(
            packet,
            nowMillis: nowMillis,
            restartEntropy: restartEntropy
        ) {
        case .processed(let result):
            return result
        case .closed(let result):
            return result
        case .terminal(_, let error):
            throw error
        }
    }

    /// Canonical Sans-I/O processing surface for a transport owner.
    ///
    /// Terminal protocol violations carry both their final wire response and
    /// typed failure so the owner can send before closing. The historical
    /// throwing methods remain adapters over this outcome.
    mutating func processPacketOutcome(
        _ packet: SCTPPacket,
        nowMillis: UInt64,
        restartEntropy: SCTPAssociationRestartEntropy? = nil
    ) throws(SCTPError) -> SCTPProcessOutcome {
        if let result = packetPreflightResult(for: packet) {
            return .processed(result)
        }
        try validateVerificationTag(packet)

        // Any valid peer packet proves reachability while SHUTDOWN is in flight.
        // Delay the restart until packet processing finishes so a SHUTDOWN ACK
        // can close cleanly without a fallible, semantically unnecessary timer
        // update. COOKIE ECHO performs its own authenticated restart handling.
        let beginsWithCookieEcho = packet.chunks.first?.chunkType
            == SCTPChunkType.cookieEcho.rawValue
        let shouldRestartShutdownT2 = state == .shutdownSent
            && !beginsWithCookieEcho

        var responses: [SCTPPacket] = []
        var deliveries: [SCTPAssociationDelivery] = []
        var sackRequested = false
        var senderWindowChanged = false

        chunkLoop: for chunk in packet.chunks {
            guard let chunkType = SCTPChunkType(rawValue: chunk.chunkType) else {
                // RFC 9260 §3.2: the upper two bits select stop/continue and
                // whether an Unrecognized Chunk Type ERROR must be returned.
                switch chunk.chunkType >> 6 {
                case 0b00:
                    break chunkLoop
                case 0b01:
                    responses.append(try unrecognizedChunkErrorPacket(for: chunk))
                    break chunkLoop
                case 0b10:
                    continue
                case 0b11:
                    responses.append(try unrecognizedChunkErrorPacket(for: chunk))
                default:
                    // Shifting UInt8 by six bits can only produce 0...3. Keep
                    // the conservative stop action if that invariant changes.
                    break chunkLoop
                }
                continue
            }

            switch chunkType {
            case .initChunk:
                if state == .shutdownAckSent {
                    // RFC 9260 §9.2: an INIT received while waiting for
                    // SHUTDOWN-COMPLETE does not restart the association. The
                    // outstanding SHUTDOWN-ACK is sent again instead.
                    responses.append(shutdownAckPacket())
                    continue
                }
                let initChunk = try decodeInit(chunk.value)
                responses.append(try handleInit(
                    initChunk,
                    rawValue: chunk.value,
                    sourcePort: packet.sourcePort,
                    nowMillis: nowMillis,
                    restartEntropy: restartEntropy
                ))

            case .initAck:
                guard state == .cookieWait else {
                    continue
                }
                let reportableParameters = try handleInitAck(chunk)
                let cookieEcho = try generateCookieEcho()
                responses.append(cookieEcho)
                if let report = try unrecognizedParametersErrorPacket(
                    for: reportableParameters,
                    bundledWith: cookieEcho
                ) {
                    responses.append(report)
                }

            case .cookieEcho:
                switch try handleCookieEcho(
                    chunk,
                    packet: packet,
                    nowMillis: nowMillis
                ) {
                case .proceed(let cookieResponses, let restartEvent):
                    responses.append(contentsOf: cookieResponses)
                    if restartEvent {
                        deliveries.append(.event(.associationRestarted))
                    }
                case .stop(let cookieResponses):
                    responses.append(contentsOf: cookieResponses)
                    return .processed(SCTPProcessResult(
                        responses: try packetizedControlResponses(responses),
                        deliveries: deliveries
                    ))
                }

            case .cookieAck:
                guard state == .cookieEchoed else {
                    continue
                }
                state = .established

            case .data:
                // RFC 4960 §6: DATA received outside a state that can
                // transfer user data is silently discarded. In particular,
                // COOKIE-ECHOED can already have a TSN tracker, but accepting
                // DATA there would expose application bytes before the
                // handshake is complete and mutate receive/SACK state.
                guard canReceiveData else {
                    continue
                }
                let dataChunk = try decodeData(chunk)
                sackRequested = true

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
                    if try holdDataForDeferredResetIfNeeded(dataChunk) {
                        break
                    }
                    let assembled = try processFragment(dataChunk)
                    for message in assembled {
                        deliveries.append(.message(SCTPReceivedMessage(
                            streamID: message.streamID,
                            ppid: message.ppid,
                            data: message.data
                        )))
                    }
                }

            case .sack:
                // RFC 4960 §6: SACK is processed only in the states listed by
                // the receive-state table. Gate before decoding so a malformed
                // SACK in a discard state cannot surface an error or mutate
                // retransmission accounting.
                guard canProcessSack else {
                    continue
                }
                let sackChunk = try decodeSack(chunk.value)
                let sackOutcome = retransmissionState.acknowledge(
                    cumulativeTSN: sackChunk.cumulativeTSNAck,
                    gapBlocks: sackChunk.gapAckBlocks,
                    advertisedReceiverWindowCredit: sackChunk.advertisedReceiverWindowCredit,
                    receivedMillis: nowMillis
                )
                if let terminal = terminalSackOutcome(sackOutcome) {
                    return terminal
                }
                if case .applied = sackOutcome {
                    senderWindowChanged = true
                }
                if let forwardPacket = try forwardTSNPacketIfNeeded(
                    nowMillis: nowMillis,
                    force: true
                ) {
                    responses.append(forwardPacket)
                }

            case .shutdown:
                guard state == .established
                        || state == .shutdownPending
                        || state == .shutdownSent
                        || state == .shutdownReceived
                        || state == .shutdownAckSent else {
                    continue
                }
                if let terminal = try handleShutdown(
                    chunk,
                    receivedMillis: nowMillis
                ) {
                    return terminal
                }
                senderWindowChanged = true

            case .shutdownAck:
                guard state == .shutdownSent || state == .shutdownAckSent else {
                    continue
                }
                responses.append(generateShutdownComplete(reflected: false))
                closeAssociation()
                let outboundResponses = try packetizedControlResponses(responses)
                return .closed(SCTPProcessResult(
                    responses: outboundResponses,
                    deliveries: deliveries
                ))

            case .shutdownComplete:
                if state == .shutdownAckSent {
                    closeAssociation()
                    return .closed(SCTPProcessResult(
                        responses: [],
                        deliveries: deliveries
                    ))
                }

            case .heartbeat:
                responses.append(handleHeartbeat(chunk))

            case .heartbeatAck:
                break

            case .abort:
                // RFC 4960 §9.1: the association is destroyed immediately.
                closeAssociation()
                return .terminal(
                    SCTPProcessResult(responses: [], deliveries: []),
                    .associationAborted
                )

            case .error:
                // Operation Error is advisory (RFC 4960 §3.3.10).
                break

            case .reConfig:
                if try processReconfigurationChunk(
                    chunk,
                    nowMillis: nowMillis,
                    responses: &responses,
                    deliveries: &deliveries
                ) {
                    senderWindowChanged = true
                }

            case .forwardTSN:
                guard canReceiveData else {
                    continue
                }
                guard peerSupportsPartialReliability else {
                    responses.append(try unrecognizedChunkErrorPacket(for: chunk))
                    continue
                }
                let forwardTSN: SCTPForwardTSNChunk
                do {
                    forwardTSN = try SCTPForwardTSNChunk.decode(from: chunk)
                } catch {
                    try error.rethrowUnwrapped()
                }
                for skipped in forwardTSN.skippedStreams {
                    guard skipped.streamIdentifier < negotiatedInboundStreams else {
                        throw .invalidStreamIdentifier(
                            streamID: skipped.streamIdentifier,
                            negotiated: negotiatedInboundStreams
                        )
                    }
                }
                sackRequested = true
                guard var tracker = tsnTracker else {
                    throw .invalidState(
                        "FORWARD-TSN received before TSN tracking was initialized"
                    )
                }
                if tracker.advanceCumulativeTSN(to: forwardTSN.newCumulativeTSN) {
                    tsnTracker = tracker
                    let assembled = fragmentAssembler.forward(
                        cumulativeTSN: tracker.cumulativeTSN,
                        skippedStreams: forwardTSN.skippedStreams
                    )
                    for message in assembled {
                        deliveries.append(.message(SCTPReceivedMessage(
                            streamID: message.streamID,
                            ppid: message.ppid,
                            data: message.data
                        )))
                    }
                }
            }
        }

        if shouldRestartShutdownT2,
           state == .shutdownSent,
           var timer = shutdownTimerState {
            do {
                try timer.restart(at: nowMillis)
            } catch let error {
                let abortPacket = associationAbort()
                closeAssociation()
                return .terminal(
                    SCTPProcessResult(
                        responses: [abortPacket],
                        deliveries: deliveries
                    ),
                    error
                )
            }
            shutdownTimerState = timer
        }

        try completeDeferredResetIfReady(
            responses: &responses,
            deliveries: &deliveries
        )

        // RFC 9260 §9.2: SHUTDOWN-RECEIVED continues accepting SACKs until
        // every locally sent DATA/control owner has reached a terminal ACK.
        // Only then may the association advance to SHUTDOWN-ACK-SENT.
        if state == .shutdownReceived, retransmissionState.isEmpty {
            do {
                responses.append(try enterShutdownAckSent(
                    nowMillis: nowMillis
                ))
            } catch let error {
                let abortPacket = associationAbort()
                closeAssociation()
                return .terminal(
                    SCTPProcessResult(
                        responses: [abortPacket],
                        deliveries: deliveries
                    ),
                    error
                )
            }
        }

        // RFC 4960 §6.2: send at most one SACK per packet, after all DATA chunks.
        if sackRequested {
            guard let sack = try generateSack() else {
                throw SCTPError.invalidState("SACK requested before TSN tracking was initialized")
            }
            responses.append(sack)
            if let tracker = tsnTracker {
                fragmentAssembler.cleanup(currentTSN: tracker.cumulativeTSN)
            }
        }
        if sackRequested, state == .shutdownSent {
            responses.append(try shutdownPacket())
        }

        let controlResponses: [SCTPPacket]
        do {
            controlResponses = try packetizedControlResponses(responses)
        } catch let error {
            let abortPacket = associationAbort()
            closeAssociation()
            return .terminal(
                SCTPProcessResult(
                    responses: [abortPacket],
                    deliveries: []
                ),
                error
            )
        }
        var outboundResponses = controlResponses
        if senderWindowChanged, canTransmitRetainedData {
            switch retransmissionState.outboundChunks(
                nowMillis: nowMillis,
                trigger: .acknowledgment
            ) {
            case .success(let dataChunks):
                if let forwardPacket = try forwardTSNPacketIfNeeded(
                    nowMillis: nowMillis,
                    force: false
                ) {
                    outboundResponses.append(forwardPacket)
                }
                outboundResponses.append(contentsOf: dataChunks.map(packetForDataChunk))
            case .failure(let retransmissionError):
                let abortPacket = associationAbort()
                closeAssociation()
                return .terminal(
                    SCTPProcessResult(
                        responses: [abortPacket],
                        deliveries: deliveries
                    ),
                    Self.sctpError(for: retransmissionError)
                )
            }
        }

        if state == .shutdownPending, !hasUnacknowledgedData {
            do {
                outboundResponses.append(try startShutdown(nowMillis: nowMillis))
            } catch let error {
                let abortPacket = associationAbort()
                closeAssociation()
                return .terminal(
                    SCTPProcessResult(responses: [abortPacket], deliveries: []),
                    error
                )
            }
        }

        return .processed(SCTPProcessResult(
            responses: outboundResponses,
            deliveries: deliveries
        ))
    }

    // MARK: - Sending

    /// Request an RFC 6525 reset of selected outgoing streams.
    ///
    /// Only one request is placed on the wire at a time. A later request is
    /// retained in a bounded queue and starts after the outstanding request
    /// reaches a terminal response. `nil` therefore means "accepted and queued",
    /// not failure.
    mutating func requestOutgoingStreamReset(
        _ selection: SCTPStreamSelection,
        nowMillis: UInt64
    ) throws(SCTPError) -> SCTPPacket? {
        guard state == .established else {
            throw .invalidState("Stream reset requires an established association")
        }
        guard peerSupportsStreamReconfiguration else {
            throw .streamReconfigurationNotNegotiated
        }
        try validateOutgoingResetSelection(selection)

        // Idempotent close requests do not consume queue capacity or allocate a
        // second request sequence number.
        if reconfigurationState.hasResetScheduled(selection) {
            return nil
        }

        guard reconfigurationState.pendingOutgoingReset == nil else {
            try reconfigurationState.enqueue(selection)
            return nil
        }
        return try startOutgoingStreamReset(selection, nowMillis: nowMillis)
    }

    /// Begin an RFC 9260 graceful association shutdown.
    ///
    /// `nil` means outstanding DATA or control work must drain first. The
    /// SHUTDOWN packet is then emitted by SACK processing or
    /// ``pollOutboundPackets(nowMillis:)``.
    mutating func requestShutdown(
        nowMillis: UInt64
    ) throws(SCTPError) -> SCTPPacket? {
        switch state {
        case .established:
            // Association shutdown supersedes local stream-reset work. RFC 9260
            // waits for outstanding DATA, while receive-side reset/deferred DATA
            // state remains active until the association actually closes.
            // Keep this transition transactional. Releasing reset-blocked DATA
            // assigns TSNs/SSNs and can start T3; starting SHUTDOWN starts T2/T5.
            // If either clock calculation fails, the established association
            // must retain the exact reset and DATA ownership it had on entry.
            let originalReconfigurationState = reconfigurationState
            let originalRetransmissionState = retransmissionState
            let originalNextTSN = nextTSN
            let originalNextStreamSeqNumber = nextStreamSeqNumber
            let originalShutdownTimerState = shutdownTimerState
            do {
                reconfigurationState.cancelOutgoingResets()
                _ = try releaseQueuedUserMessages(nowMillis: nowMillis)
                guard retransmissionState.isEmpty else {
                    state = .shutdownPending
                    return nil
                }
                return try startShutdown(nowMillis: nowMillis)
            } catch {
                reconfigurationState = originalReconfigurationState
                retransmissionState = originalRetransmissionState
                nextTSN = originalNextTSN
                nextStreamSeqNumber = originalNextStreamSeqNumber
                shutdownTimerState = originalShutdownTimerState
                state = .established
                throw error
            }
        case .shutdownPending, .shutdownSent, .shutdownReceived, .shutdownAckSent:
            return nil
        case .closed, .cookieWait, .cookieEchoed:
            throw .invalidState("Graceful shutdown requires an established association")
        }
    }

    /// Immediately destroy the local association without generating wire I/O.
    ///
    /// Transport owners use this after their own terminal state is committed or
    /// when synchronous teardown explicitly supersedes graceful shutdown.
    mutating func terminate() {
        closeAssociation()
    }

    /// Send data on a stream through the historical single-packet surface.
    ///
    /// Messages that require fragmentation fail explicitly so the caller can use
    /// ``sendDataPackets(streamID:payloadProtocolIdentifier:data:unordered:nowMillis:maximumPacketByteCount:)``.
    /// Small-message behavior and the return type remain source-compatible.
    mutating func sendData(
        streamID: UInt16,
        payloadProtocolIdentifier: UInt32,
        data: [UInt8],
        unordered: Bool,
        reliability: SCTPMessageReliability = .reliable,
        nowMillis: UInt64
    ) throws(SCTPError) -> SCTPPacket {
        try validateDataSend(streamID: streamID)
        guard !reconfigurationState.hasResetScheduled(for: streamID) else {
            throw .sendRequiresPacketBatchDuringReset(streamID: streamID)
        }
        if case .reliable = reliability {
            // Reliable DATA is valid on every established association.
        } else if !peerSupportsPartialReliability {
            throw .partialReliabilityNotNegotiated
        }
        if case .maximumLifetimeMilliseconds(0) = reliability {
            throw .sendRequiresPacketBatchForExpiredMessage
        }
        let maximumPayload = try Self.maximumPayloadByteCount(
            maximumPacketByteCount: Self.defaultMaximumPacketByteCount
        )
        guard data.count <= maximumPayload else {
            throw .messageRequiresPacketBatch(
                payloadByteCount: data.count,
                maximumSinglePacketPayloadByteCount: maximumPayload
            )
        }
        guard retransmissionState.canImmediatelyTransmitNewDataChunk(
            byteCount: data.count
        ) else {
            let available = min(
                retransmissionState.availableNewDataByteCount,
                UInt64(Int.max)
            )
            throw .sendWindowUnavailable(
                requiredByteCount: data.count,
                availableByteCount: Int(available)
            )
        }
        // The canonical batch path may discover an expired earlier message and
        // generate FORWARD-TSN beside this DATA. Preserve the historical API's
        // one-packet contract transactionally instead of committing hidden
        // protocol output and then returning a generic state failure.
        let snapshot = self
        let packets = try sendDataPackets(
            streamID: streamID,
            payloadProtocolIdentifier: payloadProtocolIdentifier,
            data: data,
            unordered: unordered,
            reliability: reliability,
            nowMillis: nowMillis,
            maximumPacketByteCount: Self.defaultMaximumPacketByteCount
        )
        guard let packet = packets.first, packets.count == 1 else {
            self = snapshot
            throw .sendRequiresPacketBatchForProtocolProgress(
                packetCount: packets.count
            )
        }
        return packet
    }

    /// Fragment and atomically admit one SCTP user message.
    ///
    /// Every fragment shares the original immutable Array storage through an
    /// owner/range view. All chunks and packets are generated and checked before
    /// retransmission, TSN, or SSN state is changed. Ordered messages advance the
    /// SSN exactly once; all fragments carry that same SSN and consecutive TSNs.
    mutating func sendDataPackets(
        streamID: UInt16,
        payloadProtocolIdentifier: UInt32,
        data: [UInt8],
        unordered: Bool,
        reliability: SCTPMessageReliability = .reliable,
        nowMillis: UInt64,
        maximumPacketByteCount: Int = 1_200
    ) throws(SCTPError) -> [SCTPPacket] {
        try validateDataSend(streamID: streamID)
        if case .reliable = reliability {
            // Reliable DATA is valid on every established SCTP association.
        } else if !peerSupportsPartialReliability {
            throw .partialReliabilityNotNegotiated
        }
        let maximumPayload = try Self.maximumPayloadByteCount(
            maximumPacketByteCount: maximumPacketByteCount
        )
        let fragmentCount = data.isEmpty
            ? 1
            : ((data.count - 1) / maximumPayload) + 1
        guard UInt64(fragmentCount) <= UInt64(UInt32.max) else {
            throw .invalidFormat("SCTP user message requires more than UInt32.max fragments")
        }
        let assignedReliability = try SCTPAssignedMessageReliability.resolve(
            reliability,
            acceptedAtMillis: nowMillis
        )

        // RFC 3758 TR3 evaluates timed reliability before assigning a TSN.
        // A zero-lifetime message expires at admission and therefore consumes
        // neither sequence space nor retransmission ownership.
        if assignedReliability.isExpired(at: nowMillis) {
            return []
        }

        let (reservedByteCount, byteOverflow) = reconfigurationState
            .queuedUserDataByteCount.addingReportingOverflow(data.count)
        let (reservedChunkCount, chunkOverflow) = reconfigurationState
            .queuedUserChunkCount.addingReportingOverflow(fragmentCount)
        guard !byteOverflow, !chunkOverflow else {
            throw .sendQueueFull(
                bytesInFlight: reconfigurationState.queuedUserDataByteCount,
                limit: Int.max
            )
        }
        // Reserve retransmission capacity for every reset-blocked owner. This
        // makes later release infallible with respect to byte/chunk ceilings and
        // prevents unrelated streams from consuming the promised capacity.
        do {
            try retransmissionState.validateAdditionalByteCount(
                reservedByteCount,
                additionalChunkCount: reservedChunkCount
            )
        } catch {
            throw error.asSCTPError
        }

        if reconfigurationState.hasResetScheduled(for: streamID) {
            try reconfigurationState.enqueueUserMessage(.init(
                streamID: streamID,
                payloadProtocolIdentifier: payloadProtocolIdentifier,
                data: data,
                unordered: unordered,
                reliability: assignedReliability,
                maximumPacketByteCount: maximumPacketByteCount,
                fragmentCount: fragmentCount
            ))
            return []
        }

        let firstTSN = nextTSN
        let seqNum = nextStreamSeqNumber[streamID, default: 0]
        let chunks = try makeDataChunks(
            streamID: streamID,
            payloadProtocolIdentifier: payloadProtocolIdentifier,
            data: data,
            unordered: unordered,
            maximumPacketByteCount: maximumPacketByteCount,
            maximumPayloadByteCount: maximumPayload,
            fragmentCount: fragmentCount,
            firstTSN: firstTSN,
            streamSequenceNumber: seqNum
        )

        // The batch enqueue performs a complete capacity preflight before its
        // first mutation. Only a successful admission commits sequence state.
        do {
            try retransmissionState.admit(
                contentsOf: chunks,
                at: nowMillis,
                reliability: assignedReliability
            )
        } catch {
            throw error.asSCTPError
        }

        nextTSN = firstTSN &+ UInt32(fragmentCount)
        if !unordered {
            nextStreamSeqNumber[streamID] = seqNum &+ 1
        }

        let outboundChunks: [SCTPDataChunk]
        switch retransmissionState.outboundChunks(
            nowMillis: nowMillis,
            trigger: .application
        ) {
        case .success(let selected):
            outboundChunks = selected
        case .failure(let retransmissionError):
            let error = Self.sctpError(for: retransmissionError)
            closeAssociation()
            throw error
        }
        var packets: [SCTPPacket] = []
        do {
            if let forwardPacket = try forwardTSNPacketIfNeeded(
                nowMillis: nowMillis,
                force: false
            ) {
                packets.append(forwardPacket)
            }
        } catch let error {
            closeAssociation()
            throw error
        }
        packets.append(contentsOf: outboundChunks.map(packetForDataChunk))
        return packets
    }

    private func makeDataChunks(
        streamID: UInt16,
        payloadProtocolIdentifier: UInt32,
        data: [UInt8],
        unordered: Bool,
        maximumPacketByteCount: Int,
        maximumPayloadByteCount: Int,
        fragmentCount: Int,
        firstTSN: UInt32,
        streamSequenceNumber: UInt16
    ) throws(SCTPError) -> [SCTPDataChunk] {
        var chunks: [SCTPDataChunk] = []
        chunks.reserveCapacity(fragmentCount)
        var lowerBound = 0
        for fragmentIndex in 0..<fragmentCount {
            let fragmentByteCount = data.isEmpty
                ? 0
                : min(maximumPayloadByteCount, data.count - lowerBound)
            let upperBound = data.isEmpty
                ? 0
                : lowerBound + fragmentByteCount
            let dataChunk = SCTPDataChunk(
                tsn: firstTSN &+ UInt32(fragmentIndex),
                streamIdentifier: streamID,
                streamSequenceNumber: streamSequenceNumber,
                payloadProtocolIdentifier: payloadProtocolIdentifier,
                userDataOwner: data,
                userDataRange: lowerBound..<upperBound,
                beginningFragment: fragmentIndex == 0,
                endingFragment: fragmentIndex == fragmentCount - 1,
                unordered: unordered
            )
            let packet = packetForDataChunk(dataChunk)
            guard packet.encodedByteCount <= maximumPacketByteCount else {
                throw .packetSizeExceeded(
                    actual: packet.encodedByteCount,
                    limit: maximumPacketByteCount
                )
            }
            chunks.append(dataChunk)
            lowerBound = upperBound
        }
        return chunks
    }

    /// Move every user message whose stream is no longer reset-blocked into the
    /// retransmission queue. TSN and ordered SSN assignment happens here, after
    /// the final reset result, so a successful reset starts at SSN zero while a
    /// denied reset continues the pre-request sequence.
    private mutating func releaseQueuedUserMessages(
        nowMillis: UInt64
    ) throws(SCTPError) -> Bool {
        var releasedAny = false
        while let index = reconfigurationState.firstSendableUserMessageIndex() {
            let message = reconfigurationState.queuedUserMessages[index]
            if message.reliability.isExpired(at: nowMillis) {
                reconfigurationState.removeUserMessage(at: index)
                continue
            }
            let maximumPayload = try Self.maximumPayloadByteCount(
                maximumPacketByteCount: message.maximumPacketByteCount
            )
            let firstTSN = nextTSN
            let sequenceNumber = nextStreamSeqNumber[message.streamID, default: 0]
            let chunks = try makeDataChunks(
                streamID: message.streamID,
                payloadProtocolIdentifier: message.payloadProtocolIdentifier,
                data: message.data,
                unordered: message.unordered,
                maximumPacketByteCount: message.maximumPacketByteCount,
                maximumPayloadByteCount: maximumPayload,
                fragmentCount: message.fragmentCount,
                firstTSN: firstTSN,
                streamSequenceNumber: sequenceNumber
            )
            do {
                try retransmissionState.admit(
                    contentsOf: chunks,
                    at: nowMillis,
                    reliability: message.reliability
                )
            } catch {
                throw error.asSCTPError
            }

            nextTSN = firstTSN &+ UInt32(message.fragmentCount)
            if !message.unordered {
                nextStreamSeqNumber[message.streamID] = sequenceNumber &+ 1
            }
            reconfigurationState.removeUserMessage(at: index)
            releasedAny = true
        }
        return releasedAny
    }

    private func packetForDataChunk(_ dataChunk: SCTPDataChunk) -> SCTPPacket {
        SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [SCTPChunk(validatedDataChunk: dataChunk)]
        )
    }

    private mutating func forwardTSNPacketIfNeeded(
        nowMillis: UInt64,
        force: Bool
    ) throws(SCTPError) -> SCTPPacket? {
        guard peerSupportsPartialReliability else { return nil }
        let forwardTSN: SCTPForwardTSNChunk?
        switch retransmissionState.pendingForwardTSN(
            nowMillis: nowMillis,
            force: force,
            maximumPacketByteCount: Self.defaultMaximumPacketByteCount
        ) {
        case .success(let chunk):
            forwardTSN = chunk
        case .failure(let error):
            throw Self.sctpError(for: error)
        }
        guard let forwardTSN else { return nil }
        let chunk: SCTPChunk
        do {
            chunk = try forwardTSN.toChunk()
        } catch {
            try error.rethrowUnwrapped()
        }
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [chunk]
        )
    }

    private func validateDataSend(streamID: UInt16) throws(SCTPError) {
        guard state == .established else {
            throw .invalidState("DATA send requires an established association")
        }
        guard streamID < negotiatedOutboundStreams else {
            throw .invalidStreamIdentifier(
                streamID: streamID,
                negotiated: negotiatedOutboundStreams
            )
        }
    }

    private var canReceiveData: Bool {
        switch state {
        case .established, .shutdownPending, .shutdownSent:
            true
        case .closed, .cookieWait, .cookieEchoed, .shutdownReceived, .shutdownAckSent:
            false
        }
    }

    /// RFC 4960 §6 receive-state table for SACK processing.
    ///
    /// COOKIE-ECHOED is the table's optional case; processing it avoids an
    /// unnecessary retransmission when a peer's COOKIE-ACK crosses its SACK.
    private var canProcessSack: Bool {
        switch state {
        case .cookieEchoed, .established, .shutdownPending, .shutdownReceived:
            true
        case .closed, .cookieWait, .shutdownSent, .shutdownAckSent:
            false
        }
    }

    private var canTransmitRetainedData: Bool {
        switch state {
        case .established, .shutdownPending, .shutdownReceived:
            true
        case .closed, .cookieWait, .cookieEchoed, .shutdownSent, .shutdownAckSent:
            false
        }
    }

    private static func maximumPayloadByteCount(
        maximumPacketByteCount: Int
    ) throws(SCTPError) -> Int {
        guard maximumPacketByteCount >= minimumMaximumPacketByteCount else {
            throw .invalidMaximumPacketByteCount(
                actual: maximumPacketByteCount,
                minimum: minimumMaximumPacketByteCount
            )
        }

        let chunkBudget = maximumPacketByteCount - 12
        let alignedChunkBudget = chunkBudget - (chunkBudget % 4)
        let uint16PayloadLimit = Int(UInt16.max) - 16
        let maximumPayload = min(
            alignedChunkBudget - 16,
            uint16PayloadLimit
        )
        guard maximumPayload > 0 else {
            throw .invalidMaximumPacketByteCount(
                actual: maximumPacketByteCount,
                minimum: minimumMaximumPacketByteCount
            )
        }
        return maximumPayload
    }

    /// Poll every packet that protocol state currently permits the caller to emit.
    ///
    /// - Parameter nowMillis: the current time on the caller's monotonic clock.
    /// - Returns: an ordered batch containing eligible DATA retransmissions,
    ///   newly window-admitted DATA, zero-window probes, and timed control
    ///   retransmissions. A retransmission limit failure closes the association.
    mutating func pollOutboundPacketsOutcome(
        nowMillis: UInt64
    ) -> SCTPOutboundPollOutcome {
        guard state != .closed else {
            retransmissionState.removeAll()
            return .packets([])
        }

        if let timer = shutdownTimerState,
           timer.isT5Expired(at: nowMillis) {
            return terminalOutboundPoll(.shutdownGuardTimeout)
        }
        var packets: [SCTPPacket] = []
        let outboundDataChunks: [SCTPDataChunk]
        switch retransmissionState.outboundChunks(
            nowMillis: nowMillis,
            trigger: .timer
        ) {
        case .success(let chunks):
            outboundDataChunks = chunks
        case .failure(let retransmissionError):
            // RFC 4960 §8.2: exceeding the per-DATA retransmit limit destroys the
            // association.
            let error = Self.sctpError(for: retransmissionError)
            return terminalOutboundPoll(error)
        }
        do {
            if let forwardPacket = try forwardTSNPacketIfNeeded(
                nowMillis: nowMillis,
                force: false
            ) {
                packets.append(forwardPacket)
            }
        } catch let error {
            return terminalOutboundPoll(error)
        }
        packets.reserveCapacity(packets.count + outboundDataChunks.count + 1)
        packets.append(contentsOf: outboundDataChunks.map(packetForDataChunk))

        if state == .established,
           var pending = reconfigurationState.pendingOutgoingReset,
           !pending.implicitlyAcknowledged {
            let elapsed = nowMillis >= pending.lastSentMillis
                ? nowMillis - pending.lastSentMillis
                : 0
            if elapsed >= pending.rtoMillis {
                if !pending.peerReportedInProgress {
                    guard pending.retransmitCount < SCTPReconfigurationState.maximumRetransmitCount else {
                        let error = SCTPError.reconfigurationTimeout(
                            requestSequenceNumber: pending.request.requestSequenceNumber
                        )
                        return terminalOutboundPoll(error)
                    }
                    pending.retransmitCount += 1
                }
                pending.lastSentMillis = nowMillis
                pending.rtoMillis = min(
                    pending.rtoMillis &* 2,
                    SCTPReconfigurationState.maximumRTOMillis
                )
                reconfigurationState.pendingOutgoingReset = pending
                packets.append(pending.packet)
            }
        }

        if state == .shutdownPending, !hasUnacknowledgedData {
            do {
                packets.append(try startShutdown(nowMillis: nowMillis))
            } catch let error {
                return terminalOutboundPoll(error)
            }
        }

        if var timer = shutdownTimerState,
           timer.isT2Expired(at: nowMillis) {
            guard timer.retransmitCount < SCTPShutdownTimerState.maximumRetransmitCount else {
                return terminalOutboundPoll(.shutdownTimeout)
            }
            do {
                try timer.backoff(at: nowMillis)
            } catch let error {
                return terminalOutboundPoll(error)
            }
            shutdownTimerState = timer
            switch timer.controlFlight {
            case .shutdown:
                do {
                    packets.append(try shutdownPacket())
                } catch let error {
                    return terminalOutboundPoll(error)
                }
            case .shutdownAck:
                packets.append(shutdownAckPacket())
            }
        }
        return .packets(packets)
    }

    /// Compatibility projection for callers that cannot emit a terminal wire
    /// packet beside its typed failure. Transport owners should use
    /// ``pollOutboundPacketsOutcome(nowMillis:)``.
    mutating func pollOutboundPackets(
        nowMillis: UInt64
    ) -> Result<[SCTPPacket], SCTPError> {
        switch pollOutboundPacketsOutcome(nowMillis: nowMillis) {
        case .packets(let packets):
            return .success(packets)
        case .terminal(_, let error):
            return .failure(error)
        }
    }

    /// Compatibility spelling retained for callers that only expected DATA
    /// retransmissions. The result may also contain newly admitted DATA,
    /// zero-window probes, and timed control packets.
    @available(*, deprecated, renamed: "pollOutboundPackets(nowMillis:)")
    mutating func getPendingRetransmissions(
        nowMillis: UInt64
    ) -> Result<[SCTPPacket], SCTPError> {
        pollOutboundPackets(nowMillis: nowMillis)
    }

    private mutating func terminalOutboundPoll(
        _ error: SCTPError
    ) -> SCTPOutboundPollOutcome {
        let abortPacket = associationAbort()
        closeAssociation()
        return .terminal(packets: [abortPacket], error: error)
    }

    // MARK: - Verification tag (RFC 4960 §8.5)

    /// Validate packet-wide chunk constraints and apply RFC 9260 §8.4 OOTB
    /// precedence before verification-tag checks or any association mutation.
    private func packetPreflightResult(
        for packet: SCTPPacket
    ) -> SCTPProcessResult? {
        let containsAbort = packet.chunks.contains(where: {
            $0.chunkType == SCTPChunkType.abort.rawValue
        })
        let containsShutdownAck = packet.chunks.contains(where: {
            $0.chunkType == SCTPChunkType.shutdownAck.rawValue
        })
        let containsShutdownComplete = packet.chunks.contains(where: {
            $0.chunkType == SCTPChunkType.shutdownComplete.rawValue
        })
        let isOutOfTheBlue = state == .closed
            || ((state == .cookieWait || state == .cookieEchoed) && containsShutdownAck)

        // An OOTB ABORT has packet-wide priority over every other chunk,
        // including otherwise-processable INIT and COOKIE-ECHO chunks.
        if isOutOfTheBlue, containsAbort {
            return SCTPProcessResult(responses: [], deliveries: [])
        }

        // INIT and INIT-ACK are packet-exclusive. A tag-zero packet carrying
        // INIT plus any other chunk is explicitly a silent discard (§8.5.1).
        let containsInit = packet.chunks.contains(where: {
            $0.chunkType == SCTPChunkType.initChunk.rawValue
        })
        let containsInitAck = packet.chunks.contains(where: {
            $0.chunkType == SCTPChunkType.initAck.rawValue
        })
        if (containsInit || containsInitAck), packet.chunks.count != 1 {
            return SCTPProcessResult(responses: [], deliveries: [])
        }
        if containsShutdownComplete, packet.chunks.count != 1 {
            return SCTPProcessResult(responses: [], deliveries: [])
        }

        guard isOutOfTheBlue else {
            if let cookieEchoIndex = packet.chunks.firstIndex(where: {
                $0.chunkType == SCTPChunkType.cookieEcho.rawValue
            }), cookieEchoIndex != 0 {
                return SCTPProcessResult(responses: [], deliveries: [])
            }
            return nil
        }

        if containsInit, packet.verificationTag == 0 {
            return nil
        }
        if packet.chunks.first?.chunkType == SCTPChunkType.cookieEcho.rawValue {
            return nil
        }
        if containsShutdownAck {
            return SCTPProcessResult(
                responses: [reflectedShutdownComplete(for: packet)],
                deliveries: []
            )
        }
        if containsShutdownComplete {
            return SCTPProcessResult(responses: [], deliveries: [])
        }
        if packet.chunks.contains(where: {
            $0.chunkType == SCTPChunkType.cookieAck.rawValue
        }) || packet.chunks.contains(where: Self.isStaleCookieError) {
            return SCTPProcessResult(responses: [], deliveries: [])
        }

        return SCTPProcessResult(
            responses: [reflectedAbort(for: packet)],
            deliveries: []
        )
    }

    private static func isStaleCookieError(_ chunk: SCTPChunk) -> Bool {
        guard chunk.chunkType == SCTPChunkType.error.rawValue else {
            return false
        }
        let value = chunk.value
        var offset = 0
        while offset + 4 <= value.count {
            let code = UInt16(value[offset]) << 8 | UInt16(value[offset + 1])
            let length = Int(UInt16(value[offset + 2]) << 8 | UInt16(value[offset + 3]))
            guard length >= 4, length <= value.count - offset else {
                return false
            }
            if code == 3 {
                return true
            }
            let paddedLength = (length + 3) & ~3
            guard paddedLength >= 4, paddedLength <= value.count - offset else {
                return false
            }
            offset += paddedLength
        }
        return false
    }

    private static func sctpError(
        for retransmissionError: RetransmissionError
    ) -> SCTPError {
        switch retransmissionError {
        case .maxRetransmitsExceeded:
            return .maxRetransmitsExceeded
        case .accountingInvariantViolation:
            return .associationFailed(
                "SCTP retransmission accounting invariant was violated"
            )
        }
    }

    private func reflectedAbort(for packet: SCTPPacket) -> SCTPPacket {
        SCTPPacket(
            sourcePort: localPort,
            destinationPort: packet.sourcePort,
            verificationTag: packet.verificationTag,
            chunks: [SCTPChunk(
                validatedChunkType: SCTPChunkType.abort.rawValue,
                flags: 0x01,
                value: []
            )]
        )
    }

    private func reflectedShutdownComplete(for packet: SCTPPacket) -> SCTPPacket {
        SCTPPacket(
            sourcePort: localPort,
            destinationPort: packet.sourcePort,
            verificationTag: packet.verificationTag,
            chunks: [SCTPChunk(
                validatedChunkType: SCTPChunkType.shutdownComplete.rawValue,
                flags: 0x01,
                value: []
            )]
        )
    }

    private func associationAbort() -> SCTPPacket {
        SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [SCTPChunk(
                validatedChunkType: SCTPChunkType.abort.rawValue,
                value: []
            )]
        )
    }

    private func unrecognizedChunkErrorPacket(
        for chunk: SCTPChunk
    ) throws(SCTPError) -> SCTPPacket {
        let errorChunk: SCTPChunk
        do {
            errorChunk = try SCTPUnrecognizedChunkErrorCause(
                unrecognizedChunk: chunk
            ).toChunk()
        } catch {
            try error.rethrowUnwrapped()
        }
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [errorChunk]
        )
    }

    /// Build an RFC 9260 cause-8 report that remains bundled after COOKIE ECHO.
    ///
    /// Cause 8 is a SHOULD-level report for INIT-ACK. Parameters that cannot fit
    /// beside the COOKIE-ECHO under the current conservative path budget are
    /// omitted rather than emitting a prohibited pre-COOKIE-ACK standalone
    /// ERROR packet.
    private func unrecognizedParametersErrorPacket(
        for parameters: [[UInt8]],
        bundledWith cookieEcho: SCTPPacket
    ) throws(SCTPError) -> SCTPPacket? {
        guard !parameters.isEmpty else { return nil }

        var selected: [[UInt8]] = []
        var causeLength = 4
        for parameter in parameters {
            var candidateCauseLength = causeLength
            if let previous = selected.last {
                candidateCauseLength += ((previous.count + 3) & ~3)
                    - previous.count
            }
            let (nextCauseLength, causeOverflow) = candidateCauseLength
                .addingReportingOverflow(parameter.count)
            guard !causeOverflow,
                  nextCauseLength <= Int(UInt16.max) - 4 else {
                continue
            }
            let errorChunkLength = 4 + nextCauseLength
            let errorChunkEncodedByteCount = (errorChunkLength + 3) & ~3
            let (bundledByteCount, packetOverflow) = cookieEcho.encodedByteCount
                .addingReportingOverflow(errorChunkEncodedByteCount)
            guard !packetOverflow,
                  bundledByteCount <= Self.defaultMaximumPacketByteCount else {
                continue
            }
            selected.append(parameter)
            causeLength = nextCauseLength
        }
        guard !selected.isEmpty else { return nil }

        let errorChunk: SCTPChunk
        do {
            errorChunk = try SCTPUnrecognizedParametersErrorCause(
                unrecognizedParameters: selected
            ).toChunk()
        } catch {
            try error.rethrowUnwrapped()
        }
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [errorChunk]
        )
    }

    private func cookieReceivedWhileShuttingDownErrorPacket() -> SCTPPacket {
        SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [SCTPCookieReceivedWhileShuttingDownErrorCause().toChunk()]
        )
    }

    private mutating func terminalSackOutcome(
        _ outcome: SCTPSackOutcome
    ) -> SCTPProcessOutcome? {
        guard case .protocolViolation(let violation) = outcome else {
            return nil
        }
        let abortPacket = associationAbort()
        closeAssociation()
        return .terminal(
            SCTPProcessResult(
                responses: [abortPacket],
                deliveries: []
            ),
            .sackProtocolViolation(violation)
        )
    }

    private mutating func handleShutdown(
        _ chunk: SCTPChunk,
        receivedMillis: UInt64
    ) throws(SCTPError) -> SCTPProcessOutcome? {
        let value = chunk.value
        guard value.count == 4 else {
            throw .invalidFormat("SHUTDOWN must contain one cumulative TSN acknowledgment")
        }
        let cumulativeTSN = UInt32(value[0]) << 24
            | UInt32(value[1]) << 16
            | UInt32(value[2]) << 8
            | UInt32(value[3])
        let outcome = retransmissionState.acknowledgeShutdown(
            cumulativeTSN: cumulativeTSN,
            receivedMillis: receivedMillis
        )
        if let terminal = terminalSackOutcome(outcome) {
            return terminal
        }
        state = .shutdownReceived
        return nil
    }

    /// Destroy the transmission control block and release every retained owner.
    private mutating func closeAssociation() {
        state = .closed
        receivedCookie = nil
        remoteVerificationTag = 0
        peerInitialTSN = 0
        peerARWC = 0
        peerSupportsStreamReconfiguration = false
        peerSupportsPartialReliability = false
        tsnTracker = nil
        fragmentAssembler.removeAll()
        retransmissionState.removeAll()
        reconfigurationState.removeAllRetainedState()
        shutdownTimerState = nil
        nextStreamSeqNumber.removeAll(keepingCapacity: false)
    }

    /// Packetize control responses without dropping protocol work.
    ///
    /// Adjacent chunks with identical packet headers are coalesced up to the
    /// conservative path budget. Overflow starts another packet in input order.
    /// RFC 9260 packet-exclusive chunks are always emitted alone.
    private func packetizedControlResponses(
        _ responses: [SCTPPacket]
    ) throws(SCTPError) -> [SCTPPacket] {
        var packets: [SCTPPacket] = []
        var pendingChunks: [SCTPChunk] = []
        var pendingSourcePort: UInt16 = 0
        var pendingDestinationPort: UInt16 = 0
        var pendingVerificationTag: UInt32 = 0
        var pendingEncodedByteCount = 12

        func packet(
            sourcePort: UInt16,
            destinationPort: UInt16,
            verificationTag: UInt32,
            chunks: [SCTPChunk]
        ) -> SCTPPacket {
            SCTPPacket(
                sourcePort: sourcePort,
                destinationPort: destinationPort,
                verificationTag: verificationTag,
                chunks: chunks
            )
        }

        func hasMatchingHeader(_ response: SCTPPacket) -> Bool {
            pendingChunks.isEmpty
                || (pendingSourcePort == response.sourcePort
                    && pendingDestinationPort == response.destinationPort
                    && pendingVerificationTag == response.verificationTag)
        }

        func flushPending() {
            guard !pendingChunks.isEmpty else { return }
            packets.append(packet(
                sourcePort: pendingSourcePort,
                destinationPort: pendingDestinationPort,
                verificationTag: pendingVerificationTag,
                chunks: pendingChunks
            ))
            pendingChunks = []
            pendingEncodedByteCount = 12
        }

        for response in responses {
            guard !response.chunks.isEmpty else {
                throw .invalidState("Generated SCTP control response contained no chunks")
            }
            if !hasMatchingHeader(response) {
                flushPending()
            }
            if pendingChunks.isEmpty {
                pendingSourcePort = response.sourcePort
                pendingDestinationPort = response.destinationPort
                pendingVerificationTag = response.verificationTag
            }

            for chunk in response.chunks {
                let (standaloneByteCount, standaloneOverflow) = 12.addingReportingOverflow(
                    chunk.encodedByteCount
                )
                guard !standaloneOverflow,
                      standaloneByteCount <= Self.defaultMaximumPacketByteCount else {
                    throw .packetSizeExceeded(
                        actual: standaloneOverflow ? Int.max : standaloneByteCount,
                        limit: Self.defaultMaximumPacketByteCount
                    )
                }

                if Self.isPacketExclusiveControlChunk(chunk) {
                    flushPending()
                    packets.append(packet(
                        sourcePort: response.sourcePort,
                        destinationPort: response.destinationPort,
                        verificationTag: response.verificationTag,
                        chunks: [chunk]
                    ))
                    continue
                }

                let (nextByteCount, overflow) = pendingEncodedByteCount
                    .addingReportingOverflow(chunk.encodedByteCount)
                if overflow || nextByteCount > Self.defaultMaximumPacketByteCount {
                    flushPending()
                    pendingSourcePort = response.sourcePort
                    pendingDestinationPort = response.destinationPort
                    pendingVerificationTag = response.verificationTag
                }
                pendingChunks.append(chunk)
                pendingEncodedByteCount += chunk.encodedByteCount
            }
        }

        flushPending()
        return packets
    }

    private static func isPacketExclusiveControlChunk(_ chunk: SCTPChunk) -> Bool {
        chunk.chunkType == SCTPChunkType.initChunk.rawValue
            || chunk.chunkType == SCTPChunkType.initAck.rawValue
            || chunk.chunkType == SCTPChunkType.shutdownComplete.rawValue
    }

    private func validateVerificationTag(_ packet: SCTPPacket) throws(SCTPError) {
        // RFC 4960 §8.5.1 (A): packets carrying INIT must use tag 0.
        let containsInit = packet.chunks.contains { $0.chunkType == SCTPChunkType.initChunk.rawValue }
        if containsInit {
            guard packet.verificationTag == 0 else {
                throw SCTPError.verificationTagMismatch(expected: 0, actual: packet.verificationTag)
            }
            return
        }

        // RFC 9260 §8.5.1(D): COOKIE-ECHO verification uses the Initiate Tag
        // authenticated inside the opaque cookie. Action A and C deliberately
        // carry a tag that differs from the live TCB, so generic TCB validation
        // must not run before cookie authentication and Table 12 classification.
        if packet.chunks.first?.chunkType == SCTPChunkType.cookieEcho.rawValue {
            return
        }

        if state == .shutdownAckSent,
           packet.chunks.count == 1,
           let shutdownComplete = packet.chunks.first,
           shutdownComplete.chunkType == SCTPChunkType.shutdownComplete.rawValue,
           shutdownComplete.flags & 0x01 != 0,
           packet.verificationTag == remoteVerificationTag {
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
        rawValue: [UInt8],
        sourcePort: UInt16,
        nowMillis: UInt64,
        restartEntropy: SCTPAssociationRestartEntropy?
    ) throws(SCTPError) -> SCTPPacket {
        // RFC 4960 §5.2.1/§5.2.2: an INIT received while the association is not
        // CLOSED must NOT tear down or mutate the live association. We reply with
        // an INIT-ACK carrying a fresh cookie that encodes the peer's *new*
        // parameters, but defer committing them until a valid COOKIE-ECHO arrives.
        // Negotiate stream counts (RFC 4960 §5.1.1).
        let negotiatedOutbound = min(localMaxOutboundStreams, initChunk.numberOfInboundStreams)
        let negotiatedInbound = min(localMaxInboundStreams, initChunk.numberOfOutboundStreams)
        let initParameters = try initializationParameters(in: rawValue)
        let peerSupportsReconfiguration =
            initParameters.supportsStreamReconfiguration
        let peerSupportsPartialReliability =
            initParameters.supportsPartialReliability

        let responseTag: UInt32
        let responseInitialTSN: UInt32
        let localTieTag: UInt32
        let peerTieTag: UInt32
        switch state {
        case .closed, .cookieWait:
            responseTag = localVerificationTag
            responseInitialTSN = nextTSN
            localTieTag = 0
            peerTieTag = 0
        case .cookieEchoed:
            responseTag = localVerificationTag
            responseInitialTSN = nextTSN
            localTieTag = localVerificationTag
            peerTieTag = remoteVerificationTag
        case .established, .shutdownPending, .shutdownSent, .shutdownReceived:
            guard let restartEntropy else {
                throw .restartEntropyUnavailable
            }
            guard restartEntropy.initiateTag != 0,
                  restartEntropy.initiateTag != localVerificationTag else {
                throw .restartInitiateTagCollision
            }
            responseTag = restartEntropy.initiateTag
            responseInitialTSN = restartEntropy.initialTSN
            localTieTag = localVerificationTag
            peerTieTag = remoteVerificationTag
        case .shutdownAckSent:
            throw .invalidState(
                "SHUTDOWN-ACK-SENT must retransmit SHUTDOWN-ACK for an INIT"
            )
        }

        // Generate the secure cookie encoding the peer's parameters from THIS
        // INIT. The cookie — not live state — is the source of truth that
        // handleCookieEcho commits.
        let cookie = SCTPCookieCore.generate(
            secretKey: cookieSecretKey,
            timestamp: nowMillis,
            peerTag: initChunk.initiateTag,
            localTag: responseTag,
            localTieTag: localTieTag,
            peerTieTag: peerTieTag,
            localInitialTSN: responseInitialTSN,
            peerInitialTSN: initChunk.initialTSN,
            peerARWC: initChunk.advertisedReceiverWindowCredit,
            outboundStreams: negotiatedOutbound,
            inboundStreams: negotiatedInbound,
            extensionFlags:
                (peerSupportsReconfiguration
                    ? Self.streamReconfigurationCookieFlag
                    : 0)
                | (peerSupportsPartialReliability
                    ? Self.partialReliabilityCookieFlag
                    : 0),
            localPort: localPort,
            peerPort: sourcePort,
            crypto: cookieCrypto
        )

        // Build INIT-ACK with cookie, advertising our local stream maxima.
        let initAck = SCTPInitChunk(
            initiateTag: responseTag,
            advertisedReceiverWindowCredit: advertisedReceiverWindowCredit,
            numberOfOutboundStreams: localMaxOutboundStreams,
            numberOfInboundStreams: localMaxInboundStreams,
            initialTSN: responseInitialTSN
        )

        var initAckValue = initAck.encodeBytes()
        initAckValue.append(contentsOf: encodeCookieParameter(cookie.encode()))
        let maximumInitAckValueByteCount = min(
            Int(UInt16.max) - 4,
            Self.defaultMaximumPacketByteCount - 16
        )
        for parameter in initParameters.reportableParameters {
            let report: [UInt8]
            do {
                report = try SCTPUnrecognizedParameter(
                    unrecognizedParameter: parameter
                ).encodeParameterBytes()
            } catch {
                try error.rethrowUnwrapped()
            }
            let reservedTailByteCount =
                Self.initializationExtensionParameters.count
            guard initAckValue.count
                    <= maximumInitAckValueByteCount - reservedTailByteCount,
                  report.count <= maximumInitAckValueByteCount
                    - reservedTailByteCount - initAckValue.count else {
                // RFC 9260 permits omitting reports that would make INIT-ACK
                // excessively large. Keep the mandatory cookie and local
                // capability advertisement within the active path budget.
                continue
            }
            initAckValue.append(contentsOf: report)
        }
        initAckValue.append(contentsOf: Self.initializationExtensionParameters)

        let ackChunk: SCTPChunk
        do {
            ackChunk = try SCTPChunk(
                chunkType: SCTPChunkType.initAck.rawValue,
                value: initAckValue
            )
        } catch {
            try error.rethrowUnwrapped()
        }
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: sourcePort,
            verificationTag: initChunk.initiateTag,
            chunks: [ackChunk]
        )
    }

    private mutating func handleInitAck(
        _ chunk: SCTPChunk
    ) throws(SCTPError) -> [[UInt8]] {
        let value = chunk.value
        guard value.count >= 16 else {
            throw SCTPError.invalidFormat("INIT-ACK too short")
        }

        let initAck = try decodeInit(value)
        let parameters = try initializationAcknowledgementParameters(in: value)

        remoteVerificationTag = initAck.initiateTag
        peerInitialTSN = initAck.initialTSN
        peerARWC = initAck.advertisedReceiverWindowCredit
        retransmissionState.setPeerAdvertisedReceiverWindow(
            initAck.advertisedReceiverWindowCredit
        )
        negotiatedOutboundStreams = min(localMaxOutboundStreams, initAck.numberOfInboundStreams)
        negotiatedInboundStreams = min(localMaxInboundStreams, initAck.numberOfOutboundStreams)
        receivedCookie = parameters.cookie
        tsnTracker = TSNTracker(initialTSN: initAck.initialTSN)
        reconfigurationState.nextExpectedPeerRequestSequenceNumber = initAck.initialTSN
        peerSupportsStreamReconfiguration =
            parameters.supportsStreamReconfiguration
        peerSupportsPartialReliability =
            parameters.supportsPartialReliability
        state = .cookieEchoed
        return parameters.reportableParameters
    }

    private func generateCookieEcho() throws(SCTPError) -> SCTPPacket {
        guard let cookie = receivedCookie else {
            throw SCTPError.invalidState("COOKIE-ECHO requested before INIT-ACK delivered a cookie")
        }
        let chunk: SCTPChunk
        do {
            chunk = try SCTPChunk(
                chunkType: SCTPChunkType.cookieEcho.rawValue,
                value: cookie
            )
        } catch {
            try error.rethrowUnwrapped()
        }
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [chunk]
        )
    }

    private mutating func handleCookieEcho(
        _ chunk: SCTPChunk,
        packet: SCTPPacket,
        nowMillis: UInt64
    ) throws(SCTPError) -> SCTPCookieEchoDisposition {
        // Decode and authenticate before reading any field as protocol authority.
        // Malformed and bad-MAC cookies are RFC-mandated silent packet discards,
        // not association failures.
        let cookie: SCTPCookieCore
        do {
            cookie = try SCTPCookieCore.decode(from: chunk.value)
        } catch {
            return .stop(responses: [])
        }
        guard cookie.isAuthentic(
            secretKey: cookieSecretKey,
            crypto: cookieCrypto
        ) else {
            return .stop(responses: [])
        }
        guard cookie.localPort == localPort,
              cookie.peerPort == packet.sourcePort,
              packet.destinationPort == localPort,
              packet.verificationTag == cookie.localTag else {
            return .stop(responses: [])
        }

        let action = cookieEchoAction(for: cookie)
        guard nowMillis >= cookie.timestamp else {
            return .stop(responses: [])
        }
        if cookie.isExpired(
            nowMillis: nowMillis,
            maxAgeMillis: Self.cookieMaxAgeMillis
        ), action != .acknowledge {
            return .stop(responses: [staleCookieErrorPacket(
                for: cookie,
                receivedAt: nowMillis,
                sourcePort: packet.sourcePort
            )])
        }

        switch action {
        case .establish:
            installNewAssociation(from: cookie)
            return .proceed(
                responses: [cookieAckPacket(for: cookie)],
                restartEvent: false
            )

        case .restart:
            if state == .shutdownAckSent {
                return .proceed(
                    responses: [
                        shutdownAckPacket(),
                        cookieReceivedWhileShuttingDownErrorPacket(),
                    ],
                    restartEvent: false
                )
            }
            installNewAssociation(from: cookie)
            return .proceed(
                responses: [cookieAckPacket(for: cookie)],
                restartEvent: true
            )

        case .collision:
            installCollisionPeer(from: cookie)
            return .proceed(
                responses: [cookieAckPacket(for: cookie)],
                restartEvent: false
            )

        case .acknowledge:
            if state == .cookieEchoed {
                state = .established
                receivedCookie = nil
            }
            return .proceed(
                responses: [cookieAckPacket(for: cookie)],
                restartEvent: false
            )

        case .discardLate, .discardUnlisted:
            return .stop(responses: [])
        }
    }

    private func cookieEchoAction(
        for cookie: SCTPCookieCore
    ) -> SCTPCookieEchoAction {
        guard state != .closed else { return .establish }

        let localMatches = cookie.localTag == localVerificationTag
        let peerIsKnown = remoteVerificationTag != 0 && cookie.peerTag != 0
        let peerMatches = peerIsKnown
            && cookie.peerTag == remoteVerificationTag
        let localTieMatches = localVerificationTag != 0
            && cookie.localTieTag == localVerificationTag
        let peerTieMatches = remoteVerificationTag != 0
            && cookie.peerTieTag == remoteVerificationTag

        if !localMatches,
           peerIsKnown,
           !peerMatches,
           localTieMatches,
           peerTieMatches {
            return .restart
        }
        if localMatches, !peerMatches {
            return .collision
        }
        if !localMatches,
           peerMatches,
           cookie.localTieTag == 0,
           cookie.peerTieTag == 0 {
            return .discardLate
        }
        if localMatches, peerMatches {
            return .acknowledge
        }
        return .discardUnlisted
    }

    /// Replace the complete TCB after a cold open or authenticated Action A.
    /// Existing DATA is intentionally discarded; RFC 9260 permits retention but
    /// requires congestion state to be reset, and preserving partial messages
    /// across a peer restart would violate message ownership.
    private mutating func installNewAssociation(from cookie: SCTPCookieCore) {
        localVerificationTag = cookie.localTag
        remoteVerificationTag = cookie.peerTag
        remotePort = cookie.peerPort
        nextTSN = cookie.localInitialTSN
        peerInitialTSN = cookie.peerInitialTSN
        peerARWC = cookie.peerARWC
        negotiatedOutboundStreams = cookie.outboundStreams
        negotiatedInboundStreams = cookie.inboundStreams
        peerSupportsStreamReconfiguration = (
            cookie.extensionFlags & Self.streamReconfigurationCookieFlag
        ) != 0
        peerSupportsPartialReliability = (
            cookie.extensionFlags & Self.partialReliabilityCookieFlag
        ) != 0
        receivedCookie = nil
        nextStreamSeqNumber.removeAll(keepingCapacity: true)
        fragmentAssembler = FragmentReassembler()
        retransmissionState = RetransmissionState(
            initialTSN: cookie.localInitialTSN
        )
        retransmissionState.setPeerAdvertisedReceiverWindow(cookie.peerARWC)
        reconfigurationState = SCTPReconfigurationState(
            localInitialTSN: cookie.localInitialTSN
        )
        reconfigurationState.nextExpectedPeerRequestSequenceNumber =
            cookie.peerInitialTSN
        shutdownTimerState = nil
        tsnTracker = TSNTracker(initialTSN: cookie.peerInitialTSN)
        state = .established
    }

    /// Apply Table 12 Action B without replacing local tag/TSN ownership.
    private mutating func installCollisionPeer(from cookie: SCTPCookieCore) {
        remoteVerificationTag = cookie.peerTag
        remotePort = cookie.peerPort
        peerInitialTSN = cookie.peerInitialTSN
        peerARWC = cookie.peerARWC
        negotiatedOutboundStreams = cookie.outboundStreams
        negotiatedInboundStreams = cookie.inboundStreams
        peerSupportsStreamReconfiguration = (
            cookie.extensionFlags & Self.streamReconfigurationCookieFlag
        ) != 0
        peerSupportsPartialReliability = (
            cookie.extensionFlags & Self.partialReliabilityCookieFlag
        ) != 0
        receivedCookie = nil
        fragmentAssembler = FragmentReassembler()
        retransmissionState.setPeerAdvertisedReceiverWindow(cookie.peerARWC)
        reconfigurationState.nextExpectedPeerRequestSequenceNumber =
            cookie.peerInitialTSN
        shutdownTimerState = nil
        tsnTracker = TSNTracker(initialTSN: cookie.peerInitialTSN)
        state = .established
    }

    private func cookieAckPacket(for cookie: SCTPCookieCore) -> SCTPPacket {
        SCTPPacket(
            sourcePort: localPort,
            destinationPort: cookie.peerPort,
            verificationTag: cookie.peerTag,
            chunks: [SCTPChunk(
                validatedChunkType: SCTPChunkType.cookieAck.rawValue,
                value: []
            )]
        )
    }

    private func staleCookieErrorPacket(
        for cookie: SCTPCookieCore,
        receivedAt nowMillis: UInt64,
        sourcePort: UInt16
    ) -> SCTPPacket {
        let ageMillis = nowMillis - cookie.timestamp
        let staleMillis = ageMillis - Self.cookieMaxAgeMillis
        let (microseconds, overflow) = staleMillis.multipliedReportingOverflow(
            by: 1_000
        )
        let boundedMicroseconds = overflow
            ? UInt64(UInt32.max)
            : min(microseconds, UInt64(UInt32.max))
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: sourcePort,
            verificationTag: cookie.peerTag,
            chunks: [SCTPStaleCookieErrorCause(
                stalenessMicroseconds: UInt32(boundedMicroseconds)
            ).toChunk()]
        )
    }

    private func handleHeartbeat(_ chunk: SCTPChunk) -> SCTPPacket {
        let ackChunk = SCTPChunk(
            validatedChunkType: SCTPChunkType.heartbeatAck.rawValue,
            value: chunk.value
        )
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [ackChunk]
        )
    }

    // MARK: - Stream reconfiguration (RFC 6525)

    private mutating func startOutgoingStreamReset(
        _ selection: SCTPStreamSelection,
        nowMillis: UInt64
    ) throws(SCTPError) -> SCTPPacket {
        let request = SCTPOutgoingSSNResetRequest(
            requestSequenceNumber: reconfigurationState.nextLocalRequestSequenceNumber,
            responseSequenceNumber: reconfigurationState.nextExpectedPeerRequestSequenceNumber &- 1,
            senderLastAssignedTSN: nextTSN &- 1,
            streamIDs: selection.wireStreamIDs
        )
        let chunk: SCTPChunk
        do {
            chunk = try SCTPReconfigurationChunk(
                parameters: [.outgoingSSNReset(request)]
            ).toChunk()
        } catch {
            try error.rethrowUnwrapped()
        }
        let packet = reconfigurationPacket(chunk: chunk)
        reconfigurationState.nextLocalRequestSequenceNumber &+= 1
        reconfigurationState.pendingOutgoingReset = .init(
            request: request,
            selection: selection,
            packet: packet,
            lastSentMillis: nowMillis,
            rtoMillis: retransmissionState.currentRTOMillis,
            retransmitCount: 0,
            peerReportedInProgress: false,
            implicitlyAcknowledged: false
        )
        return packet
    }

    private mutating func startNextQueuedResetIfPresent(
        nowMillis: UInt64,
        responses: inout [SCTPPacket]
    ) throws(SCTPError) {
        guard reconfigurationState.pendingOutgoingReset == nil,
              let selection = reconfigurationState.popQueuedReset() else {
            return
        }
        responses.append(try startOutgoingStreamReset(
            selection,
            nowMillis: nowMillis
        ))
    }

    private func validateOutgoingResetSelection(
        _ selection: SCTPStreamSelection
    ) throws(SCTPError) {
        for streamID in selection.wireStreamIDs {
            guard streamID < negotiatedOutboundStreams else {
                throw .invalidStreamResetIdentifier(
                    streamID: streamID,
                    negotiated: negotiatedOutboundStreams
                )
            }
        }
    }

    private func incomingResetSelectionIsValid(
        _ selection: SCTPStreamSelection
    ) -> Bool {
        selection.wireStreamIDs.allSatisfy { $0 < negotiatedInboundStreams }
    }

    private mutating func processReconfigurationChunk(
        _ chunk: SCTPChunk,
        nowMillis: UInt64,
        responses: inout [SCTPPacket],
        deliveries: inout [SCTPAssociationDelivery]
    ) throws(SCTPError) -> Bool {
        let reconfiguration: SCTPReconfigurationChunk
        do {
            reconfiguration = try SCTPReconfigurationChunk.decode(from: chunk)
        } catch {
            try error.rethrowUnwrapped()
        }

        let peerRequestSequenceNumbers = reconfiguration.parameters.compactMap {
            parameter -> UInt32? in
            switch parameter {
            case .outgoingSSNReset(let request):
                request.requestSequenceNumber
            case .incomingSSNReset(let request):
                request.requestSequenceNumber
            case .response:
                nil
            }
        }

        // A response can share a chunk with an outgoing reset request. Process
        // that response even when the request half is a retransmission.
        for parameter in reconfiguration.parameters {
            guard case .response(let response) = parameter else { continue }
            try processReconfigurationResponse(
                response,
                nowMillis: nowMillis,
                deliveries: &deliveries
            )
        }

        // RFC 6525 §5.2.2 E1: an Outgoing SSN Reset Request carries the
        // sender's last processed peer request sequence number. It acknowledges
        // our pending request and stops its retransmission timer, but it does not
        // carry the Result required by §5.2.7 H3/H4. Keep the pending request
        // until its explicit response decides success or failure.
        for parameter in reconfiguration.parameters {
            guard case .outgoingSSNReset(let request) = parameter else { continue }
            acknowledgeOutgoingResetImplicitly(
                responseSequenceNumber: request.responseSequenceNumber
            )
        }

        // RFC 6525 requires retransmitting the exact response RE-CONFIG chunk,
        // including both responses for a two-request input chunk.
        if !peerRequestSequenceNumbers.isEmpty,
           let cached = reconfigurationState.cachedPeerResponse,
           cached.requestSequenceNumbers == peerRequestSequenceNumbers {
            responses.append(reconfigurationPacket(chunk: cached.chunk))
            try startNextQueuedResetIfPresent(
                nowMillis: nowMillis,
                responses: &responses
            )
            return try releaseQueuedUserMessages(nowMillis: nowMillis)
        }

        var responseChunks: [SCTPChunk] = []
        responseChunks.reserveCapacity(peerRequestSequenceNumbers.count)

        // Do not promote a queued local request until every parameter in this
        // chunk has been evaluated against the same outstanding request. That
        // prevents a later response parameter from accidentally acknowledging a
        // request the peer has not received yet.
        for parameter in reconfiguration.parameters {
            switch parameter {
            case .response:
                continue

            case .outgoingSSNReset(let request):
                responseChunks.append(try processIncomingOutgoingReset(
                    request,
                    deliveries: &deliveries
                ))

            case .incomingSSNReset(let request):
                responseChunks.append(try processIncomingResetRequest(request))
            }
        }

        if !responseChunks.isEmpty {
            var responseParameters: [SCTPReconfigurationParameter] = []
            responseParameters.reserveCapacity(responseChunks.count)
            for responseChunk in responseChunks {
                let decoded: SCTPReconfigurationChunk
                do {
                    decoded = try SCTPReconfigurationChunk.decode(from: responseChunk)
                } catch {
                    try error.rethrowUnwrapped()
                }
                responseParameters.append(contentsOf: decoded.parameters)
            }
            let combined: SCTPChunk
            do {
                combined = try SCTPReconfigurationChunk(
                    parameters: responseParameters
                ).toChunk()
            } catch {
                try error.rethrowUnwrapped()
            }
            reconfigurationState.cachedPeerResponse = .init(
                requestSequenceNumbers: peerRequestSequenceNumbers,
                chunk: combined
            )
            responses.append(reconfigurationPacket(chunk: combined))
        }
        try startNextQueuedResetIfPresent(
            nowMillis: nowMillis,
            responses: &responses
        )
        return try releaseQueuedUserMessages(nowMillis: nowMillis)
    }

    private mutating func processReconfigurationResponse(
        _ response: SCTPReconfigurationResponse,
        nowMillis: UInt64,
        deliveries: inout [SCTPAssociationDelivery]
    ) throws(SCTPError) {
        guard let pending = reconfigurationState.pendingOutgoingReset,
              pending.request.requestSequenceNumber == response.responseSequenceNumber else {
            // A late duplicate response cannot acknowledge a different request.
            return
        }
        guard response.senderNextTSN == nil, response.receiverNextTSN == nil else {
            // Optional TSNs are valid only for an SSN/TSN reset response, never
            // for the pending Outgoing SSN Reset Request used by WebRTC close.
            throw .invalidFormat("Outgoing stream reset response contains SSN/TSN reset fields")
        }

        if response.result == .inProgress {
            var restarted = pending
            restarted.lastSentMillis = nowMillis
            restarted.peerReportedInProgress = true
            // RFC 6525 section 5.2.3 H2: an explicit In Progress response
            // supersedes an earlier implicit acknowledgement and restarts the
            // response timer. The reset remains pending until a final response.
            restarted.implicitlyAcknowledged = false
            reconfigurationState.pendingOutgoingReset = restarted
            return
        }
        completeOutgoingReset(
            result: response.result,
            deliveries: &deliveries
        )
    }

    private mutating func completeOutgoingReset(
        result: SCTPReconfigurationResult,
        deliveries: inout [SCTPAssociationDelivery]
    ) {
        guard let pending = reconfigurationState.pendingOutgoingReset else {
            return
        }
        reconfigurationState.pendingOutgoingReset = nil

        if result.isSuccess {
            resetOutgoingSequenceNumbers(pending.selection)
            deliveries.append(.event(.outgoingStreamsReset(pending.selection)))
        } else {
            deliveries.append(.event(.outgoingStreamResetFailed(
                pending.selection,
                result
            )))
        }
    }

    private mutating func acknowledgeOutgoingResetImplicitly(
        responseSequenceNumber: UInt32
    ) {
        guard var pending = reconfigurationState.pendingOutgoingReset,
              pending.request.requestSequenceNumber == responseSequenceNumber else {
            return
        }
        pending.implicitlyAcknowledged = true
        reconfigurationState.pendingOutgoingReset = pending
    }

    private mutating func processIncomingOutgoingReset(
        _ request: SCTPOutgoingSSNResetRequest,
        deliveries: inout [SCTPAssociationDelivery]
    ) throws(SCTPError) -> SCTPChunk {
        let expected = reconfigurationState.nextExpectedPeerRequestSequenceNumber
        guard request.requestSequenceNumber == expected else {
            return try makeReconfigurationResponseChunk(
                sequenceNumber: request.requestSequenceNumber,
                result: .errorBadSequenceNumber
            )
        }

        let selection = SCTPStreamSelection(wireStreamIDs: request.streamIDs)
        guard incomingResetSelectionIsValid(selection) else {
            reconfigurationState.nextExpectedPeerRequestSequenceNumber &+= 1
            let chunk = try makeReconfigurationResponseChunk(
                sequenceNumber: request.requestSequenceNumber,
                result: .errorWrongSSN
            )
            return chunk
        }

        guard let tracker = tsnTracker else {
            throw .invalidState("Stream reset received before TSN tracking was initialized")
        }
        if TSNTracker.isLessThanOrEqual(
            request.senderLastAssignedTSN,
            tracker.cumulativeTSN
        ) {
            resetIncomingSequenceNumbers(selection)
            reconfigurationState.nextExpectedPeerRequestSequenceNumber &+= 1
            deliveries.append(.event(.incomingStreamsReset(selection)))
            let chunk = try makeReconfigurationResponseChunk(
                sequenceNumber: request.requestSequenceNumber,
                result: .successPerformed
            )
            return chunk
        }

        guard reconfigurationState.deferredIncomingReset == nil else {
            reconfigurationState.nextExpectedPeerRequestSequenceNumber &+= 1
            return try makeReconfigurationResponseChunk(
                sequenceNumber: request.requestSequenceNumber,
                result: .errorRequestAlreadyInProgress
            )
        }
        reconfigurationState.deferredIncomingReset = .init(
            request: request,
            selection: selection,
            heldDataChunks: [],
            heldByteCount: 0
        )
        reconfigurationState.nextExpectedPeerRequestSequenceNumber &+= 1
        let chunk = try makeReconfigurationResponseChunk(
            sequenceNumber: request.requestSequenceNumber,
            result: .inProgress
        )
        return chunk
    }

    /// Type 14 asks this endpoint to initiate a reset of its outgoing streams.
    /// The WebRTC close protocol uses reciprocal type 13 requests instead, and
    /// this SCTP facade does not expose a generic incoming-reset policy callback.
    /// RFC 6525 permits an administrative denial, which is explicit and keeps
    /// the association usable rather than treating a valid request as malformed.
    private mutating func processIncomingResetRequest(
        _ request: SCTPIncomingSSNResetRequest
    ) throws(SCTPError) -> SCTPChunk {
        guard request.requestSequenceNumber
                == reconfigurationState.nextExpectedPeerRequestSequenceNumber else {
            return try makeReconfigurationResponseChunk(
                sequenceNumber: request.requestSequenceNumber,
                result: .errorBadSequenceNumber
            )
        }

        reconfigurationState.nextExpectedPeerRequestSequenceNumber &+= 1
        let response = try makeReconfigurationResponseChunk(
            sequenceNumber: request.requestSequenceNumber,
            result: .denied
        )
        return response
    }

    private mutating func holdDataForDeferredResetIfNeeded(
        _ chunk: SCTPDataChunk
    ) throws(SCTPError) -> Bool {
        guard var deferred = reconfigurationState.deferredIncomingReset,
              deferred.selection.contains(chunk.streamIdentifier),
              TSNTracker.isLessThan(deferred.request.senderLastAssignedTSN, chunk.tsn) else {
            return false
        }

        let (projectedBytes, overflow) = deferred.heldByteCount.addingReportingOverflow(
            chunk.userDataByteCount
        )
        guard !overflow,
              deferred.heldDataChunks.count < SCTPReconfigurationState.maximumDeferredMessageCount,
              projectedBytes <= SCTPReconfigurationState.maximumDeferredByteCount else {
            throw .receiveBufferExceeded(streamID: chunk.streamIdentifier)
        }
        deferred.heldDataChunks.append(chunk)
        deferred.heldByteCount = projectedBytes
        reconfigurationState.deferredIncomingReset = deferred
        return true
    }

    private mutating func completeDeferredResetIfReady(
        responses: inout [SCTPPacket],
        deliveries: inout [SCTPAssociationDelivery]
    ) throws(SCTPError) {
        guard let deferred = reconfigurationState.deferredIncomingReset,
              let tracker = tsnTracker,
              TSNTracker.isLessThanOrEqual(
                deferred.request.senderLastAssignedTSN,
                tracker.cumulativeTSN
              ) else {
            return
        }

        reconfigurationState.deferredIncomingReset = nil
        resetIncomingSequenceNumbers(deferred.selection)
        deliveries.append(.event(.incomingStreamsReset(deferred.selection)))

        var held = deferred.heldDataChunks
        held.sort { TSNTracker.isLessThan($0.tsn, $1.tsn) }
        for chunk in held {
            for message in try processFragment(chunk) {
                deliveries.append(.message(SCTPReceivedMessage(
                    streamID: message.streamID,
                    ppid: message.ppid,
                    data: message.data
                )))
            }
        }

        let responseChunk = try makeReconfigurationResponseChunk(
            sequenceNumber: deferred.request.requestSequenceNumber,
            result: .successPerformed
        )
        try replaceCachedPeerResponse(
            sequenceNumber: deferred.request.requestSequenceNumber,
            result: .successPerformed
        )
        responses.append(reconfigurationPacket(chunk: responseChunk))
    }

    private mutating func replaceCachedPeerResponse(
        sequenceNumber: UInt32,
        result: SCTPReconfigurationResult
    ) throws(SCTPError) {
        guard let cached = reconfigurationState.cachedPeerResponse,
              cached.requestSequenceNumbers.contains(sequenceNumber) else {
            let chunk = try makeReconfigurationResponseChunk(
                sequenceNumber: sequenceNumber,
                result: result
            )
            reconfigurationState.cachedPeerResponse = .init(
                requestSequenceNumbers: [sequenceNumber],
                chunk: chunk
            )
            return
        }

        let decoded: SCTPReconfigurationChunk
        do {
            decoded = try SCTPReconfigurationChunk.decode(from: cached.chunk)
        } catch {
            try error.rethrowUnwrapped()
        }
        let parameters = decoded.parameters.map { parameter in
            guard case .response(let response) = parameter,
                  response.responseSequenceNumber == sequenceNumber else {
                return parameter
            }
            return .response(SCTPReconfigurationResponse(
                responseSequenceNumber: sequenceNumber,
                result: result
            ))
        }
        let chunk: SCTPChunk
        do {
            chunk = try SCTPReconfigurationChunk(parameters: parameters).toChunk()
        } catch {
            try error.rethrowUnwrapped()
        }
        reconfigurationState.cachedPeerResponse = .init(
            requestSequenceNumbers: cached.requestSequenceNumbers,
            chunk: chunk
        )
    }

    private mutating func resetIncomingSequenceNumbers(
        _ selection: SCTPStreamSelection
    ) {
        if selection.wireStreamIDs.isEmpty {
            fragmentAssembler.resetAllStreams()
        } else {
            for streamID in selection.wireStreamIDs {
                fragmentAssembler.resetStream(streamID)
            }
        }
    }

    private mutating func resetOutgoingSequenceNumbers(
        _ selection: SCTPStreamSelection
    ) {
        if selection.wireStreamIDs.isEmpty {
            nextStreamSeqNumber.removeAll(keepingCapacity: true)
        } else {
            for streamID in selection.wireStreamIDs {
                nextStreamSeqNumber.removeValue(forKey: streamID)
            }
        }
    }

    private func makeReconfigurationResponseChunk(
        sequenceNumber: UInt32,
        result: SCTPReconfigurationResult
    ) throws(SCTPError) -> SCTPChunk {
        do {
            return try SCTPReconfigurationChunk(parameters: [
                .response(SCTPReconfigurationResponse(
                    responseSequenceNumber: sequenceNumber,
                    result: result
                )),
            ]).toChunk()
        } catch {
            try error.rethrowUnwrapped()
        }
    }

    private func reconfigurationPacket(chunk: SCTPChunk) -> SCTPPacket {
        SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [chunk]
        )
    }

    /// Generate a SACK for the current receive state.
    ///
    /// The advertised receiver window reflects the bytes currently held by the
    /// fragment assembler. Returns nil when TSN tracking has not been initialized.
    private mutating func generateSack() throws(SCTPError) -> SCTPPacket? {
        guard var tracker = tsnTracker else { return nil }
        // Common header (12) + SACK chunk header (4) + fixed SACK value (12).
        // Every Gap Ack Block or Duplicate TSN then consumes four bytes.
        let maximumSackEntryCount = max(
            0,
            (Self.defaultMaximumPacketByteCount - 28) / 4
        )
        let gaps = tracker.gapBlocks(maximumCount: maximumSackEntryCount)
        let allDuplicates = tracker.takeDuplicates()
        let duplicateCapacity = maximumSackEntryCount - gaps.count
        let dups = Array(allDuplicates.prefix(duplicateCapacity))
        let cumulativeTSN = tracker.cumulativeTSN
        tsnTracker = tracker

        let deferredBytes = reconfigurationState.deferredIncomingReset?.heldByteCount ?? 0
        let (totalBuffered, overflow) = fragmentAssembler.bufferedBytes.addingReportingOverflow(
            deferredBytes
        )
        let buffered = UInt32(clamping: overflow ? Int.max : totalBuffered)
        let available = advertisedReceiverWindowCredit >= buffered
            ? advertisedReceiverWindowCredit - buffered
            : 0

        let sack = SCTPSackChunk(
            cumulativeTSNAck: cumulativeTSN,
            advertisedReceiverWindowCredit: available,
            gapAckBlocks: gaps,
            duplicateTSNs: dups
        )
        let chunk: SCTPChunk
        do {
            chunk = try sack.toChunk()
        } catch {
            try error.rethrowUnwrapped()
        }
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [chunk]
        )
    }

    private mutating func startShutdown(
        nowMillis: UInt64
    ) throws(SCTPError) -> SCTPPacket {
        let packet = try shutdownPacket()
        let timer = try SCTPShutdownTimerState(
            controlFlight: .shutdown,
            sentMillis: nowMillis,
            rtoMillis: retransmissionState.currentRTOMillis
        )
        state = .shutdownSent
        shutdownTimerState = timer
        return packet
    }

    /// Build SHUTDOWN from the latest cumulative receive TSN. T2 retransmission
    /// cannot reuse stale bytes because DATA remains receivable in SHUTDOWN-SENT.
    private func shutdownPacket() throws(SCTPError) -> SCTPPacket {
        guard let tracker = tsnTracker else {
            throw .invalidState("SHUTDOWN requested before TSN tracking was initialized")
        }
        let cumulativeTSN = tracker.cumulativeTSN
        let value: [UInt8] = [
            UInt8(cumulativeTSN >> 24),
            UInt8((cumulativeTSN >> 16) & 0xFF),
            UInt8((cumulativeTSN >> 8) & 0xFF),
            UInt8(cumulativeTSN & 0xFF),
        ]
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [SCTPChunk(
                validatedChunkType: SCTPChunkType.shutdown.rawValue,
                value: value
            )]
        )
    }

    private mutating func enterShutdownAckSent(
        nowMillis: UInt64
    ) throws(SCTPError) -> SCTPPacket {
        let timer = try SCTPShutdownTimerState(
            controlFlight: .shutdownAck,
            sentMillis: nowMillis,
            rtoMillis: retransmissionState.currentRTOMillis,
            inheritedT5DeadlineMillis: shutdownTimerState?.t5DeadlineMillis
        )
        state = .shutdownAckSent
        shutdownTimerState = timer
        return shutdownAckPacket()
    }

    private func shutdownAckPacket() -> SCTPPacket {
        SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [SCTPChunk(
                validatedChunkType: SCTPChunkType.shutdownAck.rawValue,
                value: []
            )]
        )
    }

    private func generateShutdownComplete(reflected: Bool) -> SCTPPacket {
        let chunk = SCTPChunk(
            validatedChunkType: SCTPChunkType.shutdownComplete.rawValue,
            flags: reflected ? 0x01 : 0,
            value: []
        )
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteVerificationTag,
            chunks: [chunk]
        )
    }

    // MARK: - Decode helpers (bridge SCTPWireError -> SCTPError)

    private static var streamReconfigurationCookieFlag: UInt32 { 1 << 0 }
    private static var partialReliabilityCookieFlag: UInt32 { 1 << 1 }

    /// Local INIT/INIT-ACK capability parameters. The five-byte Supported
    /// Extensions parameter is padded before the following RFC 3758 parameter;
    /// its declared length correctly excludes those three padding bytes.
    private static var initializationExtensionParameters: [UInt8] {
        [
            0x80, 0x08, 0x00, 0x05, SCTPChunkType.reConfig.rawValue,
            0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x04,
        ]
    }

    private func initializationParameters(
        in initValue: [UInt8]
    ) throws(SCTPError) -> SCTPInitParameters {
        guard initValue.count >= 16 else {
            throw .invalidFormat("INIT value is shorter than its fixed fields")
        }

        var offset = 16
        var supportedExtensions: SCTPSupportedExtensionsParameter?
        var supportsPartialReliability = false
        var reportableParameters: [[UInt8]] = []
        while offset < initValue.count {
            guard initValue.count - offset >= 4 else {
                throw .invalidFormat("Truncated parameter header in INIT")
            }
            let type = readUInt16(initValue, offset: offset)
            let length = Int(readUInt16(initValue, offset: offset + 2))
            guard length >= 4, length <= initValue.count - offset else {
                throw .invalidFormat("Invalid parameter length in INIT")
            }

            if type == SCTPSupportedExtensionsParameter.parameterType {
                guard supportedExtensions == nil else {
                    throw .invalidFormat("Duplicate Supported Extensions parameter in INIT")
                }
                do {
                    supportedExtensions = try SCTPSupportedExtensionsParameter.decode(
                        from: initValue,
                        offset: offset,
                        length: length
                    )
                } catch {
                    try error.rethrowUnwrapped()
                }
            } else if type == SCTPForwardTSNSupportedParameter.parameterType {
                guard !supportsPartialReliability else {
                    throw .invalidFormat(
                        "Duplicate Forward-TSN-Supported parameter in INIT"
                    )
                }
                do {
                    _ = try SCTPForwardTSNSupportedParameter.decode(
                        from: initValue,
                        offset: offset,
                        length: length
                    )
                } catch {
                    try error.rethrowUnwrapped()
                }
                supportsPartialReliability = true
            } else {
                let action = type >> 14
                if action == 0b01 || action == 0b11 {
                    reportableParameters.append(
                        Array(initValue[offset..<(offset + length)])
                    )
                }
                if action == 0b00 || action == 0b01 {
                    break
                }
            }

            let end = offset + length
            if end == initValue.count {
                offset = end
            } else {
                let paddedLength = (length + 3) & ~3
                guard paddedLength <= initValue.count - offset else {
                    throw .invalidFormat("Truncated parameter padding in INIT")
                }
                offset += paddedLength
            }
        }
        return SCTPInitParameters(
            supportsStreamReconfiguration:
                supportedExtensions?.chunkTypes.contains(
                    SCTPChunkType.reConfig.rawValue
                ) == true,
            supportsPartialReliability: supportsPartialReliability,
            reportableParameters: reportableParameters
        )
    }

    private func initializationAcknowledgementParameters(
        in value: [UInt8]
    ) throws(SCTPError) -> SCTPInitAckParameters {
        var offset = 16
        var cookie: [UInt8]?
        var supportedExtensions: SCTPSupportedExtensionsParameter?
        var supportsPartialReliability = false
        var reportableParameters: [[UInt8]] = []
        var processesOptionalParameters = true

        while offset < value.count {
            // RFC 9260 §3.2.1 requires COOKIE-ECHO for every unknown-parameter
            // action. Once action 00/01 stops optional-parameter processing, a
            // framing-only scan may therefore continue just far enough to find
            // the mandatory State Cookie. No other trailing parameter affects
            // negotiated state or reporting.
            if !processesOptionalParameters, cookie != nil {
                break
            }
            guard value.count - offset >= 4 else {
                throw .invalidFormat(
                    "Truncated parameter header in INIT-ACK"
                )
            }
            let type = readUInt16(value, offset: offset)
            let length = Int(readUInt16(value, offset: offset + 2))
            guard length >= 4, length <= value.count - offset else {
                throw .invalidFormat(
                    "Invalid parameter length in INIT-ACK"
                )
            }

            if !processesOptionalParameters {
                if type == 7 {
                    cookie = Array(value[(offset + 4)..<(offset + length)])
                }
            } else if type == 7 {
                guard cookie == nil else {
                    throw .invalidFormat(
                        "Duplicate State Cookie parameter in INIT-ACK"
                    )
                }
                cookie = Array(value[(offset + 4)..<(offset + length)])
            } else if type
                        == SCTPSupportedExtensionsParameter.parameterType {
                guard supportedExtensions == nil else {
                    throw .invalidFormat(
                        "Duplicate Supported Extensions parameter in INIT-ACK"
                    )
                }
                do {
                    supportedExtensions =
                        try SCTPSupportedExtensionsParameter.decode(
                            from: value,
                            offset: offset,
                            length: length
                        )
                } catch {
                    try error.rethrowUnwrapped()
                }
            } else if type == SCTPForwardTSNSupportedParameter.parameterType {
                guard !supportsPartialReliability else {
                    throw .invalidFormat(
                        "Duplicate Forward-TSN-Supported parameter in INIT-ACK"
                    )
                }
                do {
                    _ = try SCTPForwardTSNSupportedParameter.decode(
                        from: value,
                        offset: offset,
                        length: length
                    )
                } catch {
                    try error.rethrowUnwrapped()
                }
                supportsPartialReliability = true
            } else if type == SCTPUnrecognizedParameter.parameterType {
                do {
                    _ = try SCTPUnrecognizedParameter.decode(
                        from: value,
                        offset: offset,
                        length: length
                    )
                } catch {
                    try error.rethrowUnwrapped()
                }
            } else {
                let action = type >> 14
                if action == 0b01 || action == 0b11 {
                    reportableParameters.append(
                        Array(value[offset..<(offset + length)])
                    )
                }
                if action == 0b00 || action == 0b01 {
                    processesOptionalParameters = false
                }
            }

            let end = offset + length
            if end == value.count {
                offset = end
            } else {
                let paddedLength = (length + 3) & ~3
                guard paddedLength <= value.count - offset else {
                    throw .invalidFormat(
                        "Truncated parameter padding in INIT-ACK"
                    )
                }
                offset += paddedLength
            }
        }

        guard let cookie else {
            throw .invalidFormat("No State Cookie in INIT-ACK")
        }
        return SCTPInitAckParameters(
            cookie: cookie,
            supportsStreamReconfiguration:
                supportedExtensions?.chunkTypes.contains(
                    SCTPChunkType.reConfig.rawValue
                ) == true,
            supportsPartialReliability: supportsPartialReliability,
            reportableParameters: reportableParameters
        )
    }

    private func decodeInit(_ value: [UInt8]) throws(SCTPError) -> SCTPInitChunk {
        do {
            return try SCTPInitChunk.decode(from: value)
        } catch {
            try error.rethrowUnwrapped()
        }
    }

    private func decodeData(_ chunk: SCTPChunk) throws(SCTPError) -> SCTPDataChunk {
        do {
            return try chunk.decodedDataChunk()
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
