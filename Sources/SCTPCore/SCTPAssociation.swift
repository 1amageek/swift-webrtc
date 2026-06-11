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
    }

    public init(
        localPort: UInt16 = 5000,
        remotePort: UInt16 = 5000
    ) {
        // RFC 4960 §3.3.2: the initiate tag must not be 0
        let tag = SCTPSecureRandom.uint32NonZero()
        let initialTSN = SCTPSecureRandom.uint32()
        let secretKey = SCTPSecureRandom.data(count: 32)
        self.cookieSecretKey = secretKey

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
            numberOfOutboundStreams: 65535,
            numberOfInboundStreams: 65535,
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
                    let isNew = tracker.receive(tsn: dataChunk.tsn)
                    s.tsnTracker = tracker
                    guard isNew else { return [] }
                    return try s.fragmentAssembler.process(chunk: dataChunk)
                }

                for msg in assembled {
                    receivedData.append((msg.streamID, msg.ppid, msg.data))
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

        // RFC 4960 §8.5.1 (B): an ABORT sent in response to an unexpected
        // packet reflects the sender's own tag (T-bit semantics)
        let containsAbort = packet.chunks.contains { $0.chunkType == SCTPChunkType.abort.rawValue }
        if containsAbort && packet.verificationTag == remoteTag {
            return
        }

        throw SCTPError.verificationTagMismatch(expected: localTag, actual: packet.verificationTag)
    }

    /// Send data on a stream
    public func sendData(
        streamID: UInt16,
        payloadProtocolIdentifier: UInt32,
        data: Data,
        unordered: Bool = false
    ) -> SCTPPacket {
        let (localPort, remotePort, remoteTag, tsn, seqNum) = assocState.withLock { s -> (UInt16, UInt16, UInt32, UInt32, UInt16) in
            let tsn = s.nextTSN
            s.nextTSN = s.nextTSN &+ 1
            let seqNum = s.nextStreamSeqNumber[streamID, default: 0]
            if !unordered {
                s.nextStreamSeqNumber[streamID] = seqNum &+ 1
            }
            return (s.localPort, s.remotePort, s.remoteVerificationTag, tsn, seqNum)
        }

        let dataChunk = SCTPDataChunk(
            tsn: tsn,
            streamIdentifier: streamID,
            streamSequenceNumber: seqNum,
            payloadProtocolIdentifier: payloadProtocolIdentifier,
            userData: data,
            unordered: unordered
        )

        // Add to retransmission queue
        assocState.withLock { s in
            s.retransmissionQueue.enqueue(dataChunk)
        }

        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteTag,
            chunks: [dataChunk.toChunk()]
        )
    }

    /// Get pending retransmissions
    /// - Returns: Packets to retransmit, or error if max retransmits exceeded
    public func getPendingRetransmissions() -> Result<[SCTPPacket], SCTPError> {
        assocState.withLock { s in
            switch s.retransmissionQueue.pendingRetransmissions() {
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
            s.remoteVerificationTag = initChunk.initiateTag
            s.remotePort = sourcePort
            s.peerInitialTSN = initChunk.initialTSN
            s.peerARWC = initChunk.advertisedReceiverWindowCredit
            s.negotiatedOutboundStreams = min(65535, initChunk.numberOfInboundStreams)
            s.negotiatedInboundStreams = min(65535, initChunk.numberOfOutboundStreams)

            // Initialize TSN tracker with peer's initial TSN
            s.tsnTracker = TSNTracker(initialTSN: initChunk.initialTSN)

            // Generate secure cookie (P0.1)
            let cookie = SCTPCookie.generate(
                secretKey: cookieSecretKey,
                peerTag: initChunk.initiateTag,
                localTag: s.localVerificationTag,
                peerInitialTSN: initChunk.initialTSN,
                peerARWC: initChunk.advertisedReceiverWindowCredit,
                outboundStreams: s.negotiatedOutboundStreams,
                inboundStreams: s.negotiatedInboundStreams
            )

            return (s.localPort, s.remotePort, s.localVerificationTag, s.nextTSN, cookie)
        }

        // Build INIT-ACK with cookie
        let initAck = SCTPInitChunk(
            initiateTag: localTag,
            numberOfOutboundStreams: 65535,
            numberOfInboundStreams: 65535,
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

            // Move to next parameter (padded to 4 bytes)
            offset += (paramLength + 3) & ~3
        }

        guard let cookie = cookieData else {
            throw SCTPError.invalidFormat("No State Cookie in INIT-ACK")
        }

        assocState.withLock { s in
            s.remoteVerificationTag = initAck.initiateTag
            s.peerInitialTSN = initAck.initialTSN
            s.peerARWC = initAck.advertisedReceiverWindowCredit
            s.negotiatedOutboundStreams = min(65535, initAck.numberOfInboundStreams)
            s.negotiatedInboundStreams = min(65535, initAck.numberOfOutboundStreams)
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
        // Validate cookie
        let cookie = try SCTPCookie.decode(from: chunk.value)

        guard cookie.validate(secretKey: cookieSecretKey) else {
            throw SCTPError.cookieValidationFailed
        }

        // Restore association state from cookie
        let (localPort, remotePort, remoteTag) = assocState.withLock { s -> (UInt16, UInt16, UInt32) in
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
