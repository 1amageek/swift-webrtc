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
        // Generate random verification tag
        var tag: UInt32 = 0
        withUnsafeMutableBytes(of: &tag) { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 4, ptr.baseAddress!)
        }

        // Generate random initial TSN (P0.2)
        var initialTSN: UInt32 = 0
        withUnsafeMutableBytes(of: &initialTSN) { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 4, ptr.baseAddress!)
        }

        // Generate cookie secret key
        var secretKey = Data(count: 32)
        secretKey.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
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
    public func processPacket(_ packet: SCTPPacket) throws -> (responses: [SCTPPacket], receivedData: [(streamID: UInt16, ppid: UInt32, data: Data)]) {
        var responses: [SCTPPacket] = []
        var receivedData: [(streamID: UInt16, ppid: UInt32, data: Data)] = []

        for chunk in packet.chunks {
            guard let chunkType = SCTPChunkType(rawValue: chunk.chunkType) else {
                continue
            }

            switch chunkType {
            case .initChunk:
                let initChunk = try SCTPInitChunk.decode(from: chunk.value)
                let response = handleInit(initChunk, sourcePort: packet.sourcePort)
                responses.append(response)

            case .initAck:
                try handleInitAck(chunk)
                // Send COOKIE-ECHO
                let cookieEcho = generateCookieEcho()
                responses.append(cookieEcho)

            case .cookieEcho:
                let response = try handleCookieEcho(chunk)
                responses.append(response)

            case .cookieAck:
                handleCookieAck()

            case .data:
                let dataChunk = try SCTPDataChunk.decode(from: chunk.value, flags: chunk.flags)

                // Track TSN
                let isNew = assocState.withLock { s -> Bool in
                    s.tsnTracker?.receive(tsn: dataChunk.tsn) ?? true
                }

                if isNew {
                    // Process through fragment assembler
                    let assembled = assocState.withLock { s in
                        s.fragmentAssembler.process(chunk: dataChunk)
                    }

                    for msg in assembled {
                        receivedData.append((msg.streamID, msg.ppid, msg.data))
                    }
                }

                // Generate SACK
                let sack = generateSack()
                responses.append(sack)

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

            default:
                break
            }
        }

        return (responses, receivedData)
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

            if paramType == 7 { // State Cookie
                guard offset + 4 + paramLength - 4 <= value.count else {
                    throw SCTPError.invalidFormat("Cookie parameter truncated")
                }
                cookieData = Data(value[(offset + 4)..<(offset + paramLength)])
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

    private func generateCookieEcho() -> SCTPPacket {
        let (localPort, remotePort, remoteTag, cookie) = assocState.withLock { s in
            (s.localPort, s.remotePort, s.remoteVerificationTag, s.receivedCookie ?? Data())
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

    private func generateSack() -> SCTPPacket {
        let (localPort, remotePort, remoteTag, cumulativeTSN, gaps, dups) = assocState.withLock { s -> (UInt16, UInt16, UInt32, UInt32, [(UInt16, UInt16)], [UInt32]) in
            guard let tracker = s.tsnTracker else {
                return (s.localPort, s.remotePort, s.remoteVerificationTag, 0, [], [])
            }
            var mutableTracker = tracker
            let dups = mutableTracker.takeDuplicates()
            s.tsnTracker = mutableTracker
            return (s.localPort, s.remotePort, s.remoteVerificationTag, tracker.cumulativeTSN, tracker.gapBlocks, dups)
        }

        let sack = SCTPSackChunk(
            cumulativeTSNAck: cumulativeTSN,
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
