/// SCTP Association (RFC 4960)
///
/// Manages an SCTP association over DTLS for WebRTC data channels.

import Foundation
import Synchronization

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

    private struct AssocState: Sendable {
        var state: SCTPAssociationState = .closed
        var localPort: UInt16
        var remotePort: UInt16
        var localVerificationTag: UInt32
        var remoteVerificationTag: UInt32 = 0
        var nextTSN: UInt32 = 0
        var lastReceivedTSN: UInt32 = 0
        var advertisedReceiverWindowCredit: UInt32 = 65535
        var nextStreamSeqNumber: [UInt16: UInt16] = [:]
    }

    public init(
        localPort: UInt16 = 5000,
        remotePort: UInt16 = 5000
    ) {
        var tag: UInt32 = 0
        withUnsafeMutableBytes(of: &tag) { ptr in
            let _ = SecRandomCopyBytes(kSecRandomDefault, 4, ptr.baseAddress!)
        }
        self.assocState = Mutex(AssocState(
            localPort: localPort,
            remotePort: remotePort,
            localVerificationTag: tag
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
                let initAck = try SCTPInitChunk.decode(from: chunk.value)
                handleInitAck(initAck)
                // Send COOKIE-ECHO
                let cookieEcho = generateCookieEcho()
                responses.append(cookieEcho)

            case .cookieEcho:
                let response = handleCookieEcho(chunk)
                responses.append(response)

            case .cookieAck:
                handleCookieAck()

            case .data:
                let dataChunk = try SCTPDataChunk.decode(from: chunk.value, flags: chunk.flags)
                receivedData.append((dataChunk.streamIdentifier, dataChunk.payloadProtocolIdentifier, dataChunk.userData))
                // Generate SACK
                let sack = generateSack(tsn: dataChunk.tsn)
                responses.append(sack)

            case .sack:
                break // ACK received, update window

            case .shutdown:
                let ack = generateShutdownAck()
                responses.append(ack)

            case .shutdownAck:
                assocState.withLock { $0.state = .closed }

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
            s.nextTSN += 1
            let seqNum = s.nextStreamSeqNumber[streamID, default: 0]
            s.nextStreamSeqNumber[streamID] = seqNum + 1
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

        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteTag,
            chunks: [dataChunk.toChunk()]
        )
    }

    // MARK: - Private handlers

    private func handleInit(_ initChunk: SCTPInitChunk, sourcePort: UInt16) -> SCTPPacket {
        let (localPort, remotePort, tag, tsn) = assocState.withLock { s -> (UInt16, UInt16, UInt32, UInt32) in
            s.remoteVerificationTag = initChunk.initiateTag
            s.remotePort = sourcePort
            return (s.localPort, s.remotePort, s.localVerificationTag, s.nextTSN)
        }

        let initAck = SCTPInitChunk(
            initiateTag: tag,
            numberOfOutboundStreams: 65535,
            numberOfInboundStreams: 65535,
            initialTSN: tsn
        )

        // Include a cookie (simplified — in production, should be HMAC-protected)
        var cookieValue = initAck.encode()
        // Append cookie data
        cookieValue.append(Data(repeating: 0xCC, count: 4))

        let ackChunk = SCTPChunk(chunkType: SCTPChunkType.initAck.rawValue, value: cookieValue)

        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: initChunk.initiateTag,
            chunks: [ackChunk]
        )
    }

    private func handleInitAck(_ initAck: SCTPInitChunk) {
        assocState.withLock { s in
            s.remoteVerificationTag = initAck.initiateTag
            s.state = .cookieEchoed
        }
    }

    private func generateCookieEcho() -> SCTPPacket {
        let (localPort, remotePort, remoteTag) = assocState.withLock { s in
            (s.localPort, s.remotePort, s.remoteVerificationTag)
        }
        let chunk = SCTPChunk(chunkType: SCTPChunkType.cookieEcho.rawValue, value: Data(repeating: 0xCC, count: 4))
        return SCTPPacket(
            sourcePort: localPort,
            destinationPort: remotePort,
            verificationTag: remoteTag,
            chunks: [chunk]
        )
    }

    private func handleCookieEcho(_ chunk: SCTPChunk) -> SCTPPacket {
        let (localPort, remotePort, remoteTag) = assocState.withLock { s in
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

    private func generateSack(tsn: UInt32) -> SCTPPacket {
        let (localPort, remotePort, remoteTag) = assocState.withLock { s -> (UInt16, UInt16, UInt32) in
            s.lastReceivedTSN = tsn
            return (s.localPort, s.remotePort, s.remoteVerificationTag)
        }

        let sack = SCTPSackChunk(cumulativeTSNAck: tsn)
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
}
