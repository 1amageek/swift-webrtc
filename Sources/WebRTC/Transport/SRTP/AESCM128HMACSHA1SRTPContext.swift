import P2PCoreCrypto
import Synchronization

/// RFC 3711 AES_CM_128_HMAC_SHA1_80 protection with per-SSRC replay state.
///
/// The context owns independent outbound and inbound session keys. Mutable
/// packet-index and replay state uses the same `Mutex<SRTPState>` storage and
/// isolation contract on Native, WASM, and Embedded builds. Crypto executes
/// outside the lock; a short reservation prevents concurrent nonce reuse or
/// duplicate acceptance for the same SSRC and packet index.
final class AESCM128HMACSHA1SRTPContext: SRTPPacketProtecting, Sendable {
    static var authenticationTagByteCount: Int { 10 }
    static var srtcpIndexByteCount: Int { 4 }
    static var maximumEncryptedByteCount: Int { 65_536 * 16 }

    private let outboundKeys: SRTPDirectionalSessionKeys
    private let inboundKeys: SRTPDirectionalSessionKeys
    private let crypto: SRTPCryptoContext
    private let state = Mutex(SRTPState())
    private let rtpParser = RFC3550RTPPacketParser()
    private let rtcpParser = RFC3550RTCPDatagramParser()

    init(
        outbound: SRTPMasterKeyMaterial,
        inbound: SRTPMasterKeyMaterial,
        crypto: SRTPCryptoContext
    ) throws(SRTPError) {
        guard crypto.hmacSHA1ByteCount >= Self.authenticationTagByteCount else {
            throw .invalidAuthenticationTagLength(
                expectedAtLeast: Self.authenticationTagByteCount,
                actual: crypto.hmacSHA1ByteCount
            )
        }
        do {
            self.outboundKeys = try deriveSessionKeys(from: outbound, crypto: crypto)
            self.inboundKeys = try deriveSessionKeys(from: inbound, crypto: crypto)
            self.crypto = crypto
        } catch {
            throw .counterMode(error)
        }
    }

    func protectRTP(_ packet: inout [UInt8]) throws(SRTPError) {
        let layout: RTPPacketLayout
        do {
            layout = try rtpParser.layout(in: packet.span)
        } catch {
            throw .malformedRTP(error)
        }

        let encryptedRange = layout.payloadRange.lowerBound..<packet.count
        guard encryptedRange.count <= Self.maximumEncryptedByteCount else {
            throw .encryptedPortionTooLarge(
                kind: .rtp,
                maximum: Self.maximumEncryptedByteCount,
                actual: encryptedRange.count
            )
        }
        let synchronizationSource = layout.fixedHeader.synchronizationSource
        let index = try state.withLock { state throws(SRTPError) in
            try state.reserveOutboundRTP(
                synchronizationSource: synchronizationSource,
                sequenceNumber: layout.fixedHeader.sequenceNumber
            )
        }
        let counter = srtpInitialCounter(
            salt: outboundKeys.rtpSalt,
            synchronizationSource: synchronizationSource,
            packetIndex: index
        )

        do {
            try outboundKeys.rtpCipher.applyKeystream(
                to: &packet,
                range: encryptedRange,
                initialCounter: counter
            )
        } catch {
            let didBurn = state.withLock {
                $0.burnOutboundRTP(
                    synchronizationSource: synchronizationSource,
                    index: index
                )
            }
            guard didBurn else {
                throw .stateReservationLost(
                    kind: .rtp,
                    synchronizationSource: synchronizationSource,
                    index: index
                )
            }
            throw .counterMode(error)
        }

        let rolloverCounter = UInt32(index >> 16)
        let digest = crypto.authenticationCodeSHA1(
            message: packet,
            authenticatedRange: packet.indices,
            suffix: networkOrderBytes(rolloverCounter),
            key: outboundKeys.rtpAuthenticationKey,
        )
        guard digest.count >= Self.authenticationTagByteCount else {
            let didBurn = state.withLock {
                $0.burnOutboundRTP(
                    synchronizationSource: synchronizationSource,
                    index: index
                )
            }
            guard didBurn else {
                throw .stateReservationLost(
                    kind: .rtp,
                    synchronizationSource: synchronizationSource,
                    index: index
                )
            }
            throw .invalidAuthenticationTagLength(
                expectedAtLeast: Self.authenticationTagByteCount,
                actual: digest.count
            )
        }

        try state.withLock { state throws(SRTPError) in
            try state.commitOutboundRTP(
                synchronizationSource: synchronizationSource,
                index: index
            )
        }
        packet.append(contentsOf: digest.prefix(Self.authenticationTagByteCount))
    }

    func unprotectRTP(_ packet: inout [UInt8]) throws(SRTPError) {
        let minimumByteCount = 12 + Self.authenticationTagByteCount
        guard packet.count >= minimumByteCount else {
            throw .packetTooShort(kind: .rtp, minimum: minimumByteCount, actual: packet.count)
        }

        let encryptedPacketByteCount = packet.count - Self.authenticationTagByteCount
        let header = try encryptedRTPHeader(
            in: packet.span.extracting(0..<encryptedPacketByteCount)
        )
        let encryptedByteCount = encryptedPacketByteCount - header.payloadOffset
        guard encryptedByteCount <= Self.maximumEncryptedByteCount else {
            throw .encryptedPortionTooLarge(
                kind: .rtp,
                maximum: Self.maximumEncryptedByteCount,
                actual: encryptedByteCount
            )
        }
        let index = try state.withLock { state throws(SRTPError) in
            try state.reserveInboundRTP(
                synchronizationSource: header.synchronizationSource,
                sequenceNumber: header.sequenceNumber
            )
        }

        let rolloverCounter = UInt32(index >> 16)
        let digest = crypto.authenticationCodeSHA1(
            message: packet,
            authenticatedRange: 0..<encryptedPacketByteCount,
            suffix: networkOrderBytes(rolloverCounter),
            key: inboundKeys.rtpAuthenticationKey,
        )
        let isAuthentic = authenticationTagMatches(
            expectedDigest: digest,
            packet: packet.span,
            authenticatedByteCount: encryptedPacketByteCount,
            tagByteCount: Self.authenticationTagByteCount
        )
        guard isAuthentic else {
            state.withLock {
                $0.cancelInbound(
                    kind: .rtp,
                    synchronizationSource: header.synchronizationSource,
                    index: index
                )
            }
            throw .authenticationFailure(kind: .rtp)
        }

        try state.withLock { state throws(SRTPError) in
            try state.commitInbound(
                kind: .rtp,
                synchronizationSource: header.synchronizationSource,
                index: index
            )
        }

        let counter = srtpInitialCounter(
            salt: inboundKeys.rtpSalt,
            synchronizationSource: header.synchronizationSource,
            packetIndex: index
        )
        do {
            try inboundKeys.rtpCipher.applyKeystream(
                to: &packet,
                range: header.payloadOffset..<encryptedPacketByteCount,
                initialCounter: counter
            )
        } catch {
            throw .counterMode(error)
        }

        do {
            _ = try rtpParser.layout(
                in: packet.span.extracting(0..<encryptedPacketByteCount)
            )
        } catch {
            throw .malformedRTP(error)
        }
        packet.removeLast(Self.authenticationTagByteCount)
    }

    func protectRTCP(_ packet: inout [UInt8]) throws(SRTPError) {
        guard packet.count >= 8 else {
            throw .packetTooShort(kind: .rtcp, minimum: 8, actual: packet.count)
        }
        let plaintextByteCount = packet.count
        let encryptedByteCount = plaintextByteCount - 8
        guard encryptedByteCount <= Self.maximumEncryptedByteCount else {
            throw .encryptedPortionTooLarge(
                kind: .rtcp,
                maximum: Self.maximumEncryptedByteCount,
                actual: encryptedByteCount
            )
        }
        do {
            _ = try rtcpParser.layout(in: packet.span, framing: .reducedSize)
        } catch {
            throw .malformedRTCP(error)
        }

        let synchronizationSource = readUInt32(packet.span, at: 4)
        let index = try state.withLock { state throws(SRTPError) in
            try state.reserveOutboundRTCP(synchronizationSource: synchronizationSource)
        }
        let counter = srtpInitialCounter(
            salt: outboundKeys.rtcpSalt,
            synchronizationSource: synchronizationSource,
            packetIndex: UInt64(index)
        )

        do {
            try outboundKeys.rtcpCipher.applyKeystream(
                to: &packet,
                range: 8..<plaintextByteCount,
                initialCounter: counter
            )
        } catch {
            let didBurn = state.withLock {
                $0.burnOutboundRTCP(
                    synchronizationSource: synchronizationSource,
                    index: index
                )
            }
            guard didBurn else {
                throw .stateReservationLost(
                    kind: .rtcp,
                    synchronizationSource: synchronizationSource,
                    index: UInt64(index)
                )
            }
            throw .counterMode(error)
        }

        let indexWord = index | 0x8000_0000
        packet.append(contentsOf: networkOrderBytes(indexWord))
        let digest = crypto.authenticationCodeSHA1(
            message: packet,
            authenticatedRange: packet.indices,
            suffix: nil,
            key: outboundKeys.rtcpAuthenticationKey,
        )
        guard digest.count >= Self.authenticationTagByteCount else {
            let didBurn = state.withLock {
                $0.burnOutboundRTCP(
                    synchronizationSource: synchronizationSource,
                    index: index
                )
            }
            guard didBurn else {
                throw .stateReservationLost(
                    kind: .rtcp,
                    synchronizationSource: synchronizationSource,
                    index: UInt64(index)
                )
            }
            throw .invalidAuthenticationTagLength(
                expectedAtLeast: Self.authenticationTagByteCount,
                actual: digest.count
            )
        }

        try state.withLock { state throws(SRTPError) in
            try state.commitOutboundRTCP(
                synchronizationSource: synchronizationSource,
                index: index
            )
        }
        packet.append(contentsOf: digest.prefix(Self.authenticationTagByteCount))
    }

    func unprotectRTCP(_ packet: inout [UInt8]) throws(SRTPError) {
        let trailerByteCount = Self.srtcpIndexByteCount + Self.authenticationTagByteCount
        let minimumByteCount = 8 + trailerByteCount
        guard packet.count >= minimumByteCount else {
            throw .packetTooShort(kind: .rtcp, minimum: minimumByteCount, actual: packet.count)
        }

        let authenticatedByteCount = packet.count - Self.authenticationTagByteCount
        let plaintextByteCount = authenticatedByteCount - Self.srtcpIndexByteCount
        let indexWord = readUInt32(packet.span, at: plaintextByteCount)
        let isEncrypted = indexWord & 0x8000_0000 != 0
        let index = indexWord & 0x7FFF_FFFF
        let encryptedByteCount = plaintextByteCount - 8
        if isEncrypted, encryptedByteCount > Self.maximumEncryptedByteCount {
            throw .encryptedPortionTooLarge(
                kind: .rtcp,
                maximum: Self.maximumEncryptedByteCount,
                actual: encryptedByteCount
            )
        }
        let synchronizationSource = try validateSRTCPClearPrefix(
            packet.span.extracting(0..<plaintextByteCount)
        )

        try state.withLock { state throws(SRTPError) in
            try state.reserveInboundRTCP(
                synchronizationSource: synchronizationSource,
                index: index
            )
        }

        let digest = crypto.authenticationCodeSHA1(
            message: packet,
            authenticatedRange: 0..<authenticatedByteCount,
            suffix: nil,
            key: inboundKeys.rtcpAuthenticationKey,
        )
        let isAuthentic = authenticationTagMatches(
            expectedDigest: digest,
            packet: packet.span,
            authenticatedByteCount: authenticatedByteCount,
            tagByteCount: Self.authenticationTagByteCount
        )
        guard isAuthentic else {
            state.withLock {
                $0.cancelInbound(
                    kind: .rtcp,
                    synchronizationSource: synchronizationSource,
                    index: UInt64(index)
                )
            }
            throw .authenticationFailure(kind: .rtcp)
        }
        try state.withLock { state throws(SRTPError) in
            try state.commitInbound(
                kind: .rtcp,
                synchronizationSource: synchronizationSource,
                index: UInt64(index)
            )
        }
        guard isEncrypted else {
            throw .unencryptedSRTCPRejected
        }

        let counter = srtpInitialCounter(
            salt: inboundKeys.rtcpSalt,
            synchronizationSource: synchronizationSource,
            packetIndex: UInt64(index)
        )
        do {
            try inboundKeys.rtcpCipher.applyKeystream(
                to: &packet,
                range: 8..<plaintextByteCount,
                initialCounter: counter
            )
        } catch {
            throw .counterMode(error)
        }

        do {
            _ = try rtcpParser.layout(
                in: packet.span.extracting(0..<plaintextByteCount),
                framing: .reducedSize
            )
        } catch {
            throw .malformedRTCP(error)
        }
        packet.removeLast(trailerByteCount)
    }
}

private func authenticationTagMatches(
    expectedDigest: [UInt8],
    packet: Span<UInt8>,
    authenticatedByteCount: Int,
    tagByteCount: Int
) -> Bool {
    let receivedTag = packet.extracting(
        authenticatedByteCount..<(authenticatedByteCount + tagByteCount)
    )
    return constantTimeTagMatches(
        expectedDigest: expectedDigest,
        receivedTag: receivedTag,
        tagByteCount: tagByteCount
    )
}

private func validateSRTCPClearPrefix(_ packet: Span<UInt8>) throws(SRTPError) -> UInt32 {
    guard packet.count >= 8 else {
        throw .packetTooShort(kind: .rtcp, minimum: 8, actual: packet.count)
    }
    let version = packet[0] >> 6
    guard version == 2 else {
        throw .malformedRTCP(.invalidVersion(actual: version))
    }
    let declaredByteCount = (Int(readUInt16(packet, at: 2)) + 1) * 4
    guard declaredByteCount >= 8 else {
        throw .malformedRTCP(.insufficientBytes(
            field: .rtcpPacket,
            required: 8,
            available: declaredByteCount
        ))
    }
    guard declaredByteCount <= packet.count else {
        throw .malformedRTCP(.invalidRTCPPacketLength(
            packetIndex: 0,
            declaredBytes: declaredByteCount,
            availableBytes: packet.count
        ))
    }
    return readUInt32(packet, at: 4)
}
