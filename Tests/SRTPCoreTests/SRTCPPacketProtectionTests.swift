import P2PCoreCrypto
import P2PCrypto
import Testing
@testable import WebRTC
@Suite("SRTCP packet protection")
struct SRTCPPacketProtectionTests {
    @Test("SRTCP round trip keeps the first eight bytes clear and carries E plus index")
    func roundTrip() throws {
        let context = try testContext()
        let plaintext = rtcpPictureLossIndication()
        var protected = plaintext

        try context.protectRTCP(&protected)

        #expect(Array(protected[0..<8]) == Array(plaintext[0..<8]))
        #expect(Array(protected[8..<12]) != Array(plaintext[8..<12]))
        #expect(Array(protected[12..<16]) == [0x80, 0x00, 0x00, 0x00])
        #expect(protected.count == plaintext.count + 14)

        try context.unprotectRTCP(&protected)
        #expect(protected == plaintext)
    }

    @Test("SRTCP tampering fails without consuming the authenticated index")
    func tamperDoesNotAdvanceState() throws {
        let sender = try testContext()
        let receiver = try testContext()
        let plaintext = rtcpPictureLossIndication()
        var protected = plaintext
        try sender.protectRTCP(&protected)

        var tampered = protected
        tampered[8] ^= 0x01
        #expect(throws: SRTPError.authenticationFailure(kind: .rtcp)) {
            try receiver.unprotectRTCP(&tampered)
        }

        var authentic = protected
        try receiver.unprotectRTCP(&authentic)
        #expect(authentic == plaintext)
    }

    @Test("An authenticated SRTCP packet cannot be accepted twice")
    func replay() throws {
        let sender = try testContext()
        let receiver = try testContext()
        var protected = rtcpPictureLossIndication()
        try sender.protectRTCP(&protected)
        var first = protected
        var second = protected

        try receiver.unprotectRTCP(&first)
        #expect(throws: SRTPError.replayedPacket(
            kind: .rtcp,
            synchronizationSource: 0x1122_3344,
            index: 0
        )) {
            try receiver.unprotectRTCP(&second)
        }
    }

    @Test("SRTCP index exhaustion fails before reusing index zero")
    func indexExhaustion() throws {
        var state = SRTPState()
        state.outboundRTCP[7] = OutboundSRTCPState(
            nextIndex: OutboundSRTCPState.maximumIndex,
            highestCommittedIndex: OutboundSRTCPState.maximumIndex - 1,
            pendingIndices: []
        )

        let finalIndex = try state.reserveOutboundRTCP(synchronizationSource: 7)
        #expect(finalIndex == OutboundSRTCPState.maximumIndex)
        try state.commitOutboundRTCP(synchronizationSource: 7, index: finalIndex)
        #expect(throws: SRTPError.indexExhausted(kind: .rtcp, synchronizationSource: 7)) {
            try state.reserveOutboundRTCP(synchronizationSource: 7)
        }
    }

    @Test("An SRTCP packet without the encrypted flag is rejected after authentication")
    func encryptionRequired() throws {
        let material = try testKeyMaterial()
        let sender = try testContext(outbound: material)
        let receiver = try testContext(inbound: material)
        var protected = rtcpPictureLossIndication()
        try sender.protectRTCP(&protected)

        let authenticatedByteCount = protected.count - 10
        protected[12] &= 0x7F
        let keys = try deriveSessionKeys(
            from: material,
            crypto: defaultSRTPCryptoContext()
        )
        var authenticator = DefaultCryptoProvider.HMACSHA1(
            key: keys.rtcpAuthenticationKey.span
        )
        authenticator.update(protected.span.extracting(0..<authenticatedByteCount))
        let digest = authenticator.finalize()
        protected.replaceSubrange(
            authenticatedByteCount..<protected.count,
            with: digest.prefix(10)
        )

        #expect(throws: SRTPError.unencryptedSRTCPRejected) {
            try receiver.unprotectRTCP(&protected)
        }
        #expect(throws: SRTPError.replayedPacket(
            kind: .rtcp,
            synchronizationSource: 0x1122_3344,
            index: 0
        )) {
            try receiver.unprotectRTCP(&protected)
        }
    }

    @Test("A provider failure burns an SRTCP index and the next packet advances")
    func providerFailureBurnsIndex() throws {
        let material = try testKeyMaterial()
        let sender = try MutatingFailureSRTPContext(
            outbound: material,
            inbound: material,
            crypto: mutatingFailureSRTPCryptoContext()
        )
        let receiver = try testContext(inbound: material)
        let plaintext = rtcpPictureLossIndication()
        var firstAttempt = plaintext

        #expect(throws: SRTPError.counterMode(.providerFailure)) {
            try sender.protectRTCP(&firstAttempt)
        }
        #expect(firstAttempt != plaintext)

        var secondAttempt = plaintext
        try sender.protectRTCP(&secondAttempt)
        #expect(Array(secondAttempt[plaintext.count..<(plaintext.count + 4)]) == [
            0x80, 0x00, 0x00, 0x01,
        ])
        try receiver.unprotectRTCP(&secondAttempt)
        #expect(secondAttempt == plaintext)
    }

    @Test("Inbound provider failure consumes authenticated replay state")
    func inboundProviderFailureConsumesReplayState() throws {
        let material = try testKeyMaterial()
        let sender = try testContext(outbound: material)
        let receiver = try MutatingFailureSRTPContext(
            outbound: material,
            inbound: material,
            crypto: mutatingFailureSRTPCryptoContext()
        )
        var protected = rtcpPictureLossIndication()
        try sender.protectRTCP(&protected)
        let protectedPacket = protected

        #expect(throws: SRTPError.counterMode(.providerFailure)) {
            try receiver.unprotectRTCP(&protected)
        }
        #expect(protected != protectedPacket)

        var retry = protectedPacket
        #expect(throws: SRTPError.replayedPacket(
            kind: .rtcp,
            synchronizationSource: 0x1122_3344,
            index: 0
        )) {
            try receiver.unprotectRTCP(&retry)
        }
    }

    @Test("SRTCP rejects more than 2^16 AES-CM blocks before reserving an index")
    func encryptedPortionLimit() throws {
        let context = try testContext()
        let oversizedByteCount = TestSRTPContext.maximumEncryptedByteCount + 1
        var packet = [UInt8](repeating: 0, count: 8 + oversizedByteCount)

        #expect(throws: SRTPError.encryptedPortionTooLarge(
            kind: .rtcp,
            maximum: TestSRTPContext.maximumEncryptedByteCount,
            actual: oversizedByteCount
        )) {
            try context.protectRTCP(&packet)
        }
        packet.append(contentsOf: repeatElement(
            0,
            count: TestSRTPContext.srtcpIndexByteCount
                + TestSRTPContext.authenticationTagByteCount
        ))
        packet[8 + oversizedByteCount] = 0x80
        #expect(throws: SRTPError.encryptedPortionTooLarge(
            kind: .rtcp,
            maximum: TestSRTPContext.maximumEncryptedByteCount,
            actual: oversizedByteCount
        )) {
            try context.unprotectRTCP(&packet)
        }

        var maximum = maximumEncryptedRTCPDatagram()
        let plaintextByteCount = maximum.count
        try context.protectRTCP(&maximum)
        #expect(maximum.count == plaintextByteCount + 14)
        #expect(Array(maximum[plaintextByteCount..<(plaintextByteCount + 4)]) == [
            0x80, 0x00, 0x00, 0x00,
        ])
        try context.unprotectRTCP(&maximum)
        #expect(maximum.count == plaintextByteCount)
        #expect(maximum[maximum.count - 1] == 0)
    }

    @Test("Oversized authenticated E=0 commits replay state before policy rejection")
    func oversizedUnencryptedPacketCommitsReplay() throws {
        let material = try testKeyMaterial()
        let receiver = try testContext(inbound: material)
        var packet = [UInt8](
            repeating: 0,
            count: 8 + TestSRTPContext.maximumEncryptedByteCount + 1
        )
        packet.replaceSubrange(0..<8, with: [
            0x80, 210, 0x00, 0x01,
            0x11, 0x22, 0x33, 0x44,
        ])
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        let keys = try deriveSessionKeys(
            from: material,
            crypto: defaultSRTPCryptoContext()
        )
        var authenticator = DefaultCryptoProvider.HMACSHA1(
            key: keys.rtcpAuthenticationKey.span
        )
        authenticator.update(packet.span)
        packet.append(contentsOf: authenticator.finalize().prefix(10))

        #expect(throws: SRTPError.unencryptedSRTCPRejected) {
            try receiver.unprotectRTCP(&packet)
        }
        #expect(throws: SRTPError.replayedPacket(
            kind: .rtcp,
            synchronizationSource: 0x1122_3344,
            index: 0
        )) {
            try receiver.unprotectRTCP(&packet)
        }
    }

    @Test("Concurrent outbound SRTCP assigns unique interoperable indices")
    func concurrentOutboundIndices() async throws {
        let sender = try testContext()
        let receiver = try testContext()
        let plaintext = rtcpPictureLossIndication()

        let outcomes: [ConcurrentProtectedPacketOutcome] = await withTaskGroup(
            of: ConcurrentProtectedPacketOutcome.self
        ) { group in
            for _ in 0..<16 {
                group.addTask {
                    var packet = plaintext
                    do {
                        try sender.protectRTCP(&packet)
                        return .packet(packet)
                    } catch let error as SRTPError {
                        return .failure(error)
                    } catch {
                        return .unexpectedFailure
                    }
                }
            }
            var results: [ConcurrentProtectedPacketOutcome] = []
            for await outcome in group {
                results.append(outcome)
            }
            return results
        }

        let packets = outcomes.compactMap { outcome -> [UInt8]? in
            guard case let .packet(packet) = outcome else { return nil }
            return packet
        }
        #expect(packets.count == 16)
        #expect(!outcomes.contains(.unexpectedFailure))
        #expect(!outcomes.contains { outcome in
            if case .failure = outcome { return true }
            return false
        })

        var indices = Set<UInt32>()
        for protectedPacket in packets {
            let indexWord = readUInt32(protectedPacket.span, at: plaintext.count)
            indices.insert(indexWord & 0x7FFF_FFFF)
            var received = protectedPacket
            try receiver.unprotectRTCP(&received)
            #expect(received == plaintext)
        }
        #expect(indices == Set(UInt32(0)..<UInt32(16)))
    }

    @Test("Reserved SRTCP trailer capacity preserves caller packet storage")
    func reservedTrailerCapacityPreservesStorage() throws {
        let context = try testContext()
        var packet = rtcpPictureLossIndication()
        packet.reserveCapacity(
            packet.count
                + TestSRTPContext.srtcpIndexByteCount
                + TestSRTPContext.authenticationTagByteCount
        )
        let addressBeforeProtection = storageAddress(of: &packet)

        try context.protectRTCP(&packet)

        #expect(storageAddress(of: &packet) == addressBeforeProtection)
    }
}
