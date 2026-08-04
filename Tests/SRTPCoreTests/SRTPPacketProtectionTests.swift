import Testing
@testable import WebRTC
@Suite("SRTP packet protection")
struct SRTPPacketProtectionTests {
    @Test("libSRTP AES-CM/HMAC-SHA1-80 reference packet matches byte for byte")
    func libSRTPReferencePacket() throws {
        // cisco/libsrtp@2fc078db25bae61ed0a52dc4fdb7dcce6a6ed037
        // `test/srtp_driver.c` `srtp_validate` is an independent implementation
        // fixture using the RFC 3711 default profile.
        let material = try SRTPMasterKeyMaterial(
            masterKey: fixtureBytes("e1f97a0d3e018be0d64fa32c06de4139"),
            masterSalt: fixtureBytes("0ec675ad498afeebb6960b3aabe6")
        )
        let sender = try TestSRTPContext(
            outbound: material,
            inbound: material,
            crypto: defaultSRTPCryptoContext()
        )
        let receiver = try TestSRTPContext(
            outbound: material,
            inbound: material,
            crypto: defaultSRTPCryptoContext()
        )
        let plaintext = try fixtureBytes(
            "800f1234decafbadcafebabeabababababababababababababababab"
        )
        let ciphertext = try fixtureBytes(
            "800f1234decafbadcafebabe4e55dc4ce79978d88ca4d215949d2402"
                + "b78d6acc99ea179b8dbb"
        )

        var protected = plaintext
        try sender.protectRTP(&protected)
        #expect(protected == ciphertext)

        var received = ciphertext
        try receiver.unprotectRTP(&received)
        #expect(received == plaintext)
    }

    @Test("RTP round trip encrypts only payload bytes and removes the tag")
    func roundTripAndHeaderBoundary() throws {
        let context = try testContext()
        let plaintext: [UInt8] = [
            0x91, 0x60, 0x00, 0x01,
            0x01, 0x02, 0x03, 0x04,
            0x11, 0x22, 0x33, 0x44,
            0xAA, 0xBB, 0xCC, 0xDD,
            0xBE, 0xDE, 0x00, 0x01,
            0x10, 0x20, 0x30, 0x40,
            0x50, 0x60, 0x70, 0x80,
        ]
        var protected = plaintext

        try context.protectRTP(&protected)

        #expect(Array(protected[0..<24]) == Array(plaintext[0..<24]))
        #expect(Array(protected[24..<plaintext.count]) != Array(plaintext[24..<plaintext.count]))
        #expect(protected.count == plaintext.count + 10)

        try context.unprotectRTP(&protected)
        #expect(protected == plaintext)
    }

    @Test("Tampering fails authentication without advancing replay state")
    func tamperDoesNotAdvanceState() throws {
        let sender = try testContext()
        let receiver = try testContext()
        let plaintext = rtpPacket(sequenceNumber: 7)
        var protected = plaintext
        try sender.protectRTP(&protected)

        var tampered = protected
        tampered[tampered.count - 1] ^= 0x01
        #expect(throws: SRTPError.authenticationFailure(kind: .rtp)) {
            try receiver.unprotectRTP(&tampered)
        }

        var authentic = protected
        try receiver.unprotectRTP(&authentic)
        #expect(authentic == plaintext)
    }

    @Test("A different inbound key fails closed")
    func wrongKey() throws {
        let sender = try testContext()
        let receiver = try testContext(inbound: testKeyMaterial(byteOffset: 1))
        var protected = rtpPacket(sequenceNumber: 8)
        try sender.protectRTP(&protected)

        #expect(throws: SRTPError.authenticationFailure(kind: .rtp)) {
            try receiver.unprotectRTP(&protected)
        }
    }

    @Test("Packets shorter than the fixed header and tag are rejected")
    func truncatedTag() throws {
        let context = try testContext()
        var packet = [UInt8](repeating: 0, count: 21)

        #expect(throws: SRTPError.packetTooShort(kind: .rtp, minimum: 22, actual: 21)) {
            try context.unprotectRTP(&packet)
        }
    }

    @Test("RTP padding is encrypted with the payload and restored on receipt")
    func paddingRoundTrip() throws {
        let context = try testContext()
        let plaintext: [UInt8] = [
            0xA0, 0x60, 0x00, 0x09,
            0x01, 0x02, 0x03, 0x04,
            0x11, 0x22, 0x33, 0x44,
            0x55, 0x00, 0x00, 0x03,
        ]
        var protected = plaintext

        try context.protectRTP(&protected)
        #expect(Array(protected[12..<16]) != Array(plaintext[12..<16]))

        try context.unprotectRTP(&protected)
        #expect(protected == plaintext)
    }

    @Test("ROC wraps once while a protected retransmission is rejected")
    func rolloverAndOutboundReuse() throws {
        let sender = try testContext()
        let receiver = try testContext()
        let lastPlaintext = rtpPacket(sequenceNumber: UInt16.max)
        let wrappedPlaintext = rtpPacket(sequenceNumber: 0)
        var last = lastPlaintext
        var wrapped = wrappedPlaintext

        try sender.protectRTP(&last)
        try sender.protectRTP(&wrapped)
        try receiver.unprotectRTP(&last)
        try receiver.unprotectRTP(&wrapped)

        #expect(last == lastPlaintext)
        #expect(wrapped == wrappedPlaintext)

        var duplicatePlaintext = wrappedPlaintext
        #expect(throws: SRTPError.outboundIndexReuse(
            synchronizationSource: 0x1122_3344,
            index: 0x1_0000
        )) {
            try sender.protectRTP(&duplicatePlaintext)
        }
    }

    @Test("Replay and packets older than the 64-entry window are distinct failures")
    func replayWindow() throws {
        let sender = try testContext()
        let receiver = try testContext()
        var packets = [[UInt8]]()
        for sequenceNumber in UInt16(0)...UInt16(65) {
            var packet = rtpPacket(sequenceNumber: sequenceNumber)
            try sender.protectRTP(&packet)
            packets.append(packet)
        }

        var newest = packets[65]
        try receiver.unprotectRTP(&newest)

        var replay = packets[65]
        #expect(throws: SRTPError.replayedPacket(
            kind: .rtp,
            synchronizationSource: 0x1122_3344,
            index: 65
        )) {
            try receiver.unprotectRTP(&replay)
        }

        var tooOld = packets[0]
        #expect(throws: SRTPError.packetTooOld(
            kind: .rtp,
            synchronizationSource: 0x1122_3344,
            index: 0
        )) {
            try receiver.unprotectRTP(&tooOld)
        }
    }

    @Test("The same index under distinct SSRC values uses distinct keystream")
    func multipleSynchronizationSources() throws {
        let sender = try testContext()
        var first = rtpPacket(sequenceNumber: 1, synchronizationSource: 1)
        var second = rtpPacket(sequenceNumber: 1, synchronizationSource: 2)

        try sender.protectRTP(&first)
        try sender.protectRTP(&second)

        #expect(Array(first[12..<16]) != Array(second[12..<16]))
    }

    @Test("A provider failure after mutation burns the outbound RTP index")
    func providerFailureBurnsIndex() throws {
        let material = try testKeyMaterial()
        let context = try MutatingFailureSRTPContext(
            outbound: material,
            inbound: material,
            crypto: mutatingFailureSRTPCryptoContext()
        )
        let plaintext = rtpPacket(sequenceNumber: 22)
        var firstAttempt = plaintext

        #expect(throws: SRTPError.counterMode(.providerFailure)) {
            try context.protectRTP(&firstAttempt)
        }
        #expect(firstAttempt != plaintext)

        var secondAttempt = plaintext
        #expect(throws: SRTPError.outboundIndexReuse(
            synchronizationSource: 0x1122_3344,
            index: 22
        )) {
            try context.protectRTP(&secondAttempt)
        }
    }

    @Test("RTP rejects more than 2^16 AES-CM blocks before reserving an index")
    func encryptedPortionLimit() throws {
        let context = try testContext()
        let oversizedByteCount = TestSRTPContext.maximumEncryptedByteCount + 1
        var packet = rtpPacket(
            sequenceNumber: 23,
            payload: [UInt8](repeating: 0xA5, count: oversizedByteCount)
        )

        #expect(throws: SRTPError.encryptedPortionTooLarge(
            kind: .rtp,
            maximum: TestSRTPContext.maximumEncryptedByteCount,
            actual: oversizedByteCount
        )) {
            try context.protectRTP(&packet)
        }
        packet.append(contentsOf: repeatElement(
            0,
            count: TestSRTPContext.authenticationTagByteCount
        ))
        #expect(throws: SRTPError.encryptedPortionTooLarge(
            kind: .rtp,
            maximum: TestSRTPContext.maximumEncryptedByteCount,
            actual: oversizedByteCount
        )) {
            try context.unprotectRTP(&packet)
        }

        var maximum = rtpPacket(
            sequenceNumber: 23,
            payload: [UInt8](
                repeating: 0x5A,
                count: TestSRTPContext.maximumEncryptedByteCount
            )
        )
        try context.protectRTP(&maximum)
        #expect(maximum.count == 12 + TestSRTPContext.maximumEncryptedByteCount + 10)
        try context.unprotectRTP(&maximum)
        #expect(maximum.count == 12 + TestSRTPContext.maximumEncryptedByteCount)
        #expect(maximum[12] == 0x5A)
        #expect(maximum[maximum.count - 1] == 0x5A)
    }

    @Test("Packets reordered across an ROC transition use the prior epoch")
    func reorderedPreviousEpochAfterRollover() throws {
        let sender = try testContext()
        let receiver = try testContext()
        var packets: [UInt16: [UInt8]] = [:]
        for sequenceNumber in [UInt16(65_534), 65_535, 0, 1] {
            var packet = rtpPacket(sequenceNumber: sequenceNumber)
            try sender.protectRTP(&packet)
            packets[sequenceNumber] = packet
        }

        for sequenceNumber in [UInt16(65_535), 1, 65_534] {
            var packet = try #require(packets[sequenceNumber])
            try receiver.unprotectRTP(&packet)
            #expect(packet == rtpPacket(sequenceNumber: sequenceNumber))
        }
    }

    @Test("Reserved SRTP trailer capacity preserves caller packet storage")
    func reservedTrailerCapacityPreservesStorage() throws {
        let context = try testContext()
        var packet = rtpPacket(sequenceNumber: 24)
        packet.reserveCapacity(packet.count + TestSRTPContext.authenticationTagByteCount)
        let addressBeforeProtection = storageAddress(of: &packet)

        try context.protectRTP(&packet)

        #expect(storageAddress(of: &packet) == addressBeforeProtection)
    }
}
