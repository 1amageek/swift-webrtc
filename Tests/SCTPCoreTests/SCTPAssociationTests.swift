/// Regression tests for SCTP association packet processing,
/// retransmission, and reassembly limits.

import Testing
import Foundation
@testable import SCTPCore

@Suite("SCTP Association Tests")
struct SCTPAssociationTests {

    /// Run the full 4-way handshake between two associations
    private func establishPair() throws -> (client: SCTPAssociation, server: SCTPAssociation) {
        let client = SCTPAssociation()
        let server = SCTPAssociation()

        let initPacket = client.generateInit()
        let (initAckResponses, _) = try server.processPacket(initPacket)
        let initAck = try #require(initAckResponses.first)

        let (cookieEchoResponses, _) = try client.processPacket(initAck)
        let cookieEcho = try #require(cookieEchoResponses.first)

        let (cookieAckResponses, _) = try server.processPacket(cookieEcho)
        let cookieAck = try #require(cookieAckResponses.first)

        _ = try client.processPacket(cookieAck)
        return (client, server)
    }

    @Test("Full 4-way handshake establishes both sides")
    func fullHandshakeEstablishes() throws {
        let (client, server) = try establishPair()
        #expect(client.state == .established)
        #expect(server.state == .established)
    }

    @Test("Packet with wrong verification tag is rejected")
    func verificationTagMismatchThrows() throws {
        let (client, server) = try establishPair()

        let valid = client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: Data("hello".utf8)
        )
        let spoofed = SCTPPacket(
            sourcePort: valid.sourcePort,
            destinationPort: valid.destinationPort,
            verificationTag: valid.verificationTag &+ 1,
            chunks: valid.chunks
        )

        #expect(throws: SCTPError.self) {
            _ = try server.processPacket(spoofed)
        }
    }

    @Test("Packet carrying INIT must use verification tag 0")
    func initPacketRequiresZeroTag() throws {
        let server = SCTPAssociation()
        let initChunk = SCTPInitChunk(initiateTag: 0x1234, initialTSN: 1)
        let packet = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5000,
            verificationTag: 0xDEADBEEF,
            chunks: [initChunk.toChunk()]
        )

        #expect(throws: SCTPError.self) {
            _ = try server.processPacket(packet)
        }
    }

    @Test("ABORT closes the association and surfaces an error")
    func abortClosesAssociation() throws {
        let (client, server) = try establishPair()

        // Reuse a valid packet's tag so the ABORT passes tag validation
        let valid = client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: Data("x".utf8)
        )
        let abort = SCTPPacket(
            sourcePort: valid.sourcePort,
            destinationPort: valid.destinationPort,
            verificationTag: valid.verificationTag,
            chunks: [SCTPChunk(chunkType: SCTPChunkType.abort.rawValue, value: Data())]
        )

        #expect(throws: SCTPError.self) {
            _ = try server.processPacket(abort)
        }
        #expect(server.state == .closed)
    }

    @Test("Multiple DATA chunks in one packet produce exactly one SACK")
    func singleSackPerPacket() throws {
        let (client, server) = try establishPair()

        let p1 = client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("a".utf8))
        let p2 = client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("b".utf8))
        let bundled = SCTPPacket(
            sourcePort: p1.sourcePort,
            destinationPort: p1.destinationPort,
            verificationTag: p1.verificationTag,
            chunks: p1.chunks + p2.chunks
        )

        let (responses, received) = try server.processPacket(bundled)

        let sackCount = responses.reduce(0) { count, packet in
            count + packet.chunks.filter { $0.chunkType == SCTPChunkType.sack.rawValue }.count
        }
        #expect(sackCount == 1)
        #expect(received.count == 2)
        #expect(received[0].data == Data("a".utf8))
        #expect(received[1].data == Data("b".utf8))
    }

    @Test("SACK advertises a window reduced by buffered fragment bytes")
    func sackAdvertisesDynamicWindow() throws {
        let (client, server) = try establishPair()

        // Learn a valid TSN/tag by letting the client build a normal packet,
        // then replace its DATA chunk with a beginning-only fragment that
        // the server must hold in its reassembly buffer.
        let payload = Data(repeating: 0x42, count: 1000)
        let valid = client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: payload)
        let originalChunk = try #require(valid.chunks.first)
        let original = try SCTPDataChunk.decode(from: originalChunk.value, flags: originalChunk.flags)

        let fragment = SCTPDataChunk(
            tsn: original.tsn,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53,
            userData: payload,
            beginningFragment: true,
            endingFragment: false
        )
        let packet = SCTPPacket(
            sourcePort: valid.sourcePort,
            destinationPort: valid.destinationPort,
            verificationTag: valid.verificationTag,
            chunks: [fragment.toChunk()]
        )

        let (responses, received) = try server.processPacket(packet)
        #expect(received.isEmpty)

        let sackChunk = try #require(responses
            .flatMap(\.chunks)
            .first { $0.chunkType == SCTPChunkType.sack.rawValue })
        let sack = try SCTPSackChunk.decode(from: sackChunk.value)
        #expect(sack.advertisedReceiverWindowCredit == 65535 - 1000)
    }

    @Test("SACK acknowledgment clears the retransmission queue")
    func sackClearsRetransmissionQueue() throws {
        let (client, server) = try establishPair()

        let dataPacket = client.sendData(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: Data("payload".utf8)
        )
        #expect(client.hasUnacknowledgedData)

        let (responses, _) = try server.processPacket(dataPacket)
        let sack = try #require(responses.first)
        _ = try client.processPacket(sack)

        #expect(!client.hasUnacknowledgedData)
    }

    @Test("Unknown chunk with upper bits 00 stops packet processing")
    func unknownChunkStopAction() throws {
        let (client, server) = try establishPair()

        // Chunk type 0x3F: upper two bits 00 → stop processing this packet.
        // The DATA chunk bundled after it must NOT be processed (no SACK).
        let valid = client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("x".utf8))
        let unknown = SCTPChunk(chunkType: 0x3F, value: Data())
        let packet = SCTPPacket(
            sourcePort: valid.sourcePort,
            destinationPort: valid.destinationPort,
            verificationTag: valid.verificationTag,
            chunks: [unknown] + valid.chunks
        )

        let (responses, received) = try server.processPacket(packet)
        #expect(responses.isEmpty)
        #expect(received.isEmpty)
    }

    @Test("Unknown chunk with upper bits 11 is skipped, rest is processed")
    func unknownChunkSkipAction() throws {
        let (client, server) = try establishPair()

        // Chunk type 0xFF (not a recognized type): upper bits 11 → skip
        // the chunk and keep processing.
        let valid = client.sendData(streamID: 0, payloadProtocolIdentifier: 53, data: Data("x".utf8))
        let unknown = SCTPChunk(chunkType: 0xFF, value: Data())
        let packet = SCTPPacket(
            sourcePort: valid.sourcePort,
            destinationPort: valid.destinationPort,
            verificationTag: valid.verificationTag,
            chunks: [unknown] + valid.chunks
        )

        let (responses, received) = try server.processPacket(packet)
        #expect(received.count == 1)
        let sackCount = responses.reduce(0) { count, packet in
            count + packet.chunks.filter { $0.chunkType == SCTPChunkType.sack.rawValue }.count
        }
        #expect(sackCount == 1)
    }

    @Test("Local initiate tag is never zero")
    func initiateTagNonZero() {
        for _ in 0..<100 {
            #expect(SCTPSecureRandom.uint32NonZero() != 0)
        }
    }
}

@Suite("Retransmission Queue Tests")
struct RetransmissionQueueTests {

    private func makeChunk(tsn: UInt32) -> SCTPDataChunk {
        SCTPDataChunk(
            tsn: tsn,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53,
            userData: Data("payload".utf8)
        )
    }

    @Test("Three SACK miss indications trigger fast retransmit")
    func fastRetransmitAfterThreeMisses() {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now

        queue.enqueue(makeChunk(tsn: 10), sentTime: sentTime)
        queue.enqueue(makeChunk(tsn: 11), sentTime: sentTime)

        // TSN 11 is gap-acked (offset 2 from cumulative 9); TSN 10 is missing
        for _ in 0..<3 {
            _ = queue.acknowledge(cumulativeTSN: 9, gapBlocks: [(start: 2, end: 2)])
        }

        // RTO (3s) has not expired, so only the fast-retransmit-marked
        // chunk should be returned
        switch queue.pendingRetransmissions(now: sentTime + .milliseconds(100)) {
        case .success(let chunks):
            #expect(chunks.map(\.tsn) == [10])
        case .failure(let error):
            Issue.record("Unexpected failure: \(error)")
        }
    }

    @Test("Fewer than three miss indications do not retransmit")
    func noFastRetransmitBelowThreshold() {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now

        queue.enqueue(makeChunk(tsn: 10), sentTime: sentTime)
        queue.enqueue(makeChunk(tsn: 11), sentTime: sentTime)

        for _ in 0..<2 {
            _ = queue.acknowledge(cumulativeTSN: 9, gapBlocks: [(start: 2, end: 2)])
        }

        switch queue.pendingRetransmissions(now: sentTime + .milliseconds(100)) {
        case .success(let chunks):
            #expect(chunks.isEmpty)
        case .failure(let error):
            Issue.record("Unexpected failure: \(error)")
        }
    }

    @Test("Timer expiry retransmits and backs off RTO once per event")
    func timerExpiryBacksOffOnce() {
        var queue = RetransmissionQueue()
        let sentTime = ContinuousClock.now

        queue.enqueue(makeChunk(tsn: 10), sentTime: sentTime)
        queue.enqueue(makeChunk(tsn: 11), sentTime: sentTime)

        let initialRTO = queue.currentRTO
        switch queue.pendingRetransmissions(now: sentTime + initialRTO + .milliseconds(1)) {
        case .success(let chunks):
            #expect(chunks.map(\.tsn) == [10, 11])
            // One timeout event with two expired chunks doubles RTO once,
            // not once per chunk (RFC 4960 §6.3.3 E2)
            #expect(queue.currentRTO == initialRTO * 2)
        case .failure(let error):
            Issue.record("Unexpected failure: \(error)")
        }
    }
}

@Suite("Fragment Assembler Limit Tests")
struct FragmentAssemblerLimitTests {

    private func beginningFragment(tsn: UInt32, streamID: UInt16, seq: UInt16) -> SCTPDataChunk {
        SCTPDataChunk(
            tsn: tsn,
            streamIdentifier: streamID,
            streamSequenceNumber: seq,
            payloadProtocolIdentifier: 53,
            userData: Data("frag".utf8),
            beginningFragment: true,
            endingFragment: false
        )
    }

    @Test("Pending fragment group cap is enforced")
    func pendingGroupCapThrows() throws {
        var assembler = FragmentAssembler()

        // Fill to the cap with incomplete (beginning-only) groups.
        // Non-contiguous TSNs prevent accidental assembly.
        for i in 0..<1000 {
            _ = try assembler.process(
                chunk: beginningFragment(tsn: UInt32(i) * 2, streamID: 0, seq: UInt16(i % 65536))
            )
        }
        #expect(assembler.pendingCount == 1000)

        #expect(throws: SCTPError.self) {
            _ = try assembler.process(
                chunk: beginningFragment(tsn: 5000, streamID: 1, seq: 0)
            )
        }
    }

    @Test("Out-of-order unordered fragments still assemble")
    func outOfOrderUnorderedFragmentsAssemble() throws {
        var assembler = FragmentAssembler()
        let payload = Data("part".utf8)

        // Ending fragment arrives before the beginning fragment
        let end = SCTPDataChunk(
            tsn: 11, streamIdentifier: 0, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload,
            beginningFragment: false, endingFragment: true, unordered: true
        )
        let begin = SCTPDataChunk(
            tsn: 10, streamIdentifier: 0, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload,
            beginningFragment: true, endingFragment: false, unordered: true
        )

        let first = try assembler.process(chunk: end)
        #expect(first.isEmpty)

        let assembled = try assembler.process(chunk: begin)
        #expect(assembled.count == 1)
        #expect(assembled.first?.data == payload + payload)
    }

    @Test("bufferedBytes tracks incomplete fragments and drains on assembly")
    func bufferedBytesTracksFragments() throws {
        var assembler = FragmentAssembler()
        let payload = Data(repeating: 0xAB, count: 500)

        let begin = SCTPDataChunk(
            tsn: 10, streamIdentifier: 0, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload,
            beginningFragment: true, endingFragment: false
        )
        _ = try assembler.process(chunk: begin)
        #expect(assembler.bufferedBytes == 500)

        let end = SCTPDataChunk(
            tsn: 11, streamIdentifier: 0, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload,
            beginningFragment: false, endingFragment: true
        )
        let assembled = try assembler.process(chunk: end)
        #expect(assembled.count == 1)
        #expect(assembler.bufferedBytes == 0)
    }

    @Test("bufferedBytes tracks out-of-order messages and drains on delivery")
    func bufferedBytesTracksReorderBuffer() throws {
        var assembler = FragmentAssembler()
        let payload = Data(repeating: 0xCD, count: 300)

        // Sequence 1 arrives before expected sequence 0 — buffered
        _ = try assembler.process(chunk: SCTPDataChunk(
            tsn: 11, streamIdentifier: 0, streamSequenceNumber: 1,
            payloadProtocolIdentifier: 53, userData: payload
        ))
        #expect(assembler.bufferedBytes == 300)

        // Sequence 0 arrives — both deliver, buffer drains
        let delivered = try assembler.process(chunk: SCTPDataChunk(
            tsn: 10, streamIdentifier: 0, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload
        ))
        #expect(delivered.count == 2)
        #expect(assembler.bufferedBytes == 0)
    }

    @Test("resetStream releases buffered bytes")
    func resetStreamReleasesBufferedBytes() throws {
        var assembler = FragmentAssembler()
        let payload = Data(repeating: 0xEF, count: 400)

        _ = try assembler.process(chunk: SCTPDataChunk(
            tsn: 10, streamIdentifier: 7, streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53, userData: payload,
            beginningFragment: true, endingFragment: false
        ))
        _ = try assembler.process(chunk: SCTPDataChunk(
            tsn: 20, streamIdentifier: 7, streamSequenceNumber: 5,
            payloadProtocolIdentifier: 53, userData: payload
        ))
        #expect(assembler.bufferedBytes == 800)

        assembler.resetStream(7)
        #expect(assembler.bufferedBytes == 0)
    }

    @Test("Per-stream reorder buffer cap is enforced")
    func reorderBufferCapThrows() throws {
        var assembler = FragmentAssembler()

        // Stream expects sequence 0; sequences 1...1024 are all out of
        // order, filling the reorder buffer to its cap
        for seq in 1...1024 {
            _ = try assembler.process(chunk: SCTPDataChunk(
                tsn: UInt32(seq),
                streamIdentifier: 0,
                streamSequenceNumber: UInt16(seq),
                payloadProtocolIdentifier: 53,
                userData: Data("m".utf8)
            ))
        }

        #expect(throws: SCTPError.self) {
            _ = try assembler.process(chunk: SCTPDataChunk(
                tsn: 2000, streamIdentifier: 0, streamSequenceNumber: 1500,
                payloadProtocolIdentifier: 53, userData: Data("m".utf8)
            ))
        }
    }
}
