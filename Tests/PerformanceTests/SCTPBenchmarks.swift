/// SCTP Performance Benchmarks
///
/// Measures performance of SCTP packet processing, TSN tracking, and fragment assembly.

import Testing
import Foundation
@testable import SCTPCore

@Suite("SCTP Benchmarks")
struct SCTPBenchmarks {

    // MARK: - Packet Encoding/Decoding

    @Test("Benchmark: SCTP packet encoding")
    func benchmarkPacketEncode() {
        let dataChunk = SCTPDataChunk(
            tsn: 12345,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 51,
            userData: Data(repeating: 0x42, count: 1000)
        )
        let packet = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5001,
            verificationTag: 0x12345678,
            chunks: [dataChunk.toChunk()]
        )

        let result = benchmark("SCTPPacket.encode", iterations: 10000) {
            _ = packet.encode()
        }
        print(result)
    }

    @Test("Benchmark: SCTP packet decoding")
    func benchmarkPacketDecode() throws {
        let dataChunk = SCTPDataChunk(
            tsn: 12345,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 51,
            userData: Data(repeating: 0x42, count: 1000)
        )
        let packet = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5001,
            verificationTag: 0x12345678,
            chunks: [dataChunk.toChunk()]
        )
        let encoded = packet.encode()

        let result = try benchmark("SCTPPacket.decode", iterations: 10000) {
            _ = try SCTPPacket.decode(from: encoded)
        }
        print(result)
        print("  Packet size: \(encoded.count) bytes")
    }

    @Test("Benchmark: SCTP packet decoding (skip checksum)")
    func benchmarkPacketDecodeNoChecksum() throws {
        let dataChunk = SCTPDataChunk(
            tsn: 12345,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 51,
            userData: Data(repeating: 0x42, count: 1000)
        )
        let packet = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5001,
            verificationTag: 0x12345678,
            chunks: [dataChunk.toChunk()]
        )
        let encoded = packet.encode()

        let result = try benchmark("SCTPPacket.decode (no checksum)", iterations: 10000) {
            _ = try SCTPPacket.decode(from: encoded, validateChecksum: false)
        }
        print(result)
    }

    // MARK: - CRC-32C

    @Test("Benchmark: CRC-32C computation")
    func benchmarkCRC32C() {
        let data = Data(repeating: 0x42, count: 1500) // MTU-sized

        let result = benchmarkThroughput("CRC-32C", dataSize: 1500, iterations: 10000) {
            _ = crc32c(data)
        }
        print(result)
    }

    // MARK: - TSN Tracker

    @Test("Benchmark: TSN receive (sequential)")
    func benchmarkTSNReceiveSequential() {
        var tracker = TSNTracker(initialTSN: 0)

        let result = benchmark("TSNTracker.receive (sequential)", iterations: 10000) {
            for tsn: UInt32 in 0..<100 {
                _ = tracker.receive(tsn: tsn)
            }
        }
        print(result)
    }

    @Test("Benchmark: TSN receive (with gaps)")
    func benchmarkTSNReceiveWithGaps() {
        var tracker = TSNTracker(initialTSN: 0)

        let result = benchmark("TSNTracker.receive (gaps)", iterations: 10000) {
            // Simulate receiving with gaps
            for i: UInt32 in 0..<50 {
                _ = tracker.receive(tsn: i * 2) // Every other TSN
            }
        }
        print(result)
    }

    @Test("Benchmark: Gap block computation")
    func benchmarkGapBlocks() {
        var tracker = TSNTracker(initialTSN: 0)
        // Create gaps
        for i: UInt32 in 0..<100 {
            if i % 3 != 0 { // Skip every 3rd TSN
                _ = tracker.receive(tsn: i)
            }
        }

        let result = benchmark("TSNTracker.gapBlocks", iterations: 10000) {
            _ = tracker.gapBlocks
        }
        print(result)
        print("  Gap blocks: \(tracker.gapBlocks.count)")
    }

    // MARK: - Fragment Assembler

    @Test("Benchmark: Fragment assembly (single chunk)")
    func benchmarkFragmentSingle() {
        var assembler = FragmentAssembler()
        let fragmentData = Data(repeating: 0x42, count: 1000)

        var tsn: UInt32 = 0
        let result = benchmark("FragmentAssembler (single)", iterations: 10000) {
            let c = SCTPDataChunk(
                tsn: tsn,
                streamIdentifier: 0,
                streamSequenceNumber: UInt16(tsn % 65536),
                payloadProtocolIdentifier: 51,
                userData: fragmentData
            )
            _ = assembler.process(chunk: c)
            tsn += 1
        }
        print(result)
    }

    @Test("Benchmark: Fragment assembly (multi-chunk)")
    func benchmarkFragmentMulti() {
        var assembler = FragmentAssembler()
        let fragmentData = Data(repeating: 0x42, count: 500)

        var tsn: UInt32 = 0
        var seq: UInt16 = 0
        let result = benchmark("FragmentAssembler (multi)", iterations: 5000) {
            // 4-chunk message
            let begin = SCTPDataChunk(
                tsn: tsn, streamIdentifier: 0, streamSequenceNumber: seq,
                payloadProtocolIdentifier: 51, userData: fragmentData,
                beginningFragment: true, endingFragment: false
            )
            let mid1 = SCTPDataChunk(
                tsn: tsn + 1, streamIdentifier: 0, streamSequenceNumber: seq,
                payloadProtocolIdentifier: 51, userData: fragmentData,
                beginningFragment: false, endingFragment: false
            )
            let mid2 = SCTPDataChunk(
                tsn: tsn + 2, streamIdentifier: 0, streamSequenceNumber: seq,
                payloadProtocolIdentifier: 51, userData: fragmentData,
                beginningFragment: false, endingFragment: false
            )
            let end = SCTPDataChunk(
                tsn: tsn + 3, streamIdentifier: 0, streamSequenceNumber: seq,
                payloadProtocolIdentifier: 51, userData: fragmentData,
                beginningFragment: false, endingFragment: true
            )

            _ = assembler.process(chunk: begin)
            _ = assembler.process(chunk: mid1)
            _ = assembler.process(chunk: mid2)
            _ = assembler.process(chunk: end)

            tsn += 4
            seq += 1
        }
        print(result)
    }

    @Test("Benchmark: Fragment assembly (out of order)")
    func benchmarkFragmentOutOfOrder() {
        var assembler = FragmentAssembler()
        let fragmentData = Data(repeating: 0x42, count: 500)

        var tsn: UInt32 = 0
        var seq: UInt16 = 0
        let result = benchmark("FragmentAssembler (out-of-order)", iterations: 5000) {
            // Receive 4-chunk message out of order
            let begin = SCTPDataChunk(
                tsn: tsn, streamIdentifier: 0, streamSequenceNumber: seq,
                payloadProtocolIdentifier: 51, userData: fragmentData,
                beginningFragment: true, endingFragment: false
            )
            let mid1 = SCTPDataChunk(
                tsn: tsn + 1, streamIdentifier: 0, streamSequenceNumber: seq,
                payloadProtocolIdentifier: 51, userData: fragmentData,
                beginningFragment: false, endingFragment: false
            )
            let mid2 = SCTPDataChunk(
                tsn: tsn + 2, streamIdentifier: 0, streamSequenceNumber: seq,
                payloadProtocolIdentifier: 51, userData: fragmentData,
                beginningFragment: false, endingFragment: false
            )
            let end = SCTPDataChunk(
                tsn: tsn + 3, streamIdentifier: 0, streamSequenceNumber: seq,
                payloadProtocolIdentifier: 51, userData: fragmentData,
                beginningFragment: false, endingFragment: true
            )

            // Receive out of order: end, mid1, begin, mid2
            _ = assembler.process(chunk: end)
            _ = assembler.process(chunk: mid1)
            _ = assembler.process(chunk: begin)
            _ = assembler.process(chunk: mid2)

            tsn += 4
            seq += 1
        }
        print(result)
    }

    // MARK: - Cookie

    @Test("Benchmark: Cookie generation")
    func benchmarkCookieGenerate() {
        var secretKey = Data(count: 32)
        _ = secretKey.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        let result = benchmark("SCTPCookie.generate", iterations: 10000) {
            _ = SCTPCookie.generate(
                secretKey: secretKey,
                peerTag: 0x12345678,
                localTag: 0x87654321,
                peerInitialTSN: 1000,
                peerARWC: 65535,
                outboundStreams: 10,
                inboundStreams: 10
            )
        }
        print(result)
    }

    @Test("Benchmark: Cookie validation")
    func benchmarkCookieValidate() {
        var secretKey = Data(count: 32)
        _ = secretKey.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        let cookie = SCTPCookie.generate(
            secretKey: secretKey,
            peerTag: 0x12345678,
            localTag: 0x87654321,
            peerInitialTSN: 1000,
            peerARWC: 65535,
            outboundStreams: 10,
            inboundStreams: 10
        )

        let result = benchmark("SCTPCookie.validate", iterations: 10000) {
            _ = cookie.validate(secretKey: secretKey)
        }
        print(result)
    }

    // MARK: - Retransmission Queue

    @Test("Benchmark: Retransmission queue enqueue/ack")
    func benchmarkRetransmissionQueue() {
        var queue = RetransmissionQueue()
        let clock = ContinuousClock()
        let data = Data(repeating: 0x42, count: 1000)

        let result = benchmark("RetransmissionQueue", iterations: 5000) {
            // Enqueue 10 chunks
            for i: UInt32 in 0..<10 {
                let chunk = SCTPDataChunk(
                    tsn: i,
                    streamIdentifier: 0,
                    streamSequenceNumber: UInt16(i),
                    payloadProtocolIdentifier: 51,
                    userData: data
                )
                queue.enqueue(chunk, sentTime: clock.now)
            }

            // Acknowledge all
            _ = queue.acknowledge(cumulativeTSN: 9, gapBlocks: [])
        }
        print(result)
    }
}
