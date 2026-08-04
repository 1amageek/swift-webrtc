import Testing
@testable import WebRTC
@Suite("SRTP state and concurrency")
struct SRTPStateTests {
    @Test("The 48-bit RTP index cannot wrap under one key")
    func rtpIndexExhaustion() {
        let synchronizationSource: UInt32 = 9
        var state = SRTPState()
        state.outboundRTP[synchronizationSource] = OutboundRTPState(
            highestCommittedIndex: 0xFFFF_FFFF_FFFF,
            pendingIndices: []
        )

        #expect(throws: SRTPError.indexExhausted(
            kind: .rtp,
            synchronizationSource: synchronizationSource
        )) {
            try state.reserveOutboundRTP(
                synchronizationSource: synchronizationSource,
                sequenceNumber: 0
            )
        }
    }

    @Test("ROC zero never underflows to the exhausted final epoch")
    func initialEpochRejectsPreviousROC() throws {
        let synchronizationSource: UInt32 = 10
        var state = SRTPState()
        let initialIndex = try state.reserveInboundRTP(
            synchronizationSource: synchronizationSource,
            sequenceNumber: 10
        )
        try state.commitInbound(
            kind: .rtp,
            synchronizationSource: synchronizationSource,
            index: initialIndex
        )

        #expect(throws: SRTPError.packetTooOld(
            kind: .rtp,
            synchronizationSource: synchronizationSource,
            index: UInt64(UInt16.max)
        )) {
            try state.reserveInboundRTP(
                synchronizationSource: synchronizationSource,
                sequenceNumber: UInt16.max
            )
        }
    }

    @Test("Concurrent protection reserves one use of an RTP index")
    func concurrentOutboundDuplicate() async throws {
        let context = try testContext()
        let plaintext = rtpPacket(sequenceNumber: 42)

        let outcomes: [ConcurrentSRTPOutcome] = await withTaskGroup(
            of: ConcurrentSRTPOutcome.self
        ) { group in
            for _ in 0..<16 {
                group.addTask {
                    var packet = plaintext
                    do {
                        try context.protectRTP(&packet)
                        return .success
                    } catch let error as SRTPError {
                        return .failure(error)
                    } catch {
                        return .unexpectedFailure
                    }
                }
            }
            var results: [ConcurrentSRTPOutcome] = []
            for await outcome in group {
                results.append(outcome)
            }
            return results
        }

        #expect(outcomes.count(where: { $0 == .success }) == 1)
        #expect(outcomes.count(where: {
            $0 == .failure(.outboundIndexReuse(
                synchronizationSource: 0x1122_3344,
                index: 42
            ))
        }) == 15)
        #expect(!outcomes.contains(.unexpectedFailure))
    }

    @Test("Concurrent receipt accepts one copy of an authenticated RTP index")
    func concurrentInboundDuplicate() async throws {
        let sender = try testContext()
        let receiver = try testContext()
        var protected = rtpPacket(sequenceNumber: 43)
        try sender.protectRTP(&protected)
        let protectedPacket = protected

        let outcomes: [ConcurrentSRTPOutcome] = await withTaskGroup(
            of: ConcurrentSRTPOutcome.self
        ) { group in
            for _ in 0..<16 {
                group.addTask {
                    var packet = protectedPacket
                    do {
                        try receiver.unprotectRTP(&packet)
                        return .success
                    } catch let error as SRTPError {
                        return .failure(error)
                    } catch {
                        return .unexpectedFailure
                    }
                }
            }
            var results: [ConcurrentSRTPOutcome] = []
            for await outcome in group {
                results.append(outcome)
            }
            return results
        }

        #expect(outcomes.count(where: { $0 == .success }) == 1)
        #expect(outcomes.count(where: {
            $0 == .failure(.replayedPacket(
                kind: .rtp,
                synchronizationSource: 0x1122_3344,
                index: 43
            ))
        }) == 15)
        #expect(!outcomes.contains(.unexpectedFailure))
    }

    @Test("Concurrent SRTCP receipt accepts exactly one authenticated index")
    func concurrentInboundSRTCPDuplicate() async throws {
        let sender = try testContext()
        let receiver = try testContext()
        var protected = rtcpPictureLossIndication()
        try sender.protectRTCP(&protected)
        let protectedPacket = protected

        let outcomes: [ConcurrentSRTPOutcome] = await withTaskGroup(
            of: ConcurrentSRTPOutcome.self
        ) { group in
            for _ in 0..<16 {
                group.addTask {
                    var packet = protectedPacket
                    do {
                        try receiver.unprotectRTCP(&packet)
                        return .success
                    } catch let error as SRTPError {
                        return .failure(error)
                    } catch {
                        return .unexpectedFailure
                    }
                }
            }
            var results: [ConcurrentSRTPOutcome] = []
            for await outcome in group {
                results.append(outcome)
            }
            return results
        }

        #expect(outcomes.count(where: { $0 == .success }) == 1)
        #expect(outcomes.count(where: {
            $0 == .failure(.replayedPacket(
                kind: .rtcp,
                synchronizationSource: 0x1122_3344,
                index: 0
            ))
        }) == 15)
        #expect(!outcomes.contains(.unexpectedFailure))
    }

    @Test("Replay window accepts distance 63 and rejects distance 64")
    func exactReplayWindowBoundary() throws {
        let synchronizationSource: UInt32 = 11
        var state = SRTPState()

        try state.reserveInboundRTCP(
            synchronizationSource: synchronizationSource,
            index: 64
        )
        try state.commitInbound(
            kind: .rtcp,
            synchronizationSource: synchronizationSource,
            index: 64
        )
        try state.reserveInboundRTCP(
            synchronizationSource: synchronizationSource,
            index: 1
        )
        try state.commitInbound(
            kind: .rtcp,
            synchronizationSource: synchronizationSource,
            index: 1
        )

        #expect(throws: SRTPError.packetTooOld(
            kind: .rtcp,
            synchronizationSource: synchronizationSource,
            index: 0
        )) {
            try state.reserveInboundRTCP(
                synchronizationSource: synchronizationSource,
                index: 0
            )
        }
    }
}

private enum ConcurrentSRTPOutcome: Sendable, Equatable {
    case success
    case failure(SRTPError)
    case unexpectedFailure
}
