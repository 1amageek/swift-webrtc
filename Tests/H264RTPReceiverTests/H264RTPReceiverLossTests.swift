@testable import WebRTCMedia
import Testing

@Suite("H.264 RTP receiver loss and ordering")
struct H264RTPReceiverLossTests {
    private let support = H264RTPReceiverTestSupport()

    @Test("A gap taints both an active unit and the first observed timestamp")
    func gapQuarantinesFirstObservedTimestamp() throws {
        let receiver = try support.receiver(maximumReorderDelayNanoseconds: 50)
        let delivered = AccessUnitCollector()

        let active = try support.packet(
            sequenceNumber: 30,
            timestamp: 1,
            marker: false,
            payload: [0x7C, 0x81, 0x10]
        )
        _ = receiver.receive(
            active.bytes,
            layout: active.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        let uncertain = try support.packet(
            sequenceNumber: 32,
            timestamp: 2,
            marker: true,
            payload: [0x61, 0x20]
        )
        _ = receiver.receive(
            uncertain.bytes,
            layout: uncertain.layout,
            arrivalTimeNanoseconds: 10,
            sink: delivered.accept
        )

        let advanced = receiver.advanceTime(to: 60, sink: delivered.accept)
        let firstReport = try advanced.get()
        #expect(firstReport.declaredLostPacketCount == 1)
        #expect(firstReport.discardedAccessUnitCount == 1)
        #expect(firstReport.deliveredAccessUnitCount == 0)

        let safe = try support.packet(
            sequenceNumber: 33,
            timestamp: 3,
            marker: true,
            payload: [0x61, 0x30]
        )
        let resumed = receiver.receive(
            safe.bytes,
            layout: safe.layout,
            arrivalTimeNanoseconds: 61,
            sink: delivered.accept
        )
        let secondReport = try resumed.get()
        #expect(secondReport.discardedAccessUnitCount == 1)
        #expect(secondReport.deliveredAccessUnitCount == 1)
        #expect(delivered.values.map(\.rtpTimestamp) == [3])
    }

    @Test("FU processing failure quarantines the rest of its timestamp")
    func fragmentationFailureQuarantinesTimestamp() throws {
        let receiver = try support.receiver()
        let delivered = AccessUnitCollector()
        let invalidContinuation = try support.packet(
            sequenceNumber: 1,
            timestamp: 10,
            marker: false,
            payload: [0x7C, 0x05, 0xAA]
        )
        let failure = receiver.receive(
            invalidContinuation.bytes,
            layout: invalidContinuation.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        guard case .failure(.receiverAfterProgress(
            .fragmentationUnitWithoutStart,
            effects: let failureEffects
        )) = failure else {
            Issue.record("Expected a typed FU-without-start failure")
            return
        }
        #expect(failureEffects.discardedAccessUnitCount == 1)

        let sameTimestampTail = try support.packet(
            sequenceNumber: 2,
            timestamp: 10,
            marker: true,
            payload: [0x61, 0xBB]
        )
        let quarantined = receiver.receive(
            sameTimestampTail.bytes,
            layout: sameTimestampTail.layout,
            arrivalTimeNanoseconds: 1,
            sink: delivered.accept
        )
        #expect(try quarantined.get().deliveredAccessUnitCount == 0)

        let next = try support.packet(
            sequenceNumber: 3,
            timestamp: 11,
            marker: true,
            payload: [0x61, 0xCC]
        )
        _ = receiver.receive(
            next.bytes,
            layout: next.layout,
            arrivalTimeNanoseconds: 2,
            sink: delivered.accept
        )
        #expect(delivered.values.map(\.rtpTimestamp) == [11])
    }

    @Test("Reorder pressure resumes from the earliest buffered packet")
    func reorderPressureUsesEarliestBufferedPacket() throws {
        let receiver = try support.receiver(maximumReorderPacketCount: 3)
        let delivered = AccessUnitCollector()
        let initial = try support.packet(
            sequenceNumber: 0,
            timestamp: 0,
            marker: true,
            payload: [0x61, 0]
        )
        _ = receiver.receive(
            initial.bytes,
            layout: initial.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )

        for sequence in UInt16(3)...UInt16(4) {
            let buffered = try support.packet(
                sequenceNumber: sequence,
                timestamp: UInt32(sequence),
                marker: true,
                payload: [0x61, UInt8(sequence)]
            )
            _ = receiver.receive(
                buffered.bytes,
                layout: buffered.layout,
                arrivalTimeNanoseconds: UInt64(sequence),
                sink: delivered.accept
            )
        }
        let incoming = try support.packet(
            sequenceNumber: 5,
            timestamp: 5,
            marker: true,
            payload: [0x61, 5]
        )
        let result = receiver.receive(
            incoming.bytes,
            layout: incoming.layout,
            arrivalTimeNanoseconds: 5,
            sink: delivered.accept
        )
        let report = try result.get()

        #expect(report.disposition == .resynchronized)
        #expect(report.declaredLostPacketCount == 2)
        #expect(report.discardedPacketCount == 0)
        #expect(delivered.values.map(\.rtpTimestamp) == [0, 4, 5])
    }

    @Test("Byte pressure reports an evicted far-future packet")
    func reorderBytePressureReportsEviction() throws {
        let receiver = try support.receiver(
            maximumPacketByteCount: 30,
            maximumAccessUnitInputByteCount: 60,
            maximumReorderByteCount: 30
        )
        let delivered = AccessUnitCollector()
        let initial = try support.packet(
            sequenceNumber: 0,
            timestamp: 0,
            marker: true,
            payload: [0x61, 0]
        )
        _ = receiver.receive(
            initial.bytes,
            layout: initial.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        for sequence in UInt16(3)...UInt16(4) {
            let buffered = try support.packet(
                sequenceNumber: sequence,
                timestamp: UInt32(sequence),
                marker: true,
                payload: [0x61, UInt8(sequence)]
            )
            _ = receiver.receive(
                buffered.bytes,
                layout: buffered.layout,
                arrivalTimeNanoseconds: UInt64(sequence),
                sink: delivered.accept
            )
        }
        let largeIncoming = try support.packet(
            sequenceNumber: 5,
            timestamp: 5,
            marker: true,
            payload: [0x61] + Array(repeating: 5, count: 17)
        )
        let result = receiver.receive(
            largeIncoming.bytes,
            layout: largeIncoming.layout,
            arrivalTimeNanoseconds: 5,
            sink: delivered.accept
        )
        let report = try result.get()

        #expect(report.discardedPacketCount == 1)
        #expect(report.discardedPacketByteCount == 14)
        #expect(report.bufferedPacketCount == 1)
    }

    @Test("Half-range sequence distance is deterministically late")
    func halfRangeSequenceDistance() throws {
        let receiver = try support.receiver()
        let delivered = AccessUnitCollector()
        let initial = try support.packet(
            sequenceNumber: 0,
            timestamp: 0,
            marker: true,
            payload: [0x61, 0]
        )
        _ = receiver.receive(
            initial.bytes,
            layout: initial.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        let ambiguous = try support.packet(
            sequenceNumber: 32_769,
            timestamp: 1,
            marker: true,
            payload: [0x61, 1]
        )
        let result = receiver.receive(
            ambiguous.bytes,
            layout: ambiguous.layout,
            arrivalTimeNanoseconds: 1,
            sink: delivered.accept
        )

        #expect(try result.get().disposition == .duplicateOrLate)
        #expect(delivered.values.count == 1)
    }

    @Test("A large forward jump is explicit loss and quarantines its timestamp")
    func largeForwardJump() throws {
        let receiver = try support.receiver(maximumReorderPacketCount: 64)
        let delivered = AccessUnitCollector()
        let initial = try support.packet(
            sequenceNumber: 0,
            timestamp: 0,
            marker: true,
            payload: [0x61, 0]
        )
        _ = receiver.receive(
            initial.bytes,
            layout: initial.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        let jumped = try support.packet(
            sequenceNumber: 100,
            timestamp: 1,
            marker: true,
            payload: [0x61, 1]
        )
        let jumpResult = receiver.receive(
            jumped.bytes,
            layout: jumped.layout,
            arrivalTimeNanoseconds: 1,
            sink: delivered.accept
        )
        let jumpReport = try jumpResult.get()
        #expect(jumpReport.disposition == .resynchronized)
        #expect(jumpReport.declaredLostPacketCount == 99)
        #expect(jumpReport.deliveredAccessUnitCount == 0)

        let safe = try support.packet(
            sequenceNumber: 101,
            timestamp: 2,
            marker: true,
            payload: [0x61, 2]
        )
        let safeResult = receiver.receive(
            safe.bytes,
            layout: safe.layout,
            arrivalTimeNanoseconds: 2,
            sink: delivered.accept
        )
        #expect(try safeResult.get().discardedAccessUnitCount == 1)
        #expect(delivered.values.map(\.rtpTimestamp) == [0, 2])
    }

    @Test("A duplicate or late packet never reopens a completed unit")
    func duplicateOrLatePacket() throws {
        let receiver = try support.receiver()
        let delivered = AccessUnitCollector()
        let packet = try support.packet(
            sequenceNumber: 10,
            timestamp: 1,
            marker: true,
            payload: [0x61, 1]
        )
        _ = receiver.receive(
            packet.bytes,
            layout: packet.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        let duplicate = receiver.receive(
            packet.bytes,
            layout: packet.layout,
            arrivalTimeNanoseconds: 1,
            sink: delivered.accept
        )

        #expect(try duplicate.get().disposition == .duplicateOrLate)
        #expect(delivered.values.count == 1)
    }

    @Test("A packet closing a gap at its deadline is already late")
    func gapClosingPacketAtDeadlineDoesNotReleaseStaleMedia() throws {
        let receiver = try support.receiver(maximumReorderDelayNanoseconds: 50)
        let delivered = AccessUnitCollector()

        let initial = try support.packet(
            sequenceNumber: 0,
            timestamp: 0,
            marker: true,
            payload: [0x61, 0]
        )
        _ = receiver.receive(
            initial.bytes,
            layout: initial.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )

        let future = try support.packet(
            sequenceNumber: 2,
            timestamp: 100,
            marker: true,
            payload: [0x61, 2]
        )
        _ = receiver.receive(
            future.bytes,
            layout: future.layout,
            arrivalTimeNanoseconds: 10,
            sink: delivered.accept
        )

        let lateMissing = try support.packet(
            sequenceNumber: 1,
            timestamp: 100,
            marker: false,
            payload: [0x61, 1]
        )
        let expired = receiver.receive(
            lateMissing.bytes,
            layout: lateMissing.layout,
            arrivalTimeNanoseconds: 60,
            sink: delivered.accept
        )
        let report = try expired.get()
        #expect(report.disposition == .resynchronized)
        #expect(report.declaredLostPacketCount == 1)
        #expect(report.bufferedPacketCount == 0)
        #expect(delivered.values.map(\.rtpTimestamp) == [0])

        let safe = try support.packet(
            sequenceNumber: 3,
            timestamp: 200,
            marker: true,
            payload: [0x61, 3]
        )
        _ = receiver.receive(
            safe.bytes,
            layout: safe.layout,
            arrivalTimeNanoseconds: 61,
            sink: delivered.accept
        )
        #expect(delivered.values.map(\.rtpTimestamp) == [0, 200])
    }

    @Test("A receive event advances an active access-unit deadline")
    func receiveAdvancesAccessUnitDeadline() throws {
        let receiver = try support.receiver(
            maximumAccessUnitDurationNanoseconds: 10,
            maximumReorderDelayNanoseconds: 50
        )
        let delivered = AccessUnitCollector()
        let active = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: false,
            payload: [0x61, 1]
        )
        _ = receiver.receive(
            active.bytes,
            layout: active.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )

        let future = try support.packet(
            sequenceNumber: 3,
            timestamp: 2,
            marker: true,
            payload: [0x61, 3]
        )
        let result = receiver.receive(
            future.bytes,
            layout: future.layout,
            arrivalTimeNanoseconds: 11,
            sink: delivered.accept
        )
        let report = try result.get()
        #expect(report.disposition == .accessUnitTimedOut)
        #expect(report.discardedAccessUnitCount == 1)
        #expect(report.bufferedPacketCount == 1)
    }

    @Test("One clock advance converges across every expired gap")
    func clockAdvanceReachesDeadlineFixpoint() throws {
        let receiver = try support.receiver(
            maximumAccessUnitDurationNanoseconds: 10,
            maximumReorderDelayNanoseconds: 10
        )
        let delivered = AccessUnitCollector()
        let active = try support.packet(
            sequenceNumber: 0,
            timestamp: 0,
            marker: false,
            payload: [0x61, 0]
        )
        _ = receiver.receive(
            active.bytes,
            layout: active.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        for sequence in [UInt16(2), UInt16(4)] {
            let packet = try support.packet(
                sequenceNumber: sequence,
                timestamp: UInt32(sequence),
                marker: true,
                payload: [0x61, UInt8(sequence)]
            )
            _ = receiver.receive(
                packet.bytes,
                layout: packet.layout,
                arrivalTimeNanoseconds: 0,
                sink: delivered.accept
            )
        }

        let result = receiver.advanceTime(to: 11, sink: delivered.accept)
        let report = try result.get()
        #expect(report.disposition == .resynchronized)
        #expect(report.declaredLostPacketCount == 2)
        #expect(report.discardedAccessUnitCount == 2)
        #expect(report.bufferedPacketCount == 0)
        #expect(delivered.values.isEmpty)
    }

    @Test("A newly exposed gap gets its own witness deadline")
    func staggeredGapsDoNotInheritDeadline() throws {
        let receiver = try support.receiver(maximumReorderDelayNanoseconds: 50)
        let delivered = AccessUnitCollector()
        let initial = try support.packet(
            sequenceNumber: 0,
            timestamp: 0,
            marker: true,
            payload: [0x61, 0]
        )
        _ = receiver.receive(
            initial.bytes,
            layout: initial.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )

        let third = try support.packet(
            sequenceNumber: 3,
            timestamp: 100,
            marker: true,
            payload: [0x61, 3]
        )
        _ = receiver.receive(
            third.bytes,
            layout: third.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        let fifth = try support.packet(
            sequenceNumber: 5,
            timestamp: 200,
            marker: true,
            payload: [0x61, 5]
        )
        _ = receiver.receive(
            fifth.bytes,
            layout: fifth.layout,
            arrivalTimeNanoseconds: 49,
            sink: delivered.accept
        )

        for sequence in [UInt16(1), UInt16(2)] {
            let packet = try support.packet(
                sequenceNumber: sequence,
                timestamp: 100,
                marker: false,
                payload: [0x61, UInt8(sequence)]
            )
            _ = receiver.receive(
                packet.bytes,
                layout: packet.layout,
                arrivalTimeNanoseconds: 49,
                sink: delivered.accept
            )
        }

        let beforeDeadline = receiver.advanceTime(
            to: 50,
            sink: delivered.accept
        )
        let beforeReport = try beforeDeadline.get()
        #expect(beforeReport.declaredLostPacketCount == 0)
        #expect(beforeReport.bufferedPacketCount == 1)

        let atDeadline = receiver.advanceTime(to: 99, sink: delivered.accept)
        let deadlineReport = try atDeadline.get()
        #expect(deadlineReport.declaredLostPacketCount == 1)
        #expect(deadlineReport.bufferedPacketCount == 0)
    }

    @Test(
        "Maximum sparse reorder state converges without quadratic scanning",
        .timeLimit(.minutes(1))
    )
    func maximumSparseReorderStateIsBounded() throws {
        let receiver = try support.receiver(
            maximumPacketByteCount: 32,
            maximumReorderPacketCount: 32_767,
            maximumReorderByteCount: 300_000,
            maximumReorderDelayNanoseconds: 1
        )
        let delivered = AccessUnitCollector()
        let initial = try support.packet(
            sequenceNumber: 0,
            timestamp: 0,
            marker: true,
            payload: [0x61, 0]
        )
        _ = receiver.receive(
            initial.bytes,
            layout: initial.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )

        for rawSequence in stride(from: 2, through: 32_768, by: 2) {
            let sequence = UInt16(rawSequence)
            let packet = try support.packet(
                sequenceNumber: sequence,
                timestamp: UInt32(rawSequence),
                marker: true,
                payload: [0x61, UInt8(truncatingIfNeeded: rawSequence)]
            )
            _ = receiver.receive(
                packet.bytes,
                layout: packet.layout,
                arrivalTimeNanoseconds: 0,
                sink: delivered.accept
            )
        }

        let result = receiver.advanceTime(to: 1, sink: delivered.accept)
        let report = try result.get()
        #expect(report.disposition == .resynchronized)
        #expect(report.declaredLostPacketCount == 16_384)
        #expect(report.bufferedPacketCount == 0)
    }
}
