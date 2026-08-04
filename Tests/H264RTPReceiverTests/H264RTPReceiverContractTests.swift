@testable import WebRTCMedia
import Synchronization
import Testing

@Suite("H.264 RTP receiver ownership and limits")
struct H264RTPReceiverContractTests {
    private let support = H264RTPReceiverTestSupport()

    @Test("Layout cannot be substituted across equal-length packet owners")
    func layoutOwnerMismatch() throws {
        let receiver = try support.receiver()
        let first = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [0x61, 1]
        )
        let second = try support.packet(
            sequenceNumber: 2,
            timestamp: 1,
            marker: true,
            payload: [0x61, 2]
        )
        #expect(first.bytes.count == second.bytes.count)

        let result = receiver.receive(
            first.bytes,
            layout: second.layout,
            arrivalTimeNanoseconds: 0
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        guard case .failure(.receiver(.packetLayoutOwnerMismatch)) = result else {
            Issue.record("Expected owner/layout substitution rejection")
            return
        }
    }

    @Test("More than eight unblocked access units deliver incrementally")
    func burstDeliveryHasNoReadyQueueCliff() throws {
        let receiver = try support.receiver(maximumReorderPacketCount: 32)
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
        for sequence in UInt16(2)...UInt16(12) {
            let packet = try support.packet(
                sequenceNumber: sequence,
                timestamp: UInt32(sequence),
                marker: true,
                payload: [0x61, UInt8(sequence)]
            )
            _ = receiver.receive(
                packet.bytes,
                layout: packet.layout,
                arrivalTimeNanoseconds: UInt64(sequence),
                sink: delivered.accept
            )
        }
        let missing = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [0x61, 1]
        )
        let result = receiver.receive(
            missing.bytes,
            layout: missing.layout,
            arrivalTimeNanoseconds: 13,
            sink: delivered.accept
        )

        #expect(try result.get().deliveredAccessUnitCount == 12)
        #expect(delivered.values.count == 13)
    }

    @Test("Sink re-entry is typed and the callback is outside the mutex")
    func sinkReentry() throws {
        let receiver = try support.receiver()
        let first = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [0x61, 1]
        )
        let reentrant = try support.packet(
            sequenceNumber: 2,
            timestamp: 2,
            marker: true,
            payload: [0x61, 2]
        )
        var reentrantFailureObserved = false
        let outer = receiver.receive(
            first.bytes,
            layout: first.layout,
            arrivalTimeNanoseconds: 0
        ) { _ -> Result<Void, ReceiverTestSinkError> in
            let nested = receiver.receive(
                reentrant.bytes,
                layout: reentrant.layout,
                arrivalTimeNanoseconds: 1
            ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
            if case .failure(.receiver(.receiveInProgress)) = nested {
                reentrantFailureObserved = true
            }
            return .success(())
        }

        #expect(reentrantFailureObserved)
        #expect(try outer.get().deliveredAccessUnitCount == 1)
    }

    @Test("Sink failure reports reconstruction and queued packet disposal")
    func sinkFailureEffects() throws {
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
        for sequence in UInt16(2)...UInt16(3) {
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
        let missing = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [0x61, 1]
        )
        var attempt = 0
        let result = receiver.receive(
            missing.bytes,
            layout: missing.layout,
            arrivalTimeNanoseconds: 4
        ) { _ -> Result<Void, ReceiverTestSinkError> in
            attempt += 1
            return attempt == 1 ? .success(()) : .failure(.rejected)
        }

        guard case .failure(.sink(.rejected, effects: let effects)) = result else {
            Issue.record("Expected typed sink failure effects")
            return
        }
        #expect(effects.deliveredAccessUnitCount == 1)
        #expect(effects.discardedAccessUnitCount == 1)
        #expect(effects.discardedPacketCount == 1)
        #expect(effects.reconstructedByteCount == 12)
    }

    @Test("Packet, output, input, packet-count, and NAL-count limits fail explicitly")
    func boundedMemoryFailures() throws {
        let packetLimited = try support.receiver(
            maximumPacketByteCount: 20,
            maximumAccessUnitByteCount: 6,
            maximumAccessUnitInputByteCount: 20,
            maximumReorderByteCount: 20
        )
        let oversized = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: Array(repeating: 0x61, count: 9)
        )
        let packetResult = packetLimited.receive(
            oversized.bytes,
            layout: oversized.layout,
            arrivalTimeNanoseconds: 0
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        guard case .failure(.receiver(.packetExceedsMaximum)) = packetResult else {
            Issue.record("Expected packet byte limit")
            return
        }

        let outputLimited = try support.receiver(
            maximumPacketByteCount: 20,
            maximumAccessUnitByteCount: 6,
            maximumAccessUnitInputByteCount: 40,
            maximumReorderByteCount: 20
        )
        let outputPacket = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [0x61, 1, 2]
        )
        let outputResult = outputLimited.receive(
            outputPacket.bytes,
            layout: outputPacket.layout,
            arrivalTimeNanoseconds: 0
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        guard case .failure(.receiverAfterProgress(
            .accessUnitByteLimitExceeded,
            effects: _
        )) = outputResult else {
            Issue.record("Expected access-unit output byte limit")
            return
        }

        let inputLimited = try support.receiver(
            maximumPacketByteCount: 20,
            maximumAccessUnitInputByteCount: 20,
            maximumReorderByteCount: 20
        )
        let first = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: false,
            payload: [0x61, 1]
        )
        _ = inputLimited.receive(
            first.bytes,
            layout: first.layout,
            arrivalTimeNanoseconds: 0
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        let second = try support.packet(
            sequenceNumber: 2,
            timestamp: 1,
            marker: true,
            payload: [0x61, 2]
        )
        let inputResult = inputLimited.receive(
            second.bytes,
            layout: second.layout,
            arrivalTimeNanoseconds: 1
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        guard case .failure(.receiverAfterProgress(
            .accessUnitInputByteLimitExceeded,
            effects: _
        )) = inputResult else {
            Issue.record("Expected retained input byte limit")
            return
        }

        let packetCountLimited = try support.receiver(
            maximumPacketsPerAccessUnit: 1
        )
        let countFirst = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: false,
            payload: [0x61, 1]
        )
        _ = packetCountLimited.receive(
            countFirst.bytes,
            layout: countFirst.layout,
            arrivalTimeNanoseconds: 0
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        let countSecond = try support.packet(
            sequenceNumber: 2,
            timestamp: 1,
            marker: true,
            payload: [0x61, 2]
        )
        let packetCountResult = packetCountLimited.receive(
            countSecond.bytes,
            layout: countSecond.layout,
            arrivalTimeNanoseconds: 1
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        guard case .failure(.receiverAfterProgress(
            .accessUnitPacketLimitExceeded,
            effects: _
        )) = packetCountResult else {
            Issue.record("Expected access-unit packet-count limit")
            return
        }

        let nalLimited = try support.receiver(maximumNALUnitsPerAccessUnit: 2)
        let stap = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [
                0x78,
                0, 1, 0x61,
                0, 1, 0x61,
                0, 1, 0x61,
            ]
        )
        let nalResult = nalLimited.receive(
            stap.bytes,
            layout: stap.layout,
            arrivalTimeNanoseconds: 0
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        guard case .failure(.receiverAfterProgress(
            .accessUnitNALUnitLimitExceeded,
            effects: _
        )) = nalResult else {
            Issue.record("Expected access-unit NAL metadata limit")
            return
        }
    }

    @Test("AVCC one-byte lengths accept 255 bytes and reject 256")
    func avccLengthBoundary() throws {
        let acceptedReceiver = try support.receiver(
            accessUnitFormat: .avcc(lengthFieldByteCount: 1),
            maximumPacketByteCount: 512,
            maximumAccessUnitByteCount: 512,
            maximumAccessUnitInputByteCount: 512,
            maximumReorderByteCount: 512
        )
        let accepted = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [0x61] + Array(repeating: 1, count: 254)
        )
        let acceptedResult = acceptedReceiver.receive(
            accepted.bytes,
            layout: accepted.layout,
            arrivalTimeNanoseconds: 0
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        #expect(try acceptedResult.get().deliveredAccessUnitCount == 1)

        let rejectedReceiver = try support.receiver(
            accessUnitFormat: .avcc(lengthFieldByteCount: 1),
            maximumPacketByteCount: 512,
            maximumAccessUnitByteCount: 512,
            maximumAccessUnitInputByteCount: 512,
            maximumReorderByteCount: 512
        )
        let rejected = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [0x61] + Array(repeating: 1, count: 255)
        )
        let rejectedResult = rejectedReceiver.receive(
            rejected.bytes,
            layout: rejected.layout,
            arrivalTimeNanoseconds: 0
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        guard case .failure(.receiverAfterProgress(
            .nalUnitLengthExceedsOutputFormat(actual: 256, maximum: 255),
            effects: _
        )) = rejectedResult else {
            Issue.record("Expected AVCC one-byte length rejection")
            return
        }
    }

    @Test("AVCC four-byte lengths reject values above UInt32.max")
    func avccFourByteLengthBoundary() throws {
        // On 32-bit targets no representable Array can exceed the four-byte
        // AVCC limit, so the impossible branch is intentionally absent.
        guard Int.bitWidth > 32 else { return }
        let rejectedByteCount = Int(UInt32.max) + 1

        do {
            try H264RTPAccessUnitAssembly.validateNALUnitLength(
                rejectedByteCount,
                format: .avcc(lengthFieldByteCount: 4)
            )
            Issue.record("Expected AVCC four-byte length rejection")
        } catch let error {
            #expect(error == .nalUnitLengthExceedsOutputFormat(
                actual: rejectedByteCount,
                maximum: Int(UInt32.max)
            ))
        }
    }

    @Test("Access-unit duration is bounded and its timestamp stays quarantined")
    func accessUnitTimeout() throws {
        let receiver = try support.receiver(
            maximumAccessUnitDurationNanoseconds: 10
        )
        let delivered = AccessUnitCollector()
        let first = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: false,
            payload: [0x61, 1]
        )
        _ = receiver.receive(
            first.bytes,
            layout: first.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        let timedOut = receiver.advanceTime(to: 11, sink: delivered.accept)
        let timeoutReport = try timedOut.get()
        #expect(timeoutReport.disposition == .accessUnitTimedOut)
        #expect(timeoutReport.discardedAccessUnitCount == 1)

        let sameTimestamp = try support.packet(
            sequenceNumber: 2,
            timestamp: 1,
            marker: true,
            payload: [0x61, 2]
        )
        _ = receiver.receive(
            sameTimestamp.bytes,
            layout: sameTimestamp.layout,
            arrivalTimeNanoseconds: 12,
            sink: delivered.accept
        )
        let next = try support.packet(
            sequenceNumber: 3,
            timestamp: 2,
            marker: true,
            payload: [0x61, 3]
        )
        _ = receiver.receive(
            next.bytes,
            layout: next.layout,
            arrivalTimeNanoseconds: 13,
            sink: delivered.accept
        )
        #expect(delivered.values.map(\.rtpTimestamp) == [2])
    }

    @Test("Completed media keeps the exact materialized storage through the sink")
    func materializedStorageTransfer() throws {
        let receiver = try support.receiver()
        let delivered = AccessUnitCollector()
        let input = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [0x65, 1, 2, 3]
        )
        let result = receiver.receive(
            input.bytes,
            layout: input.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        let report = try result.get()
        let storedAddress = delivered.values[0].bytes.withUnsafeBufferPointer {
            $0.baseAddress.map { UInt(bitPattern: $0) } ?? 0
        }

        #expect(report.reconstructedByteCount == 8)
        #expect(delivered.inputStorageAddresses == [storedAddress])
    }

    @Test("A packet after marker with the same timestamp is a typed violation")
    func packetAfterMarker() throws {
        let receiver = try support.receiver()
        let delivered = AccessUnitCollector()
        let first = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [0x61, 1]
        )
        _ = receiver.receive(
            first.bytes,
            layout: first.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        let invalid = try support.packet(
            sequenceNumber: 2,
            timestamp: 1,
            marker: true,
            payload: [0x61, 2]
        )
        let result = receiver.receive(
            invalid.bytes,
            layout: invalid.layout,
            arrivalTimeNanoseconds: 1,
            sink: delivered.accept
        )
        guard case .failure(.receiverAfterProgress(
            .packetAfterMarkerForCompletedTimestamp(timestamp: 1),
            effects: let effects
        )) = result else {
            Issue.record("Expected a typed same-timestamp marker violation")
            return
        }
        #expect(effects.discardedAccessUnitCount == 1)
        #expect(delivered.values.count == 1)
    }

    @Test("Payload type, SSRC, and monotonic arrival time are enforced")
    func streamIdentityAndClock() throws {
        let receiver = try support.receiver()
        let wrongPayloadType = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [0x61, 1],
            payloadType: 97
        )
        let payloadResult = receiver.receive(
            wrongPayloadType.bytes,
            layout: wrongPayloadType.layout,
            arrivalTimeNanoseconds: 0
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        guard case .failure(.receiver(.unexpectedPayloadType(
            expected: 96,
            actual: 97
        ))) = payloadResult else {
            Issue.record("Expected payload-type rejection")
            return
        }

        let wrongSSRC = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [0x61, 1],
            synchronizationSource: 99
        )
        let ssrcResult = receiver.receive(
            wrongSSRC.bytes,
            layout: wrongSSRC.layout,
            arrivalTimeNanoseconds: 0
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        guard case .failure(.receiver(.unexpectedSynchronizationSource(
            expected: receiverTestSynchronizationSource,
            actual: 99
        ))) = ssrcResult else {
            Issue.record("Expected SSRC rejection")
            return
        }

        let first = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [0x61, 1]
        )
        _ = receiver.receive(
            first.bytes,
            layout: first.layout,
            arrivalTimeNanoseconds: 10
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        let second = try support.packet(
            sequenceNumber: 2,
            timestamp: 2,
            marker: true,
            payload: [0x61, 2]
        )
        let clockResult = receiver.receive(
            second.bytes,
            layout: second.layout,
            arrivalTimeNanoseconds: 9
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        guard case .failure(.receiverAfterProgress(
            .decreasingArrivalTime(previous: 10, current: 9),
            effects: _
        )) = clockResult else {
            Issue.record("Expected decreasing-clock rejection")
            return
        }
    }

    @Test("FU header mismatch and marker-before-end are typed failures")
    func fragmentationStateFailures() throws {
        let mismatchReceiver = try support.receiver()
        let start = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: false,
            payload: [0x7C, 0x85, 1]
        )
        _ = mismatchReceiver.receive(
            start.bytes,
            layout: start.layout,
            arrivalTimeNanoseconds: 0
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        let mismatch = try support.packet(
            sequenceNumber: 2,
            timestamp: 1,
            marker: false,
            payload: [0x7C, 0x01, 2]
        )
        let mismatchResult = mismatchReceiver.receive(
            mismatch.bytes,
            layout: mismatch.layout,
            arrivalTimeNanoseconds: 1
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        guard case .failure(.receiverAfterProgress(
            .fragmentationUnitHeaderMismatch,
            effects: _
        )) = mismatchResult else {
            Issue.record("Expected FU header mismatch")
            return
        }

        let markerReceiver = try support.receiver()
        let unterminated = try support.packet(
            sequenceNumber: 1,
            timestamp: 1,
            marker: true,
            payload: [0x7C, 0x85, 1]
        )
        let markerResult = markerReceiver.receive(
            unterminated.bytes,
            layout: unterminated.layout,
            arrivalTimeNanoseconds: 0
        ) { _ -> Result<Void, ReceiverTestSinkError> in .success(()) }
        guard case .failure(.receiverAfterProgress(
            .markerBeforeFragmentationUnitEnd,
            effects: _
        )) = markerResult else {
            Issue.record("Expected marker-before-FU-end failure")
            return
        }
    }

    @Test("A large fragmented unit is materialized at exact final size")
    func largeFragmentedAccessUnit() throws {
        let receiver = try support.receiver(
            maximumAccessUnitByteCount: 400_000,
            maximumAccessUnitInputByteCount: 400_000,
            maximumPacketsPerAccessUnit: 400
        )
        let delivered = AccessUnitCollector()
        var finalReport: H264RTPReceiveReport?
        for index in 0..<300 {
            let fragmentHeader: UInt8
            if index == 0 {
                fragmentHeader = 0x85
            } else if index == 299 {
                fragmentHeader = 0x45
            } else {
                fragmentHeader = 0x05
            }
            let packet = try support.packet(
                sequenceNumber: UInt16(index),
                timestamp: 1,
                marker: index == 299,
                payload: [0x7C, fragmentHeader]
                    + Array(repeating: UInt8(truncatingIfNeeded: index), count: 1_000)
            )
            let result = receiver.receive(
                packet.bytes,
                layout: packet.layout,
                arrivalTimeNanoseconds: UInt64(index),
                sink: delivered.accept
            )
            finalReport = try result.get()
        }

        #expect(finalReport?.reconstructedByteCount == 300_005)
        #expect(delivered.values.first?.bytes.count == 300_005)
        #expect(delivered.values.first?.nalUnitRanges == [4..<300_005])
    }
}
