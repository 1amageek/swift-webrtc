@testable import WebRTCMedia
import Testing

@Suite("H.264 RTP receiver reconstruction")
struct H264RTPReceiverSessionTests {
    private let support = H264RTPReceiverTestSupport()

    @Test("Single NAL and STAP-A packets become one Annex B access unit")
    func singleAndAggregatedNALUnits() throws {
        let receiver = try support.receiver()
        let delivered = AccessUnitCollector()

        let single = try support.packet(
            sequenceNumber: 10,
            timestamp: 90_000,
            marker: false,
            payload: [0x67, 0x01]
        )
        let first = receiver.receive(
            single.bytes,
            layout: single.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        #expect(try first.get().deliveredAccessUnitCount == 0)

        let aggregation = try support.packet(
            sequenceNumber: 11,
            timestamp: 90_000,
            marker: true,
            payload: [
                0x78,
                0x00, 0x02, 0x68, 0x02,
                0x00, 0x02, 0x65, 0x03,
            ]
        )
        let second = receiver.receive(
            aggregation.bytes,
            layout: aggregation.layout,
            arrivalTimeNanoseconds: 1,
            sink: delivered.accept
        )

        let report = try second.get()
        #expect(report.deliveredAccessUnitCount == 1)
        #expect(report.reconstructedByteCount == 18)
        let accessUnit = try #require(delivered.values.first)
        #expect(accessUnit.bytes == [
            0, 0, 0, 1, 0x67, 0x01,
            0, 0, 0, 1, 0x68, 0x02,
            0, 0, 0, 1, 0x65, 0x03,
        ])
        #expect(accessUnit.nalUnitRanges == [4..<6, 10..<12, 16..<18])
        #expect(accessUnit.packetCount == 2)
        #expect(accessUnit.containsInstantaneousDecoderRefresh)
    }

    @Test("Out-of-order FU-A is reconstructed in sequence order")
    func reorderedFragmentationUnitA() throws {
        let receiver = try support.receiver()
        let delivered = AccessUnitCollector()

        let start = try support.packet(
            sequenceNumber: 20,
            timestamp: 180_000,
            marker: false,
            payload: [0x7C, 0x85, 0xAA]
        )
        _ = receiver.receive(
            start.bytes,
            layout: start.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        let end = try support.packet(
            sequenceNumber: 22,
            timestamp: 180_000,
            marker: true,
            payload: [0x7C, 0x45, 0xCC]
        )
        let buffered = receiver.receive(
            end.bytes,
            layout: end.layout,
            arrivalTimeNanoseconds: 1,
            sink: delivered.accept
        )
        #expect(try buffered.get().disposition == .buffered)
        #expect(try buffered.get().bufferedPacketCount == 1)

        let middle = try support.packet(
            sequenceNumber: 21,
            timestamp: 180_000,
            marker: false,
            payload: [0x7C, 0x05, 0xBB]
        )
        let drained = receiver.receive(
            middle.bytes,
            layout: middle.layout,
            arrivalTimeNanoseconds: 2,
            sink: delivered.accept
        )

        #expect(try drained.get().deliveredAccessUnitCount == 1)
        #expect(try drained.get().bufferedPacketCount == 0)
        let accessUnit = try #require(delivered.values.first)
        #expect(accessUnit.bytes == [0, 0, 0, 1, 0x65, 0xAA, 0xBB, 0xCC])
        #expect(accessUnit.nalUnitRanges == [4..<8])
        #expect(accessUnit.firstSequenceNumber == 20)
        #expect(accessUnit.lastSequenceNumber == 22)
    }

    @Test("An older buffered arrival does not underflow access-unit duration")
    func reorderedHistoricalArrivalUsesObservationTime() throws {
        let receiver = try support.receiver(
            maximumAccessUnitDurationNanoseconds: 10
        )
        let delivered = AccessUnitCollector()

        let previous = try support.packet(
            sequenceNumber: 9,
            timestamp: 90_000,
            marker: true,
            payload: [0x61, 0x01]
        )
        _ = receiver.receive(
            previous.bytes,
            layout: previous.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )

        let bufferedEnd = try support.packet(
            sequenceNumber: 11,
            timestamp: 180_000,
            marker: true,
            payload: [0x61, 0x03]
        )
        let buffered = receiver.receive(
            bufferedEnd.bytes,
            layout: bufferedEnd.layout,
            arrivalTimeNanoseconds: 100,
            sink: delivered.accept
        )
        #expect(try buffered.get().disposition == .buffered)

        let delayedStart = try support.packet(
            sequenceNumber: 10,
            timestamp: 180_000,
            marker: false,
            payload: [0x61, 0x02]
        )
        let drained = receiver.receive(
            delayedStart.bytes,
            layout: delayedStart.layout,
            arrivalTimeNanoseconds: 200,
            sink: delivered.accept
        )

        #expect(try drained.get().deliveredAccessUnitCount == 1)
        #expect(delivered.values.map(\.rtpTimestamp) == [90_000, 180_000])
    }

    @Test("Timestamp transition completes an access unit without relying on marker")
    func timestampBoundaryFallback() throws {
        let receiver = try support.receiver()
        let delivered = AccessUnitCollector()
        let first = try support.packet(
            sequenceNumber: 1,
            timestamp: 100,
            marker: false,
            payload: [0x61, 0x01]
        )
        _ = receiver.receive(
            first.bytes,
            layout: first.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        let second = try support.packet(
            sequenceNumber: 2,
            timestamp: 200,
            marker: true,
            payload: [0x61, 0x02]
        )
        let result = receiver.receive(
            second.bytes,
            layout: second.layout,
            arrivalTimeNanoseconds: 1,
            sink: delivered.accept
        )

        #expect(try result.get().deliveredAccessUnitCount == 2)
        #expect(delivered.values.map(\.rtpTimestamp) == [100, 200])
    }

    @Test("Sequence ordering crosses UInt16 rollover")
    func sequenceNumberRollover() throws {
        let receiver = try support.receiver()
        let delivered = AccessUnitCollector()

        let first = try support.packet(
            sequenceNumber: .max,
            timestamp: 3,
            marker: false,
            payload: [0x61, 1]
        )
        _ = receiver.receive(
            first.bytes,
            layout: first.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )
        let second = try support.packet(
            sequenceNumber: 0,
            timestamp: 3,
            marker: true,
            payload: [0x61, 2]
        )
        let result = receiver.receive(
            second.bytes,
            layout: second.layout,
            arrivalTimeNanoseconds: 1,
            sink: delivered.accept
        )

        #expect(try result.get().deliveredAccessUnitCount == 1)
        #expect(delivered.values.first?.firstSequenceNumber == .max)
        #expect(delivered.values.first?.lastSequenceNumber == 0)
    }

    @Test("Reordered sequence indexing crosses UInt16 rollover")
    func reorderedSequenceNumberRollover() throws {
        let receiver = try support.receiver()
        let delivered = AccessUnitCollector()

        let initial = try support.packet(
            sequenceNumber: .max - 1,
            timestamp: 1,
            marker: true,
            payload: [0x61, 1]
        )
        _ = receiver.receive(
            initial.bytes,
            layout: initial.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )

        let future = try support.packet(
            sequenceNumber: 0,
            timestamp: 3,
            marker: true,
            payload: [0x61, 3]
        )
        _ = receiver.receive(
            future.bytes,
            layout: future.layout,
            arrivalTimeNanoseconds: 1,
            sink: delivered.accept
        )

        let missing = try support.packet(
            sequenceNumber: .max,
            timestamp: 2,
            marker: true,
            payload: [0x61, 2]
        )
        let result = receiver.receive(
            missing.bytes,
            layout: missing.layout,
            arrivalTimeNanoseconds: 2,
            sink: delivered.accept
        )

        let report = try result.get()
        #expect(report.deliveredAccessUnitCount == 2)
        #expect(report.bufferedPacketCount == 0)
        #expect(
            delivered.values.map(\.firstSequenceNumber)
                == [UInt16.max - 1, UInt16.max, 0]
        )
    }

    @Test("AVCC output patches length in the exact final owner")
    func avccOutput() throws {
        let receiver = try support.receiver(
            accessUnitFormat: .avcc(lengthFieldByteCount: 4)
        )
        let delivered = AccessUnitCollector()
        let input = try support.packet(
            sequenceNumber: 1,
            timestamp: 4,
            marker: true,
            payload: [0x65, 0xAA, 0xBB]
        )
        let result = receiver.receive(
            input.bytes,
            layout: input.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )

        #expect(try result.get().deliveredAccessUnitCount == 1)
        #expect(delivered.values.first?.bytes == [0, 0, 0, 3, 0x65, 0xAA, 0xBB])
        #expect(delivered.values.first?.nalUnitRanges == [4..<7])
    }

    @Test("CSRC, extension, and padding remain outside the reconstructed payload")
    func extendedRTPHeaderAndPadding() throws {
        let receiver = try support.receiver()
        let delivered = AccessUnitCollector()
        let input = try support.packet(
            sequenceNumber: 1,
            timestamp: 5,
            marker: true,
            payload: [0x61, 0xAA],
            contributingSources: [0x1111_1111, 0x2222_2222],
            extensionProfile: 0xBEDE,
            extensionData: [1, 2, 3, 4],
            paddingByteCount: 4
        )
        _ = receiver.receive(
            input.bytes,
            layout: input.layout,
            arrivalTimeNanoseconds: 0,
            sink: delivered.accept
        )

        #expect(delivered.values.first?.bytes == [0, 0, 0, 1, 0x61, 0xAA])
    }
}
