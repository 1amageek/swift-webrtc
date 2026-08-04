@testable import WebRTCMedia
import Testing

@Suite("H.264 RTP reorder packet index")
struct H264RTPReorderPacketIndexTests {
    @Test("Scaled sparse removal stays within logarithmic heap work")
    func scaledSparseRemovalHasDeterministicOperationBound() {
        for packetCount in [64, 256, 1_024, 4_096, 16_384] {
            var index = H264RTPReorderPacketIndex<Int>(
                recordsHeapOperations: true
            )

            for offset in 0..<packetCount {
                let rawSequenceNumber = (offset + 1) * 2
                index.insert(
                    offset,
                    sequenceNumber: UInt16(rawSequenceNumber),
                    extendedSequenceNumber: UInt64(rawSequenceNumber),
                    arrivalTimeNanoseconds: UInt64(packetCount - offset),
                    byteCount: 1
                )
            }

            #expect(index.count == packetCount)
            #expect(index.byteCount == packetCount)
            #expect(
                index.operationMetrics.retainedHeapNodeCount
                    == packetCount * 3
            )
            #expect(
                index.operationMetrics.retainedHeapPositionCount
                    == packetCount * 3
            )
            #expect(index.operationMetrics.heapPositionsAreConsistent)
            #expect(index.earliestArrivalTimeNanoseconds() == 1)

            var previousExtendedSequenceNumber: UInt64 = 0
            var removedPacketCount = 0
            while let removed = index.removeEarliest() {
                #expect(
                    removed.extendedSequenceNumber
                        > previousExtendedSequenceNumber
                )
                previousExtendedSequenceNumber =
                    removed.extendedSequenceNumber
                removedPacketCount += 1
            }

            let metrics = index.operationMetrics
            let heapHeight = binaryHeapHeight(for: packetCount)
            let comparisonBound = UInt64(packetCount)
                * UInt64(12 * (heapHeight + 1))
            #expect(removedPacketCount == packetCount)
            #expect(index.isEmpty)
            #expect(index.byteCount == 0)
            #expect(metrics.retainedHeapNodeCount == 0)
            #expect(metrics.retainedHeapPositionCount == 0)
            #expect(metrics.heapPositionsAreConsistent)
            #expect(metrics.heapInsertionCount == UInt64(packetCount * 3))
            #expect(metrics.heapRemovalCount == UInt64(packetCount * 3))
            #expect(metrics.heapComparisonCount <= comparisonBound)
            #expect(metrics.heapSwapCount <= metrics.heapComparisonCount)
            #expect(
                metrics.maximumComparisonCountPerHeapMutation
                    <= UInt64(2 * heapHeight + 1)
            )
        }
    }

    @Test("Constant-size churn has no periodic full-heap mutation")
    func constantSizeChurnKeepsPerMutationWorkLogarithmic() {
        let packetCount = 1_024
        let churnCount = packetCount * 8
        var index = H264RTPReorderPacketIndex<Int>(
            recordsHeapOperations: true
        )

        for sequenceNumber in 0..<packetCount {
            index.insert(
                sequenceNumber,
                sequenceNumber: UInt16(sequenceNumber),
                extendedSequenceNumber: UInt64(sequenceNumber),
                arrivalTimeNanoseconds: UInt64(sequenceNumber),
                byteCount: 1
            )
        }

        for mutation in 0..<churnCount {
            let sequenceNumber = UInt16(mutation % packetCount)
            let removed = index.remove(sequenceNumber: sequenceNumber)
            #expect(removed != nil)
            index.insert(
                mutation + packetCount,
                sequenceNumber: sequenceNumber,
                extendedSequenceNumber:
                    UInt64(mutation + packetCount),
                arrivalTimeNanoseconds:
                    UInt64(churnCount - mutation + packetCount),
                byteCount: 1
            )
        }

        let metrics = index.operationMetrics
        let heapHeight = binaryHeapHeight(for: packetCount)
        #expect(index.count == packetCount)
        #expect(index.byteCount == packetCount)
        #expect(metrics.retainedHeapNodeCount == packetCount * 3)
        #expect(metrics.retainedHeapPositionCount == packetCount * 3)
        #expect(metrics.heapPositionsAreConsistent)
        #expect(
            metrics.maximumComparisonCountPerHeapMutation
                <= UInt64(2 * heapHeight + 1)
        )
    }

    @Test("Removing and reinserting one raw sequence keeps heap identity exact")
    func sameSequenceReinsertionUsesNewIdentity() {
        var index = H264RTPReorderPacketIndex<Int>(
            recordsHeapOperations: true
        )
        index.insert(
            1,
            sequenceNumber: 7,
            extendedSequenceNumber: 7,
            arrivalTimeNanoseconds: 10,
            byteCount: 3
        )

        let first = index.remove(sequenceNumber: 7)
        #expect(first?.packet == 1)
        #expect(index.operationMetrics.retainedHeapNodeCount == 0)
        #expect(index.operationMetrics.heapPositionsAreConsistent)

        index.insert(
            2,
            sequenceNumber: 7,
            extendedSequenceNumber: 65_543,
            arrivalTimeNanoseconds: 20,
            byteCount: 5
        )

        #expect(index.earliestMetadata()?.extendedSequenceNumber == 65_543)
        #expect(index.earliestArrivalTimeNanoseconds() == 20)
        let second = index.removeFarthest()
        #expect(second?.packet == 2)
        #expect(second?.extendedSequenceNumber == 65_543)
        #expect(index.isEmpty)
        #expect(index.byteCount == 0)
        #expect(index.operationMetrics.retainedHeapNodeCount == 0)
        #expect(index.operationMetrics.retainedHeapPositionCount == 0)
        #expect(index.operationMetrics.heapPositionsAreConsistent)
    }

    private func binaryHeapHeight(for count: Int) -> Int {
        var height = 0
        var capacity = 1
        while capacity < count {
            capacity *= 2
            height += 1
        }
        return height
    }
}
