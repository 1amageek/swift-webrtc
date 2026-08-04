import Testing
@testable import WebRTCMedia
@Suite("H264RTPPayloadCore performance")
struct H264PayloadEncodingPerformanceTests {
    private static let byteCounts = [4 * 1_024, 64 * 1_024]
    private static let bytesPerBatch = 16 * 1_024 * 1_024
    private static let batchCount = 3
    private static let maximumBulkToScalarLatencyRatio = 0.5

    @Test(
        "Contiguous payload materialization remains faster than scalar append",
        .timeLimit(.minutes(1)),
        arguments: byteCounts
    )
    func bulkMaterialization(byteCount: Int) throws {
        var source = [UInt8](repeating: 0, count: byteCount)
        source[0] = 0x65
        for index in 1..<source.count {
            source[index] = UInt8(truncatingIfNeeded: index)
        }
        let ranges = [0..<source.count]
        let layout = H264RTPPacketizationLayout(
            payload: .singleNALUnit(nalUnitRange: ranges[0]),
            payloadByteCount: source.count,
            isLastPacketOfAccessUnit: true
        )
        let iterations = max(1, Self.bytesPerBatch / byteCount)
        let encoder = RFC6184H264PayloadEncoder()

        var bulkChecksum: UInt64 = 0
        var bulk = [UInt8]()
        bulk.reserveCapacity(byteCount)
        let bulkLatency = try fastestNanosecondsPerIteration(
            iterations: iterations
        ) {
            bulk.removeAll(keepingCapacity: true)
            try encoder.appendPayload(
                layout,
                from: source.span,
                nalUnitRanges: ranges.span,
                to: &bulk
            )
            bulkChecksum &+= consumedValue(bulk)
        }

        var scalarChecksum: UInt64 = 0
        var scalar = [UInt8]()
        scalar.reserveCapacity(byteCount)
        let scalarLatency = fastestNanosecondsPerIteration(
            iterations: iterations
        ) {
            scalar.removeAll(keepingCapacity: true)
            for byte in source {
                scalar.append(byte)
            }
            scalarChecksum &+= consumedValue(scalar)
        }

        let ratio = bulkLatency / scalarLatency
        print(
            "H.264 payload \(byteCount) bytes: bulk \(bulkLatency) ns, "
                + "scalar \(scalarLatency) ns, ratio \(ratio)"
        )
        #expect(bulk == source)
        #expect(scalar == source)
        #expect(bulkChecksum != 0)
        #expect(scalarChecksum != 0)
        #expect(ratio <= Self.maximumBulkToScalarLatencyRatio)
    }

    private func fastestNanosecondsPerIteration(
        iterations: Int,
        _ operation: () throws -> Void
    ) rethrows -> Double {
        for _ in 0..<min(iterations, 16) {
            try operation()
        }

        var fastest = Double.greatestFiniteMagnitude
        let clock = ContinuousClock()
        for _ in 0..<Self.batchCount {
            let start = clock.now
            for _ in 0..<iterations {
                try operation()
            }
            let elapsed = clock.now - start
            fastest = min(
                fastest,
                nanoseconds(elapsed) / Double(iterations)
            )
        }
        return fastest
    }

    private func consumedValue(_ bytes: [UInt8]) -> UInt64 {
        UInt64(bytes.count)
            &+ UInt64(bytes[0])
            &+ UInt64(bytes[bytes.count / 2])
            &+ UInt64(bytes[bytes.count - 1])
    }

    private func nanoseconds(_ duration: Duration) -> Double {
        let components = duration.components
        return Double(components.seconds) * 1_000_000_000
            + Double(components.attoseconds) / 1_000_000_000
    }
}
