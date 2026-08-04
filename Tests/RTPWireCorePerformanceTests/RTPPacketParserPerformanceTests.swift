import Testing
@testable import WebRTC
@Suite("RTPWireCore performance")
struct RTPPacketParserPerformanceTests {
    private static let packetByteCounts = [12, 1_200, 65_535]
    private static let batchCount = 7
    private static let parsesPerBatch = 20_000
    private static let warmupParses = 2_000

    // This tolerance is an asymptotic regression gate, not proof of an
    // allocation budget. Source audit and allocation instrumentation own that
    // separate contract; see Sources/WebRTC/Transport/RTP/CONTEXT.md.
    private static let maximumNormalizedLatency = 3.0
    private static let maximumNormalizedSlope = 2.0

    @Test(
        "RTP parsing latency is independent of payload length",
        .timeLimit(.minutes(1))
    )
    func payloadLengthIndependence() throws {
        let measurements = try Self.packetByteCounts.map(measurePacket)
        let baselineNanoseconds = measurements[0].nanosecondsPerParse
        let normalizedLatencies = measurements.map {
            $0.nanosecondsPerParse / baselineNanoseconds
        }
        let normalizedSlope = leastSquaresSlope(
            x: Self.packetByteCounts.map(normalizedPacketLength),
            y: normalizedLatencies
        )

        for measurement in measurements {
            print(measurement)
            #expect(measurement.checksum != 0)
        }
        print("normalized payload-length slope: \(normalizedSlope)")

        #expect(normalizedLatencies.allSatisfy {
            $0 <= Self.maximumNormalizedLatency
        })
        #expect(normalizedSlope <= Self.maximumNormalizedSlope)
    }

    private func measurePacket(byteCount: Int) throws -> RTPBatchMeasurement {
        var packet = [UInt8](repeating: 0x42, count: byteCount)
        packet[0] = 0x80
        packet[1] = 96
        packet[2] = 0x12
        packet[3] = 0x34

        let parser = RFC3550RTPPacketParser()
        var checksum: UInt64 = 0
        for _ in 0..<Self.warmupParses {
            let layout = try parser.layout(in: packet.span)
            checksum &+= consumedValue(from: layout)
        }

        let clock = ContinuousClock()
        var fastestNanosecondsPerParse = Double.greatestFiniteMagnitude
        for _ in 0..<Self.batchCount {
            var batchChecksum: UInt64 = 0
            let start = clock.now
            for _ in 0..<Self.parsesPerBatch {
                let layout = try parser.layout(in: packet.span)
                batchChecksum &+= consumedValue(from: layout)
            }
            let elapsed = clock.now - start
            let nanosecondsPerParse = nanoseconds(elapsed) / Double(Self.parsesPerBatch)
            fastestNanosecondsPerParse = min(
                fastestNanosecondsPerParse,
                nanosecondsPerParse
            )
            checksum &+= batchChecksum
        }

        return RTPBatchMeasurement(
            packetByteCount: byteCount,
            nanosecondsPerParse: fastestNanosecondsPerParse,
            checksum: checksum
        )
    }

    private func consumedValue(from layout: RTPPacketLayout) -> UInt64 {
        UInt64(layout.fixedHeader.sequenceNumber)
            &+ UInt64(layout.payloadRange.lowerBound)
            &+ UInt64(layout.payloadRange.upperBound)
    }

    private func normalizedPacketLength(_ byteCount: Int) -> Double {
        let minimum = Self.packetByteCounts[0]
        let maximum = Self.packetByteCounts[Self.packetByteCounts.count - 1]
        return Double(byteCount - minimum) / Double(maximum - minimum)
    }

    private func leastSquaresSlope(x: [Double], y: [Double]) -> Double {
        precondition(x.count == y.count && !x.isEmpty)
        let count = Double(x.count)
        let meanX = x.reduce(0, +) / count
        let meanY = y.reduce(0, +) / count
        var covariance = 0.0
        var variance = 0.0
        for index in x.indices {
            let centeredX = x[index] - meanX
            covariance += centeredX * (y[index] - meanY)
            variance += centeredX * centeredX
        }
        precondition(variance > 0)
        return covariance / variance
    }

    private func nanoseconds(_ duration: Duration) -> Double {
        let components = duration.components
        return Double(components.seconds) * 1_000_000_000
            + Double(components.attoseconds) / 1_000_000_000
    }
}

private struct RTPBatchMeasurement: CustomStringConvertible {
    let packetByteCount: Int
    let nanosecondsPerParse: Double
    let checksum: UInt64

    var description: String {
        "RTP parser \(packetByteCount) bytes: \(nanosecondsPerParse) ns/parse"
    }
}
