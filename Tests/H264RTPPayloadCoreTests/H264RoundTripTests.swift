import Testing
@testable import WebRTCMedia
@Suite("RFC 6184 H.264 payload round trips")
struct H264RoundTripTests {
    @Test(
        "FU-A packetization and parsing reconstruct every tested NAL size",
        arguments: [3, 4, 5, 16, 1_024], [3, 4, 7, 120]
    )
    func fragmentationRoundTrip(
        nalUnitByteCount: Int,
        maximumPayloadByteCount: Int
    ) throws {
        guard nalUnitByteCount > maximumPayloadByteCount else { return }

        var nalUnit = [UInt8](repeating: 0, count: nalUnitByteCount)
        nalUnit[0] = 0x65
        for index in 1..<nalUnit.count {
            nalUnit[index] = UInt8(truncatingIfNeeded: index)
        }
        let ranges = [0..<nalUnit.count]
        let packetizer = RFC6184H264Packetizer()
        let encoder = RFC6184H264PayloadEncoder()
        let parser = RFC6184H264PayloadParser()
        var recovered = [UInt8]()
        var fragmentCount = 0

        try packetizer.forEachPacket(
            in: nalUnit.span,
            nalUnitRanges: ranges.span,
            mode: .nonInterleaved,
            maximumPayloadByteCount: maximumPayloadByteCount
        ) { packetizationLayout in
            var payload = [UInt8]()
            do {
                try encoder.appendPayload(
                    packetizationLayout,
                    from: nalUnit.span,
                    nalUnitRanges: ranges.span,
                    to: &payload
                )
                let parsed = try parser.layout(
                    in: payload.span,
                    mode: .nonInterleaved
                )
                guard case .fragmentationUnitA(let fragment) = parsed.structure else {
                    Issue.record("Expected FU-A")
                    return
                }
                if fragment.isStart {
                    recovered.append(fragment.originalNALUnitHeader.rawValue)
                }
                for index in fragment.fragmentRange {
                    recovered.append(payload[index])
                }
                fragmentCount += 1
            } catch {
                Issue.record("Unexpected round-trip error: \(error)")
            }
        }

        #expect(fragmentCount >= 2)
        #expect(recovered == nalUnit)
    }

    @Test("STAP-A packetization and parsing preserve NAL order and bytes")
    func aggregationRoundTrip() throws {
        let accessUnit: [UInt8] = [0x67, 1, 2, 0x68, 3, 0x61, 4]
        let ranges = [0..<3, 3..<5, 5..<7]
        let packetizer = RFC6184H264Packetizer()
        let encoder = RFC6184H264PayloadEncoder()
        let parser = RFC6184H264PayloadParser()
        var emittedPayload: [UInt8]?

        try packetizer.forEachPacket(
            in: accessUnit.span,
            nalUnitRanges: ranges.span,
            mode: .nonInterleaved,
            maximumPayloadByteCount: 16
        ) { layout in
            var payload = [UInt8]()
            do {
                try encoder.appendPayload(
                    layout,
                    from: accessUnit.span,
                    nalUnitRanges: ranges.span,
                    to: &payload
                )
                emittedPayload = payload
            } catch {
                Issue.record("Unexpected encode error: \(error)")
            }
        }

        let payload = try #require(emittedPayload)
        let parsed = try parser.layout(in: payload.span, mode: .nonInterleaved)
        guard case .singleTimeAggregationPacketA(let aggregation) = parsed.structure else {
            Issue.record("Expected STAP-A")
            return
        }
        var recovered = [[UInt8]]()
        try aggregation.forEachNALUnit(in: payload.span) { nalUnit in
            recovered.append(Array(payload[nalUnit.range]))
        }
        #expect(recovered == [
            Array(accessUnit[0..<3]),
            Array(accessUnit[3..<5]),
            Array(accessUnit[5..<7]),
        ])
    }
}
