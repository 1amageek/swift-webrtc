import Testing
@testable import WebRTCMedia
@Suite("RFC 6184 H.264 packetizer")
struct H264PacketizerTests {
    private let packetizer = RFC6184H264Packetizer()
    private let encoder = RFC6184H264PayloadEncoder()

    @Test("Mode 0 emits one Single NAL layout per input NAL")
    func singleNALUnitMode() throws {
        let accessUnit: [UInt8] = [0x61, 1, 2, 0x65, 3]
        let ranges = [0..<3, 3..<5]
        let layouts = try packetize(
            accessUnit,
            ranges: ranges,
            mode: .singleNALUnit,
            maximumPayloadByteCount: 3
        )

        #expect(layouts.count == 2)
        #expect(layouts[0] == H264RTPPacketizationLayout(
            payload: .singleNALUnit(nalUnitRange: 0..<3),
            payloadByteCount: 3,
            isLastPacketOfAccessUnit: false
        ))
        #expect(layouts[1].isLastPacketOfAccessUnit)

        var encoded: [UInt8] = [0xAA]
        try encoder.appendPayload(
            layouts[1],
            from: accessUnit.span,
            nalUnitRanges: ranges.span,
            to: &encoded
        )
        #expect(encoded == [0xAA, 0x65, 3])
    }

    @Test("Mode 0 reports an oversized NAL instead of fragmenting it")
    func singleNALUnitModeRejectsOversizedNAL() {
        let accessUnit: [UInt8] = [0x65, 1, 2, 3]
        let ranges = [0..<4]

        #expect(throws: H264RTPPayloadError.nalUnitExceedsSingleNALMode(
            index: 0,
            byteCount: 4,
            limit: 3
        )) {
            try packetizer.forEachPacket(
                in: accessUnit.span,
                nalUnitRanges: ranges.span,
                mode: .singleNALUnit,
                maximumPayloadByteCount: 3
            ) { _ in }
        }
    }

    @Test("Mode 0 emits nothing when a later NAL is oversized")
    func singleNALUnitFailureIsTransactional() {
        let accessUnit: [UInt8] = [0x61, 0x65, 1, 2, 3]
        let ranges = [0..<1, 1..<5]
        var emissionCount = 0

        #expect(throws: H264RTPPayloadError.nalUnitExceedsSingleNALMode(
            index: 1,
            byteCount: 4,
            limit: 3
        )) {
            try packetizer.forEachPacket(
                in: accessUnit.span,
                nalUnitRanges: ranges.span,
                mode: .singleNALUnit,
                maximumPayloadByteCount: 3
            ) { _ in
                emissionCount += 1
            }
        }
        #expect(emissionCount == 0)
    }

    @Test("Mode 1 aggregates adjacent small NAL units into one STAP-A")
    func singleTimeAggregationPacketA() throws {
        let accessUnit: [UInt8] = [0x67, 1, 2, 0x48, 3]
        let ranges = [0..<3, 3..<5]
        let layouts = try packetize(
            accessUnit,
            ranges: ranges,
            mode: .nonInterleaved,
            maximumPayloadByteCount: 10
        )

        let layout = try #require(layouts.first)
        #expect(layouts.count == 1)
        #expect(layout.payloadByteCount == 10)
        #expect(layout.isLastPacketOfAccessUnit)
        #expect(layout.payload == .singleTimeAggregationPacketA(
            indicator: 0x78,
            nalUnitIndices: 0..<2
        ))

        var encoded = [UInt8]()
        try encoder.appendPayload(
            layout,
            from: accessUnit.span,
            nalUnitRanges: ranges.span,
            to: &encoded
        )
        #expect(encoded == [
            0x78,
            0x00, 0x03, 0x67, 1, 2,
            0x00, 0x02, 0x48, 3,
        ])
    }

    @Test("STAP-A is not emitted when fewer than two NAL units fit")
    func aggregationRequiresTwoUnits() throws {
        let accessUnit: [UInt8] = [0x61, 1, 0x61, 2]
        let ranges = [0..<2, 2..<4]
        let layouts = try packetize(
            accessUnit,
            ranges: ranges,
            mode: .nonInterleaved,
            maximumPayloadByteCount: 6
        )

        #expect(layouts.count == 2)
        for layout in layouts {
            guard case .singleNALUnit = layout.payload else {
                Issue.record("Expected a Single NAL layout")
                continue
            }
        }
    }

    @Test("FU-A fragments cover the source exactly once and mark only the final fragment")
    func fragmentationUnitA() throws {
        let accessUnit: [UInt8] = [0x65, 1, 2, 3, 4, 5]
        let ranges = [0..<6]
        let layouts = try packetize(
            accessUnit,
            ranges: ranges,
            mode: .nonInterleaved,
            maximumPayloadByteCount: 4
        )

        #expect(layouts.count == 3)
        let expectedRanges = [1..<3, 3..<5, 5..<6]
        let expectedHeaders: [UInt8] = [0x85, 0x05, 0x45]
        var recovered = [UInt8](arrayLiteral: accessUnit[0])

        for index in layouts.indices {
            let layout = layouts[index]
            guard case .fragmentationUnitA(
                let indicator,
                let header,
                let nalUnitRange,
                let fragmentRange
            ) = layout.payload else {
                Issue.record("Expected FU-A")
                continue
            }
            #expect(indicator == 0x7C)
            #expect(header == expectedHeaders[index])
            #expect(nalUnitRange == 0..<6)
            #expect(fragmentRange == expectedRanges[index])
            #expect(layout.payloadByteCount <= 4)
            #expect(layout.isLastPacketOfAccessUnit == (index == 2))

            var encoded = [UInt8]()
            try encoder.appendPayload(
                layout,
                from: accessUnit.span,
                nalUnitRanges: ranges.span,
                to: &encoded
            )
            #expect(encoded[0] == indicator)
            #expect(encoded[1] == header)
            recovered.append(contentsOf: encoded.dropFirst(2))
        }
        #expect(recovered == accessUnit)
    }

    @Test("FU-A requires room for indicator, header, and a nonempty fragment")
    func fragmentationMinimumPayload() {
        let accessUnit: [UInt8] = [0x65, 1, 2]
        let ranges = [0..<3]

        #expect(throws: H264RTPPayloadError.fragmentationPayloadTooSmall(
            maximumPayloadByteCount: 2
        )) {
            try packetizer.forEachPacket(
                in: accessUnit.span,
                nalUnitRanges: ranges.span,
                mode: .nonInterleaved,
                maximumPayloadByteCount: 2
            ) { _ in }
        }
    }

    @Test("Mode 1 emits nothing when a later NAL cannot be fragmented")
    func nonInterleavedFailureIsTransactional() {
        let accessUnit: [UInt8] = [0x61, 0x65, 1, 2]
        let ranges = [0..<1, 1..<4]
        var emissionCount = 0

        #expect(throws: H264RTPPayloadError.fragmentationPayloadTooSmall(
            maximumPayloadByteCount: 2
        )) {
            try packetizer.forEachPacket(
                in: accessUnit.span,
                nalUnitRanges: ranges.span,
                mode: .nonInterleaved,
                maximumPayloadByteCount: 2
            ) { _ in
                emissionCount += 1
            }
        }
        #expect(emissionCount == 0)
    }

    @Test("Mode 2 is an explicit typed unsupported result")
    func interleavedModeUnsupported() {
        let accessUnit: [UInt8] = [0x61]
        let ranges = [0..<1]

        #expect(throws: H264RTPPayloadError.unsupportedPacketizationMode(.interleaved)) {
            try packetizer.forEachPacket(
                in: accessUnit.span,
                nalUnitRanges: ranges.span,
                mode: .interleaved,
                maximumPayloadByteCount: 1200
            ) { _ in }
        }
    }

    @Test("Range validation rejects empty, out-of-owner, overlap, and Annex B framing")
    func rangeValidation() {
        let accessUnit: [UInt8] = [0x61, 1, 0x61, 2]

        let emptyRanges: [Range<Int>] = []
        #expect(throws: H264RTPPayloadError.emptyAccessUnit) {
            try packetizer.forEachPacket(
                in: accessUnit.span,
                nalUnitRanges: emptyRanges.span,
                mode: .nonInterleaved,
                maximumPayloadByteCount: 10
            ) { _ in }
        }

        let emptyNAL = [0..<0]
        #expect(throws: H264RTPPayloadError.emptyNALUnit(index: 0)) {
            try packetizer.forEachPacket(
                in: accessUnit.span,
                nalUnitRanges: emptyNAL.span,
                mode: .nonInterleaved,
                maximumPayloadByteCount: 10
            ) { _ in }
        }

        let outside = [0..<5]
        #expect(throws: H264RTPPayloadError.nalUnitRangeOutOfBounds(
            index: 0,
            lowerBound: 0,
            upperBound: 5,
            ownerByteCount: 4
        )) {
            try packetizer.forEachPacket(
                in: accessUnit.span,
                nalUnitRanges: outside.span,
                mode: .nonInterleaved,
                maximumPayloadByteCount: 10
            ) { _ in }
        }

        let overlap = [0..<3, 2..<4]
        #expect(throws: H264RTPPayloadError.unorderedOrOverlappingNALUnitRange(index: 1)) {
            try packetizer.forEachPacket(
                in: accessUnit.span,
                nalUnitRanges: overlap.span,
                mode: .nonInterleaved,
                maximumPayloadByteCount: 10
            ) { _ in }
        }

        let annexB: [UInt8] = [0, 0, 0, 1, 0x65, 1]
        let annexBRange = [0..<6]
        #expect(throws: H264RTPPayloadError.reservedNALUnitType(0)) {
            try packetizer.forEachPacket(
                in: annexB.span,
                nalUnitRanges: annexBRange.span,
                mode: .nonInterleaved,
                maximumPayloadByteCount: 10
            ) { _ in }
        }

        let forbidden: [UInt8] = [0xE1]
        let singleByteRange = [0..<1]
        #expect(throws: H264RTPPayloadError.forbiddenBitSet) {
            try packetizer.forEachPacket(
                in: forbidden.span,
                nalUnitRanges: singleByteRange.span,
                mode: .nonInterleaved,
                maximumPayloadByteCount: 10
            ) { _ in }
        }

        let packetizationUnit: [UInt8] = [0x78]
        #expect(throws: H264RTPPayloadError.packetizationUnitProvidedAsNALUnit(
            index: 0,
            type: 24
        )) {
            try packetizer.forEachPacket(
                in: packetizationUnit.span,
                nalUnitRanges: singleByteRange.span,
                mode: .nonInterleaved,
                maximumPayloadByteCount: 10
            ) { _ in }
        }
    }

    @Test("Encoder reports destination capacity overflow as a typed failure")
    func encoderCapacityOverflow() {
        let accessUnit: [UInt8] = [0x61]
        let ranges = [0..<1]
        let layout = H264RTPPacketizationLayout(
            payload: .singleNALUnit(nalUnitRange: 0..<1),
            payloadByteCount: .max,
            isLastPacketOfAccessUnit: true
        )
        var destination: [UInt8] = [0]

        #expect(throws: H264RTPPayloadError.integerOverflow) {
            try encoder.appendPayload(
                layout,
                from: accessUnit.span,
                nalUnitRanges: ranges.span,
                to: &destination
            )
        }
        #expect(destination == [0])
    }

    @Test("Encoder validates forged layout sizes before allocation or mutation")
    func encoderRejectsForgedLayoutSizes() {
        let accessUnit: [UInt8] = [0x61]
        let ranges = [0..<1]
        let forgedByteCounts = [Int.max, -1]

        for forgedByteCount in forgedByteCounts {
            let layout = H264RTPPacketizationLayout(
                payload: .singleNALUnit(nalUnitRange: 0..<1),
                payloadByteCount: forgedByteCount,
                isLastPacketOfAccessUnit: true
            )
            var destination: [UInt8] = []

            #expect(throws: H264RTPPayloadError.invalidPacketizationLayout) {
                try encoder.appendPayload(
                    layout,
                    from: accessUnit.span,
                    nalUnitRanges: ranges.span,
                    to: &destination
                )
            }
            #expect(destination.isEmpty)
        }
    }

    @Test("Encoder leaves destination unchanged when structural validation fails")
    func encoderFailureIsTransactional() {
        let accessUnit: [UInt8] = [0x67, 1, 0x68, 2]
        let ranges = [0..<2, 2..<4]
        let layout = H264RTPPacketizationLayout(
            payload: .singleTimeAggregationPacketA(
                indicator: 0x18,
                nalUnitIndices: 0..<2
            ),
            payloadByteCount: 9,
            isLastPacketOfAccessUnit: true
        )
        var destination: [UInt8] = [0xAA]

        #expect(throws: H264RTPPayloadError.invalidPacketizationLayout) {
            try encoder.appendPayload(
                layout,
                from: accessUnit.span,
                nalUnitRanges: ranges.span,
                to: &destination
            )
        }
        #expect(destination == [0xAA])
    }

    @Test("Traversal stops before enumerating remaining FU-A fragments")
    func traversalStopsImmediately() throws {
        var accessUnit: [UInt8] = [0x65]
        accessUnit.append(contentsOf: repeatElement(1, count: 10_000))
        let ranges = [0..<accessUnit.count]
        var visitCount = 0

        let outcome = try packetizer.traversePackets(
            in: accessUnit.span,
            nalUnitRanges: ranges.span,
            mode: .nonInterleaved,
            maximumPayloadByteCount: 3
        ) { _ in
            visitCount += 1
            return visitCount == 2 ? .stop : .proceed
        }

        #expect(outcome == .stopped)
        #expect(visitCount == 2)
    }

    private func packetize(
        _ accessUnit: [UInt8],
        ranges: [Range<Int>],
        mode: H264PacketizationMode,
        maximumPayloadByteCount: Int
    ) throws -> [H264RTPPacketizationLayout] {
        var layouts = [H264RTPPacketizationLayout]()
        try packetizer.forEachPacket(
            in: accessUnit.span,
            nalUnitRanges: ranges.span,
            mode: mode,
            maximumPayloadByteCount: maximumPayloadByteCount
        ) { layout in
            layouts.append(layout)
        }
        return layouts
    }
}
