import Testing
@testable import WebRTCMedia
@Suite("RFC 6184 H.264 payload parser")
struct H264PayloadParserTests {
    private let parser = RFC6184H264PayloadParser()

    @Test("Single NAL parsing returns a range into the original owner")
    func singleNALUnit() throws {
        let payload: [UInt8] = [0x65, 1, 2, 3]
        let layout = try parser.layout(in: payload.span, mode: .singleNALUnit)

        #expect(layout.payloadByteCount == payload.count)
        guard case .singleNALUnit(let nalUnit) = layout.structure else {
            Issue.record("Expected Single NAL")
            return
        }
        #expect(nalUnit.header.unitType == 5)
        #expect(nalUnit.header.referenceIndicator == 3)
        #expect(nalUnit.range == 0..<4)
        #expect(payload.span.extracting(nalUnit.range)[1] == 1)
    }

    @Test("STAP-A parsing and iteration retain exact owner ranges")
    func singleTimeAggregationPacketA() throws {
        let payload: [UInt8] = [
            0x78,
            0x00, 0x03, 0x67, 1, 2,
            0x00, 0x02, 0x48, 3,
        ]
        let layout = try parser.layout(in: payload.span, mode: .nonInterleaved)
        guard case .singleTimeAggregationPacketA(let aggregation) = layout.structure else {
            Issue.record("Expected STAP-A")
            return
        }

        #expect(aggregation.unitCount == 2)
        #expect(aggregation.aggregationUnitsRange == 1..<10)
        var nalUnits = [H264NALUnitLayout]()
        try aggregation.forEachNALUnit(in: payload.span) { nalUnits.append($0) }
        #expect(nalUnits.count == 2)
        #expect(nalUnits[0].range == 3..<6)
        #expect(nalUnits[1].range == 8..<10)
        #expect(nalUnits[0].header.unitType == 7)
        #expect(nalUnits[1].header.unitType == 8)
    }

    @Test("STAP-A validates every length boundary and nested payload type")
    func malformedSingleTimeAggregationPacketA() {
        let fixtures: [([UInt8], H264RTPPayloadError)] = [
            ([0x78], .emptySingleTimeAggregationPacketA),
            ([0x78, 0], .truncatedAggregationUnitHeader(offset: 1, availableBytes: 1)),
            ([0x78, 0, 0], .emptyAggregationUnit(index: 0)),
            ([0x78, 0, 3, 0x67], .invalidAggregationUnitLength(
                index: 0,
                declaredBytes: 3,
                availableBytes: 1
            )),
            ([0x78, 0, 1, 0x78], .packetizationUnitProvidedAsNALUnit(
                index: 0,
                type: 24
            )),
            ([0x58, 0, 1, 0x67], .inconsistentSingleTimeAggregationPacketAIndicator),
        ]

        for (payload, expected) in fixtures {
            #expect(throws: expected) {
                try parser.layout(in: payload.span, mode: .nonInterleaved)
            }
        }
    }

    @Test("FU-A exposes the reconstructed NAL header and fragment range")
    func fragmentationUnitA() throws {
        let startPayload: [UInt8] = [0x7C, 0x85, 1, 2]
        let startLayout = try parser.layout(
            in: startPayload.span,
            mode: .nonInterleaved
        )
        guard case .fragmentationUnitA(let fragment) = startLayout.structure else {
            Issue.record("Expected FU-A")
            return
        }
        #expect(fragment.isStart)
        #expect(!fragment.isEnd)
        #expect(fragment.originalNALUnitHeader.rawValue == 0x65)
        #expect(fragment.fragmentRange == 2..<4)

        // RFC 6184 permits an empty FU payload. The reassembly layer owns
        // fragment-count and age limits, not this pure payload parser.
        let emptyEnd: [UInt8] = [0x7C, 0x45]
        let emptyLayout = try parser.layout(in: emptyEnd.span, mode: .nonInterleaved)
        guard case .fragmentationUnitA(let emptyFragment) = emptyLayout.structure else {
            Issue.record("Expected FU-A")
            return
        }
        #expect(emptyFragment.isEnd)
        #expect(emptyFragment.fragmentRange.isEmpty)
    }

    @Test("FU-A ignores the receiver-side reserved bit but rejects malformed semantics")
    func fragmentationUnitAValidation() throws {
        let reservedBit: [UInt8] = [0x7C, 0xA5, 1]
        let layout = try parser.layout(in: reservedBit.span, mode: .nonInterleaved)
        guard case .fragmentationUnitA(let fragment) = layout.structure else {
            Issue.record("Expected FU-A")
            return
        }
        #expect(fragment.isStart)

        let fixtures: [([UInt8], H264RTPPayloadError)] = [
            ([0x7C], .truncatedFragmentationUnitA(availableBytes: 1)),
            ([0x7C, 0xC5], .fragmentationUnitAStartAndEndSet),
            ([0x7C, 0x80], .invalidFragmentationUnitAType(0)),
            ([0x7C, 0x98], .invalidFragmentationUnitAType(24)),
        ]
        for (payload, expected) in fixtures {
            #expect(throws: expected) {
                try parser.layout(in: payload.span, mode: .nonInterleaved)
            }
        }
    }

    @Test("Packetization modes reject structures outside their negotiated contract")
    func modeValidation() {
        let stapA: [UInt8] = [0x78, 0, 1, 0x67]
        let fuA: [UInt8] = [0x7C, 0x85, 1]
        let stapB: [UInt8] = [0x79, 0, 0]
        let single: [UInt8] = [0x61]

        #expect(throws: H264RTPPayloadError.packetTypeNotAllowed(
            mode: .singleNALUnit,
            type: 24
        )) {
            try parser.layout(in: stapA.span, mode: .singleNALUnit)
        }
        #expect(throws: H264RTPPayloadError.packetTypeNotAllowed(
            mode: .singleNALUnit,
            type: 28
        )) {
            try parser.layout(in: fuA.span, mode: .singleNALUnit)
        }
        #expect(throws: H264RTPPayloadError.packetTypeNotAllowed(
            mode: .nonInterleaved,
            type: 25
        )) {
            try parser.layout(in: stapB.span, mode: .nonInterleaved)
        }
        #expect(throws: H264RTPPayloadError.unsupportedPacketizationMode(.interleaved)) {
            try parser.layout(in: single.span, mode: .interleaved)
        }
    }

    @Test("Empty, forbidden, and reserved payload headers fail explicitly")
    func headerValidation() {
        let empty: [UInt8] = []
        let forbidden: [UInt8] = [0xE5]
        let reservedZero: [UInt8] = [0]
        let reservedThirty: [UInt8] = [30]

        #expect(throws: H264RTPPayloadError.emptyPayload) {
            try parser.layout(in: empty.span, mode: .nonInterleaved)
        }
        #expect(throws: H264RTPPayloadError.forbiddenBitSet) {
            try parser.layout(in: forbidden.span, mode: .nonInterleaved)
        }
        #expect(throws: H264RTPPayloadError.reservedNALUnitType(0)) {
            try parser.layout(in: reservedZero.span, mode: .nonInterleaved)
        }
        #expect(throws: H264RTPPayloadError.reservedNALUnitType(30)) {
            try parser.layout(in: reservedThirty.span, mode: .nonInterleaved)
        }
    }

    @Test("A STAP-A layout rejects a substituted owner")
    func aggregationOwnerMismatch() throws {
        let payload: [UInt8] = [0x78, 0, 1, 0x67]
        let layout = try parser.layout(in: payload.span, mode: .nonInterleaved)
        guard case .singleTimeAggregationPacketA(let aggregation) = layout.structure else {
            Issue.record("Expected STAP-A")
            return
        }
        let wrongOwner: [UInt8] = [0x78]
        #expect(throws: H264RTPPayloadError.payloadOwnerByteCountMismatch(
            expected: 4,
            actual: 1
        )) {
            try aggregation.forEachNALUnit(in: wrongOwner.span) { _ in }
        }
    }
}
