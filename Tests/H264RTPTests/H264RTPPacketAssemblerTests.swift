import Testing
@testable import WebRTCMedia
@testable import WebRTC

@Suite("H.264 RTP packet assembly")
struct H264RTPPacketAssemblerTests {
    @Test("A single NAL is assembled into one marked RTP packet")
    func singleNALUnitPacket() throws {
        let accessUnit: [UInt8] = [0x65, 1, 2, 3]
        let ranges = [0..<accessUnit.count]
        let payloadLayout = try firstLayout(
            accessUnit: accessUnit,
            ranges: ranges,
            maximumPayloadByteCount: 1_178
        )
        let noExtension: [UInt8] = []

        let packet = try RFC6184H264RTPPacketAssembler().packet(
            header: H264RTPPacketHeader(
                payloadType: 96,
                sequenceNumber: 7,
                timestamp: 90_000,
                synchronizationSource: 0x11223344
            ),
            payloadLayout: payloadLayout,
            accessUnit: accessUnit.span,
            nalUnitRanges: ranges.span,
            extensionProfile: nil,
            extensionData: noExtension.span,
            maximumDatagramByteCount: 1_200,
            protectionTrailerByteCount: 10
        )

        let rtp = try RFC3550RTPPacketParser().layout(in: packet.span)
        #expect(rtp.fixedHeader.marker)
        #expect(rtp.fixedHeader.payloadType == 96)
        #expect(rtp.fixedHeader.sequenceNumber == 7)
        #expect(rtp.fixedHeader.timestamp == 90_000)
        #expect(rtp.fixedHeader.synchronizationSource == 0x11223344)
        #expect(Array(packet[rtp.payloadRange]) == accessUnit)
    }

    @Test("FU-A packets derive marker state from the access-unit layout")
    func fragmentationMarkerContract() throws {
        let accessUnit: [UInt8] = [0x65, 1, 2, 3, 4, 5]
        let ranges = [0..<accessUnit.count]
        let noExtension: [UInt8] = []
        var layouts: [H264RTPPacketizationLayout] = []
        try RFC6184H264Packetizer().forEachPacket(
            in: accessUnit.span,
            nalUnitRanges: ranges.span,
            mode: .nonInterleaved,
            maximumPayloadByteCount: 4
        ) { layouts.append($0) }

        #expect(layouts.count == 3)
        for index in layouts.indices {
            let packet = try RFC6184H264RTPPacketAssembler().packet(
                header: H264RTPPacketHeader(
                    payloadType: 96,
                    sequenceNumber: UInt16(index),
                    timestamp: 90_000,
                    synchronizationSource: 1
                ),
                payloadLayout: layouts[index],
                accessUnit: accessUnit.span,
                nalUnitRanges: ranges.span,
                extensionProfile: nil,
                extensionData: noExtension.span,
                maximumDatagramByteCount: 26,
                protectionTrailerByteCount: 10
            )
            let rtp = try RFC3550RTPPacketParser().layout(in: packet.span)
            #expect(rtp.fixedHeader.marker == (index == layouts.count - 1))
            #expect(rtp.fixedHeader.sequenceNumber == UInt16(index))
            let payload = Array(packet[rtp.payloadRange])
            let h264 = try RFC6184H264PayloadParser().layout(
                in: payload.span,
                mode: .nonInterleaved
            )
            guard case .fragmentationUnitA = h264.structure else {
                Issue.record("Expected FU-A payload")
                continue
            }
        }
    }

    @Test("The protected datagram limit is enforced before payload materialization")
    func protectedDatagramLimit() throws {
        let accessUnit: [UInt8] = [0x65, 1, 2, 3]
        let ranges = [0..<accessUnit.count]
        let payloadLayout = try firstLayout(
            accessUnit: accessUnit,
            ranges: ranges,
            maximumPayloadByteCount: 1_178
        )
        let noExtension: [UInt8] = []

        #expect(throws: H264RTPPacketError.packetExceedsMaximum(
            actual: 26,
            maximum: 25
        )) {
            try RFC6184H264RTPPacketAssembler().packet(
                header: H264RTPPacketHeader(
                    payloadType: 96,
                    sequenceNumber: 0,
                    timestamp: 0,
                    synchronizationSource: 1
                ),
                payloadLayout: payloadLayout,
                accessUnit: accessUnit.span,
                nalUnitRanges: ranges.span,
                extensionProfile: nil,
                extensionData: noExtension.span,
                maximumDatagramByteCount: 25,
                protectionTrailerByteCount: 10
            )
        }
    }

    private func firstLayout(
        accessUnit: [UInt8],
        ranges: [Range<Int>],
        maximumPayloadByteCount: Int
    ) throws -> H264RTPPacketizationLayout {
        var first: H264RTPPacketizationLayout?
        try RFC6184H264Packetizer().forEachPacket(
            in: accessUnit.span,
            nalUnitRanges: ranges.span,
            mode: .nonInterleaved,
            maximumPayloadByteCount: maximumPayloadByteCount
        ) { layout in
            if first == nil {
                first = layout
            }
        }
        return try #require(first)
    }
}
