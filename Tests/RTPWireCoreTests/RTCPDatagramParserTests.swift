import Testing
@testable import WebRTC
@Suite("RTCP datagram parser")
struct RTCPDatagramParserTests {
    private let parser = RFC3550RTCPDatagramParser()

    private var receiverReport: [UInt8] {
        [0x80, 0xC9, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44]
    }

    private var matchingSourceDescription: [UInt8] {
        [
            0x81, 0xCA, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x01, 0x01, 0x61, 0x00,
        ]
    }

    @Test("Minimal RR plus matching SDES CNAME is valid compound RTCP")
    func minimalCompound() throws {
        let bytes = receiverReport + matchingSourceDescription

        let layout = try parser.layout(in: bytes.span, framing: .compound)

        #expect(layout.packetLayouts.count == 2)
        #expect(layout.packetLayouts[0].commonHeader.packetType == 201)
        #expect(layout.packetLayouts[1].commonHeader.packetType == 202)
        #expect(layout.byteCount == bytes.count)
    }

    @Test("A lone RR is reduced-size data but not compound RTCP")
    func framingContractsDiffer() throws {
        let bytes = receiverReport

        let reduced = try parser.layout(in: bytes.span, framing: .reducedSize)
        #expect(reduced.packetLayouts.count == 1)
        #expect(throws: RTPWireError.compoundRequiresMultiplePackets(actual: 1)) {
            try parser.layout(in: bytes.span, framing: .compound)
        }
    }

    @Test("A reduced-size PLI packet is accepted without SR, RR, or SDES")
    func reducedSizePLI() throws {
        let bytes: [UInt8] = [
            0x81, 0xCE, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88,
        ]

        let layout = try parser.layout(in: bytes.span, framing: .reducedSize)

        #expect(layout.packetLayouts.count == 1)
        #expect(layout.packetLayouts[0].commonHeader.countOrFormat == 1)
        #expect(layout.packetLayouts[0].commonHeader.packetType == 206)
    }

    @Test("Unknown subsequent RTCP packet types remain in the layout")
    func unknownPacketType() throws {
        let unknown: [UInt8] = [0x80, 0xD0, 0x00, 0x00]
        let bytes = receiverReport + matchingSourceDescription + unknown

        let layout = try parser.layout(in: bytes.span, framing: .compound)

        #expect(layout.packetLayouts.count == 3)
        #expect(layout.packetLayouts[2].commonHeader.packetType == 208)
    }

    @Test("Compound CNAME must identify the initial report source")
    func cnameSourceBinding() {
        let otherSourceDescription: [UInt8] = [
            0x81, 0xCA, 0x00, 0x02,
            0x99, 0x88, 0x77, 0x66,
            0x01, 0x01, 0x61, 0x00,
        ]
        let bytes = receiverReport + otherSourceDescription

        #expect(throws: RTPWireError.compoundMissingSourceDescriptionCNAME) {
            try parser.layout(in: bytes.span, framing: .compound)
        }
    }

    @Test("SDES without a CNAME remains structurally valid but fails compound policy")
    func missingCNAME() {
        let sourceDescriptionWithoutCNAME: [UInt8] = [
            0x81, 0xCA, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x00, 0x00, 0x00, 0x00,
        ]
        let bytes = receiverReport + sourceDescriptionWithoutCNAME

        #expect(throws: RTPWireError.compoundMissingSourceDescriptionCNAME) {
            try parser.layout(in: bytes.span, framing: .compound)
        }
    }

    @Test("All declared SDES chunks must be present and terminated")
    func malformedSourceDescriptions() {
        let truncatedSecondChunk: [UInt8] = [
            0x82, 0xCA, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x01, 0x01, 0x61, 0x00,
        ]
        let itemExtendsBeyondChunk: [UInt8] = [
            0x81, 0xCA, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x02, 0x03, 0x61, 0x62,
        ]
        let missingEndItem: [UInt8] = [
            0x81, 0xCA, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x02, 0x02, 0x61, 0x62,
        ]
        let nonzeroAlignmentOctet: [UInt8] = [
            0x81, 0xCA, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x00, 0x01, 0x00, 0x00,
        ]

        for bytes in [
            truncatedSecondChunk,
            itemExtendsBeyondChunk,
            missingEndItem,
            nonzeroAlignmentOctet,
        ] {
            #expect(throws: RTPWireError.malformedSourceDescription(packetIndex: 0)) {
                try parser.layout(in: bytes.span, framing: .reducedSize)
            }
        }
    }

    @Test("A matching CNAME may appear in a later SDES chunk")
    func matchingCNAMEInLaterChunk() throws {
        let twoSourceDescriptions: [UInt8] = [
            0x82, 0xCA, 0x00, 0x04,
            0x99, 0x88, 0x77, 0x66,
            0x01, 0x01, 0x62, 0x00,
            0x11, 0x22, 0x33, 0x44,
            0x01, 0x01, 0x61, 0x00,
        ]
        let bytes = receiverReport + twoSourceDescriptions

        let layout = try parser.layout(in: bytes.span, framing: .compound)

        #expect(layout.packetLayouts.count == 2)
        #expect(layout.packetLayouts[1].commonHeader.countOrFormat == 2)
    }

    @Test("Declared packet length cannot extend beyond its datagram")
    func truncatedPacket() {
        let bytes: [UInt8] = [0x80, 0xC9, 0x00, 0x02, 0, 0, 0, 0]

        #expect(throws: RTPWireError.invalidRTCPPacketLength(
            packetIndex: 0,
            declaredBytes: 12,
            availableBytes: 8
        )) {
            try parser.layout(in: bytes.span, framing: .reducedSize)
        }
    }

    @Test("Padding is legal only on the final individual packet")
    func paddingBeforeLast() {
        let paddedReport: [UInt8] = [
            0xA0, 0xC9, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x00, 0x00, 0x00, 0x04,
        ]
        let bytes = paddedReport + matchingSourceDescription

        #expect(throws: RTPWireError.rtcpPaddingBeforeLast(packetIndex: 0)) {
            try parser.layout(in: bytes.span, framing: .compound)
        }
    }

    @Test("RTCP padding count must be nonzero and four-byte aligned")
    func invalidPaddingCount() {
        let bytes: [UInt8] = [
            0xA0, 0xD0, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x01,
        ]

        #expect(throws: RTPWireError.invalidRTCPPadding(packetIndex: 0, count: 1)) {
            try parser.layout(in: bytes.span, framing: .reducedSize)
        }
    }

    @Test("Valid final padding is excluded from the RTCP body range")
    func validFinalPadding() throws {
        let bytes: [UInt8] = [
            0xA0, 0xD0, 0x00, 0x02,
            0x11, 0x22, 0x33, 0x44,
            0x00, 0x00, 0x00, 0x04,
        ]

        let layout = try parser.layout(in: bytes.span, framing: .reducedSize)

        #expect(layout.packetLayouts[0].bodyRange == 4..<8)
        #expect(layout.packetLayouts[0].paddingRange == 8..<12)
    }

    @Test("RTCP padding count cannot be zero or exceed the packet body")
    func paddingCountBounds() {
        let zeroCount: [UInt8] = [
            0xA0, 0xD0, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
        ]
        let excessiveCount: [UInt8] = [
            0xA0, 0xD0, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x08,
        ]

        #expect(throws: RTPWireError.invalidRTCPPadding(packetIndex: 0, count: 0)) {
            try parser.layout(in: zeroCount.span, framing: .reducedSize)
        }
        #expect(throws: RTPWireError.invalidRTCPPadding(packetIndex: 0, count: 8)) {
            try parser.layout(in: excessiveCount.span, framing: .reducedSize)
        }
    }

    @Test("RTCP packets require RTP version two")
    func invalidVersion() {
        let bytes: [UInt8] = [0x40, 0xD0, 0x00, 0x00]

        #expect(throws: RTPWireError.invalidVersion(actual: 1)) {
            try parser.layout(in: bytes.span, framing: .reducedSize)
        }
    }

    @Test("Metadata allocation is bounded by the configured packet limit")
    func packetLimit() throws {
        let packet: [UInt8] = [0x80, 0xD0, 0x00, 0x00]
        var bytes = [UInt8]()
        for _ in 0..<64 {
            bytes.append(contentsOf: packet)
        }

        let atLimit = try parser.layout(
            in: bytes.span,
            framing: .reducedSize,
            limits: RTCPParseLimits(maximumPacketCount: 64)
        )
        #expect(atLimit.packetLayouts.count == 64)

        bytes.append(contentsOf: packet)

        #expect(throws: RTPWireError.packetLimitExceeded(limit: 64)) {
            try parser.layout(
                in: bytes.span,
                framing: .reducedSize,
                limits: RTCPParseLimits(maximumPacketCount: 64)
            )
        }

        #expect(throws: RTPWireError.packetLimitExceeded(limit: 0)) {
            try parser.layout(
                in: packet.span,
                framing: .reducedSize,
                limits: RTCPParseLimits(maximumPacketCount: 0)
            )
        }
    }

    @Test("One to three trailing bytes are rejected")
    func trailingBytes() {
        for trailingByteCount in 1...3 {
            let bytes = receiverReport + [UInt8](repeating: 0, count: trailingByteCount)
            #expect(throws: RTPWireError.trailingRTCPBytes(count: trailingByteCount)) {
                try parser.layout(in: bytes.span, framing: .reducedSize)
            }
        }
    }

    @Test("Known report structures enforce their minimum lengths")
    func shortSenderReport() {
        let bytes: [UInt8] = [0x80, 0xC8, 0x00, 0x01, 0, 0, 0, 1]

        #expect(throws: RTPWireError.insufficientBytes(
            field: .rtcpSenderReport,
            required: 24,
            available: 4
        )) {
            try parser.layout(in: bytes.span, framing: .reducedSize)
        }
    }
}
