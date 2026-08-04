import Testing
@testable import WebRTC
@Suite("RTP packet parser")
struct RTPPacketParserTests {
    private let parser = RFC3550RTPPacketParser()

    @Test("Minimal RTP header produces an empty payload range")
    func minimalPacket() throws {
        let bytes: [UInt8] = [
            0x80, 0x60, 0x12, 0x34,
            0x01, 0x02, 0x03, 0x04,
            0x11, 0x22, 0x33, 0x44,
        ]

        let layout = try parser.layout(in: bytes.span)

        #expect(layout.packetLength == 12)
        #expect(layout.fixedHeader.payloadType == 96)
        #expect(layout.fixedHeader.sequenceNumber == 0x1234)
        #expect(layout.fixedHeader.timestamp == 0x01020304)
        #expect(layout.fixedHeader.synchronizationSource == 0x11223344)
        #expect(layout.payloadRange == 12..<12)
        #expect(layout.paddingRange == nil)
    }

    @Test("CSRC, raw extension, payload, and padding retain exact owner ranges")
    func variableHeaderRanges() throws {
        let bytes: [UInt8] = [
            0xB1, 0xE0, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x04,
            0xAA, 0xBB, 0xCC, 0xDD,
            0xBE, 0xDE, 0x00, 0x01,
            0x10, 0x20, 0x30, 0x40,
            0x99,
            0x00, 0x00, 0x00, 0x04,
        ]

        let layout = try parser.layout(in: bytes.span)

        #expect(layout.fixedHeader.marker)
        #expect(layout.fixedHeader.contributingSourceCount == 1)
        #expect(layout.contributingSourcesRange == 12..<16)
        #expect(layout.headerExtension?.profileIdentifier == 0xBEDE)
        #expect(layout.headerExtension?.dataRange == 20..<24)
        #expect(layout.payloadRange == 24..<25)
        #expect(layout.paddingRange == 25..<29)
        #expect(bytes.span.extracting(layout.payloadRange)[0] == 0x99)
    }

    @Test("Zero-length RFC 3550 extension is valid")
    func emptyExtension() throws {
        let bytes: [UInt8] = [
            0x90, 0x60, 0, 1,
            0, 0, 0, 2,
            0, 0, 0, 3,
            0x10, 0x00, 0x00, 0x00,
        ]

        let layout = try parser.layout(in: bytes.span)

        #expect(layout.headerExtension?.dataRange == 16..<16)
        #expect(layout.payloadRange == 16..<16)
    }

    @Test("The maximum CSRC count retains one contiguous owner range")
    func maximumContributingSourceCount() throws {
        var bytes: [UInt8] = [
            0x8F, 0x60, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x03,
        ]
        for source in UInt32(0)..<UInt32(15) {
            bytes.append(UInt8((source >> 24) & 0xFF))
            bytes.append(UInt8((source >> 16) & 0xFF))
            bytes.append(UInt8((source >> 8) & 0xFF))
            bytes.append(UInt8(source & 0xFF))
        }

        let layout = try parser.layout(in: bytes.span)

        #expect(layout.fixedHeader.contributingSourceCount == 15)
        #expect(layout.contributingSourcesRange == 12..<72)
        #expect(layout.payloadRange == 72..<72)
    }

    @Test("Every truncated extension-header boundary fails before reading fields")
    func truncatedExtensionHeader() {
        let fixedHeader: [UInt8] = [
            0x90, 0x60, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x03,
        ]
        let extensionHeader: [UInt8] = [0xBE, 0xDE, 0x00, 0x01]

        for presentByteCount in 0..<extensionHeader.count {
            var bytes = fixedHeader
            bytes.append(contentsOf: extensionHeader.prefix(presentByteCount))
            #expect(throws: RTPWireError.insufficientBytes(
                field: .rtpHeaderExtensionHeader,
                required: 16,
                available: 12 + presentByteCount
            )) {
                try parser.layout(in: bytes.span)
            }
        }
    }

    @Test("Every truncated extension-data boundary reports its available byte count")
    func truncatedExtensionData() {
        let header: [UInt8] = [
            0x90, 0x60, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x03,
            0xBE, 0xDE, 0x00, 0x01,
        ]
        let extensionData: [UInt8] = [0x10, 0x20, 0x30, 0x40]

        for presentByteCount in 0..<extensionData.count {
            var bytes = header
            bytes.append(contentsOf: extensionData.prefix(presentByteCount))
            #expect(throws: RTPWireError.invalidHeaderExtensionLength(
                declaredWords: 1,
                availableBytes: presentByteCount
            )) {
                try parser.layout(in: bytes.span)
            }
        }
    }

    @Test("Malformed variable fields fail with typed errors", arguments: [
        ([0x40] as [UInt8], RTPWireError.insufficientBytes(field: .rtpFixedHeader, required: 12, available: 1)),
        ([0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], RTPWireError.invalidVersion(actual: 1)),
        ([0x81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], RTPWireError.insufficientBytes(field: .rtpContributingSources, required: 16, available: 12)),
        ([0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], RTPWireError.insufficientBytes(field: .rtpHeaderExtensionHeader, required: 16, available: 12)),
        ([0x90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1], RTPWireError.invalidHeaderExtensionLength(declaredWords: 1, availableBytes: 0)),
        ([0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], RTPWireError.invalidRTPPadding(count: 0, availableBytes: 1)),
        ([0xA0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], RTPWireError.invalidRTPPadding(count: 1, availableBytes: 1)),
    ])
    func malformedPacket(bytes: [UInt8], expected: RTPWireError) {
        #expect(throws: expected) {
            try parser.layout(in: bytes.span)
        }
    }
}
