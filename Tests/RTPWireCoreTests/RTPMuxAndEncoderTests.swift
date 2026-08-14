import Testing
@testable import WebRTC
@Suite("RTP mux and header encoder")
struct RTPMuxAndEncoderTests {
    @Test("RFC 5761 classifies both range boundaries")
    func classifierBoundaries() throws {
        let classifier = RFC5761MuxClassifier()
        let cases: [(UInt8, RTPRTCPPacketKind)] = [
            (191, .rtp),
            (192, .rtcp),
            (223, .rtcp),
            (224, .rtp),
        ]

        for (secondByte, expected) in cases {
            let bytes: [UInt8] = [0x80, secondByte]
            #expect(try classifier.classify(bytes.span) == expected)
        }
    }

    @Test("RTP payload-type policy rejects the RFC 5761 conflict range")
    func payloadTypePolicy() throws {
        let classifier = RFC5761MuxClassifier()

        try classifier.validateNegotiatedRTPPayloadType(63)
        #expect(throws: RTPMuxConfigurationError.payloadTypeConflictsWithRTCP(64)) {
            try classifier.validateNegotiatedRTPPayloadType(64)
        }
        #expect(throws: RTPMuxConfigurationError.payloadTypeConflictsWithRTCP(95)) {
            try classifier.validateNegotiatedRTPPayloadType(95)
        }
        try classifier.validateNegotiatedRTPPayloadType(96)
        #expect(throws: RTPMuxConfigurationError.payloadTypeOutOfRange(128)) {
            try classifier.validateNegotiatedRTPPayloadType(128)
        }
    }

    @Test("Header encoding round-trips without materializing media payload")
    func headerRoundTrip() throws {
        let extensionBytes: [UInt8] = [1, 2, 3, 4]
        let encoded = try RFC3550RTPHeaderEncoder().encodedHeader(
            RTPOutboundHeader(
                marker: true,
                payloadType: 96,
                sequenceNumber: 0x1234,
                timestamp: 0x01020304,
                synchronizationSource: 0x11223344,
                contributingSources: [0x55667788]
            ),
            extensionProfile: 0xBEDE,
            extensionData: extensionBytes.span
        )

        let layout = try RFC3550RTPPacketParser().layout(in: encoded.span)
        #expect(layout.fixedHeader.marker)
        #expect(layout.fixedHeader.contributingSourceCount == 1)
        #expect(layout.headerExtension?.profileIdentifier == 0xBEDE)
        #expect(layout.headerExtension?.dataRange.count == 4)
        #expect(layout.payloadRange.isEmpty)
    }

    @Test("Header appending writes into the caller's final packet owner")
    func headerAppending() throws {
        let extensionBytes: [UInt8] = [1, 2, 3, 4]
        let header = RTPOutboundHeader(
            marker: true,
            payloadType: 96,
            sequenceNumber: 0x1234,
            timestamp: 0x01020304,
            synchronizationSource: 0x11223344,
            contributingSources: [0x55667788]
        )
        let encoder = RFC3550RTPHeaderEncoder()
        let separatelyOwned = try encoder.encodedHeader(
            header,
            extensionProfile: 0xBEDE,
            extensionData: extensionBytes.span
        )
        var finalPacket: [UInt8] = [0xAA]

        try encoder.appendHeader(
            header,
            extensionProfile: 0xBEDE,
            extensionData: extensionBytes.span,
            to: &finalPacket
        )

        #expect(finalPacket.count == separatelyOwned.count + 1)
        for index in 0..<separatelyOwned.count {
            #expect(finalPacket[index + 1] == separatelyOwned[index])
        }
    }

    @Test("Maximum header extension bulk copy preserves every boundary byte")
    func maximumHeaderExtension() throws {
        let byteCount = Int(UInt16.max) * 4
        var extensionBytes = [UInt8](repeating: 0, count: byteCount)
        for index in extensionBytes.indices {
            extensionBytes[index] = UInt8(truncatingIfNeeded: index)
        }
        let header = RTPOutboundHeader(
            marker: false,
            payloadType: 96,
            sequenceNumber: 1,
            timestamp: 2,
            synchronizationSource: 3
        )
        var destination = [UInt8]()

        try RFC3550RTPHeaderEncoder().appendHeader(
            header,
            extensionProfile: 0xBEDE,
            extensionData: extensionBytes.span,
            to: &destination
        )

        let layout = try RFC3550RTPPacketParser().layout(in: destination.span)
        let extensionRange = try #require(layout.headerExtension?.dataRange)
        #expect(extensionRange.count == extensionBytes.count)
        #expect(destination[extensionRange.lowerBound] == extensionBytes[0])
        #expect(
            destination[extensionRange.lowerBound + extensionBytes.count / 2]
                == extensionBytes[extensionBytes.count / 2]
        )
        #expect(
            destination[extensionRange.upperBound - 1]
                == extensionBytes[extensionBytes.count - 1]
        )
    }

    @Test("Header encoder rejects invalid bounded metadata")
    func invalidHeaderMetadata() {
        let encoder = RFC3550RTPHeaderEncoder()
        let noBytes: [UInt8] = []
        let fourBytes: [UInt8] = [0, 0, 0, 0]
        let twoBytes: [UInt8] = [0, 0]

        #expect(throws: RTPWireError.invalidPayloadType(actual: 128)) {
            try encoder.encodedHeader(
                RTPOutboundHeader(
                    marker: false,
                    payloadType: 128,
                    sequenceNumber: 0,
                    timestamp: 0,
                    synchronizationSource: 0
                ),
                extensionProfile: nil,
                extensionData: noBytes.span
            )
        }
        #expect(throws: RTPWireError.unexpectedHeaderExtensionData(byteCount: 4)) {
            try encoder.encodedHeader(
                RTPOutboundHeader(
                    marker: false,
                    payloadType: 96,
                    sequenceNumber: 0,
                    timestamp: 0,
                    synchronizationSource: 0
                ),
                extensionProfile: nil,
                extensionData: fourBytes.span
            )
        }
        #expect(throws: RTPWireError.invalidHeaderExtensionAlignment(byteCount: 2)) {
            try encoder.encodedHeader(
                RTPOutboundHeader(
                    marker: false,
                    payloadType: 96,
                    sequenceNumber: 0,
                    timestamp: 0,
                    synchronizationSource: 0
                ),
                extensionProfile: 0xBEDE,
                extensionData: twoBytes.span
            )
        }

        var destination: [UInt8] = [0xAA]
        #expect(throws: RTPWireError.invalidPayloadType(actual: 128)) {
            try encoder.appendHeader(
                RTPOutboundHeader(
                    marker: false,
                    payloadType: 128,
                    sequenceNumber: 0,
                    timestamp: 0,
                    synchronizationSource: 0
                ),
                extensionProfile: nil,
                extensionData: noBytes.span,
                to: &destination
            )
        }
        #expect(destination == [0xAA])
    }
}
