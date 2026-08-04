import Testing
@testable import WebRTC
@Suite("WebRTC media configuration")
struct WebRTCMediaConfigurationTests {
    @Test("The SRTP profile exposes exact packet trailer capacities")
    func exposesProtectionTrailerSizes() {
        let profile = WebRTCMediaProtectionProfile.aes128CMHMACSHA180
        #expect(profile.rtpProtectionTrailerByteCount == 10)
        #expect(profile.rtcpProtectionTrailerByteCount == 14)
    }

    @Test("A caller-selected dynamic RTP payload type is accepted")
    func acceptsDynamicPayloadType() throws {
        let configuration = try WebRTCMediaConfiguration(
            rtpPayloadTypes: [96, 97],
            allowsReducedSizeRTCP: true
        )

        #expect(configuration.protectionProfile == .aes128CMHMACSHA180)
        #expect(configuration.rtpPayloadTypes == [96, 97])
        #expect(configuration.allowsReducedSizeRTCP)
    }

    @Test("At least one RTP payload type is required")
    func rejectsEmptyPayloadTypes() {
        #expect(throws: WebRTCMediaConfigurationError.emptyRTPPayloadTypes) {
            try WebRTCMediaConfiguration(rtpPayloadTypes: [])
        }
    }

    @Test("Duplicate RTP payload types are rejected")
    func rejectsDuplicatePayloadType() {
        #expect(throws: WebRTCMediaConfigurationError.duplicateRTPPayloadType(96)) {
            try WebRTCMediaConfiguration(rtpPayloadTypes: [96, 96])
        }
    }

    @Test("RFC 5761 conflicting payload types are rejected", arguments: [UInt8(64), 79, 95])
    func rejectsMuxConflict(payloadType: UInt8) {
        #expect(throws: WebRTCMediaConfigurationError.rtpRTCPMuxConflict(payloadType)) {
            try WebRTCMediaConfiguration(rtpPayloadTypes: [payloadType])
        }
    }
}
