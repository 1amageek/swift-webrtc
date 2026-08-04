import P2PCoreBytes
import WebRTC
/// One-owner RTP packet assembly for RFC 6184 H.264 payloads.
public struct RFC6184H264RTPPacketAssembler: H264RTPPacketAssembling, Sendable {
    public init() {}

    public func packet(
        header: H264RTPPacketHeader,
        payloadLayout: H264RTPPacketizationLayout,
        accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>,
        extensionProfile: UInt16? = nil,
        extensionData: Span<UInt8>,
        maximumDatagramByteCount: Int,
        protectionTrailerByteCount: Int
    ) throws(H264RTPPacketError) -> [UInt8] {
        guard (1...65_535).contains(maximumDatagramByteCount) else {
            throw .invalidMaximumDatagramByteCount(actual: maximumDatagramByteCount)
        }
        guard protectionTrailerByteCount >= 0,
              protectionTrailerByteCount <= maximumDatagramByteCount else {
            throw .invalidProtectionTrailerByteCount(actual: protectionTrailerByteCount)
        }

        let rtpHeader = RTPOutboundHeader(
            marker: payloadLayout.isLastPacketOfAccessUnit,
            payloadType: header.payloadType,
            sequenceNumber: header.sequenceNumber,
            timestamp: header.timestamp,
            synchronizationSource: header.synchronizationSource,
            contributingSources: header.contributingSources
        )
        let headerEncoder = RFC3550RTPHeaderEncoder()
        let headerByteCount: Int
        do {
            headerByteCount = try headerEncoder.headerByteCount(
                rtpHeader,
                extensionProfile: extensionProfile,
                extensionData: extensionData
            )
        } catch {
            throw .rtpHeader(error)
        }

        let (plaintextByteCount, plaintextOverflow) = headerByteCount.addingReportingOverflow(
            payloadLayout.payloadByteCount
        )
        guard !plaintextOverflow else {
            throw .integerOverflow
        }
        let (protectedByteCount, protectedOverflow) = plaintextByteCount.addingReportingOverflow(
            protectionTrailerByteCount
        )
        guard !protectedOverflow else {
            throw .integerOverflow
        }
        guard protectedByteCount <= maximumDatagramByteCount else {
            throw .packetExceedsMaximum(
                actual: protectedByteCount,
                maximum: maximumDatagramByteCount
            )
        }

        var packet: [UInt8] = []
        packet.reserveCapacity(protectedByteCount)
        do {
            try headerEncoder.appendHeader(
                rtpHeader,
                extensionProfile: extensionProfile,
                extensionData: extensionData,
                to: &packet
            )
        } catch {
            throw .rtpHeader(error)
        }
        do {
            try RFC6184H264PayloadEncoder().appendPayload(
                payloadLayout,
                from: accessUnit,
                nalUnitRanges: nalUnitRanges,
                to: &packet
            )
        } catch {
            throw .h264Payload(error)
        }
        guard packet.count == plaintextByteCount else {
            throw .assembledByteCountMismatch(
                expected: plaintextByteCount,
                actual: packet.count
            )
        }
        return packet
    }
}
