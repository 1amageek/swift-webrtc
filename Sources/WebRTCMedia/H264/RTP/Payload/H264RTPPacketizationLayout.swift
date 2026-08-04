/// An allocation-free plan for one outbound RFC 6184 RTP payload.
public struct H264RTPPacketizationLayout: Sendable, Equatable {
    public let payload: H264RTPPacketizationPayload
    public let payloadByteCount: Int
    public let isLastPacketOfAccessUnit: Bool

    init(
        payload: H264RTPPacketizationPayload,
        payloadByteCount: Int,
        isLastPacketOfAccessUnit: Bool
    ) {
        self.payload = payload
        self.payloadByteCount = payloadByteCount
        self.isLastPacketOfAccessUnit = isLastPacketOfAccessUnit
    }
}
