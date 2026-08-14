import NetworkingCore

/// Composes validated RTP and RFC 6184 metadata into one final packet owner.
public protocol H264RTPPacketAssembling: Sendable {
    /// Returns one plaintext RTP packet and reserves capacity for the protection
    /// trailer that a downstream SRTP context will append in place.
    func packet(
        header: H264RTPPacketHeader,
        payloadLayout: H264RTPPacketizationLayout,
        accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>,
        extensionProfile: UInt16?,
        extensionData: Span<UInt8>,
        maximumDatagramByteCount: Int,
        protectionTrailerByteCount: Int
    ) throws(H264RTPPacketError) -> [UInt8]
}
