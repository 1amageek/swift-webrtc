/// Media protection profiles implemented by the WebRTC media path.

/// An SRTP protection profile that can be required during DTLS negotiation.
///
/// The facade owns this type so callers do not depend on swift-tls wire-layer
/// types. `WebRTC` maps it to the corresponding `use_srtp` profile internally.
public enum WebRTCMediaProtectionProfile: Sendable, Hashable {
    /// AES-128 counter mode with a truncated 80-bit HMAC-SHA1 tag.
    case aes128CMHMACSHA180

    /// Bytes appended to each protected RTP packet by this profile.
    public var rtpProtectionTrailerByteCount: Int {
        switch self {
        case .aes128CMHMACSHA180:
            return 10
        }
    }

    /// Bytes appended to each protected RTCP packet by this profile.
    ///
    /// AES_CM_128_HMAC_SHA1_80 appends a 4-byte SRTCP index followed by the
    /// 10-byte authentication tag.
    public var rtcpProtectionTrailerByteCount: Int {
        switch self {
        case .aes128CMHMACSHA180:
            return 14
        }
    }
}
