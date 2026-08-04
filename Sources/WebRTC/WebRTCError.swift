/// WebRTC Errors

/// Errors in WebRTC operations
public enum WebRTCError: Error, Sendable {
    /// The locally provisioned DTLS identity or engine configuration is invalid.
    case invalidLocalIdentity
    case connectionFailed(String)
    case dtlsHandshakeFailed(String)
    @available(
        *,
        deprecated,
        message: "Use sctpWireFailed or sctpProtocolFailed to preserve the typed failure."
    )
    case sctpFailed(String)
    /// SCTP packet bytes failed structural or checksum validation.
    case sctpWireFailed(SCTPWireError)
    /// A concrete SCTP operation failed at an API boundary.
    case sctpProtocolFailed(SCTPError)
    /// A data-channel lifecycle or DCEP operation failed.
    case dataChannelFailed(DataChannelError)
    /// The application did not consume ordered data-channel events fast enough.
    case dataChannelEventBufferExceeded(limit: Int)
    /// Buffered DataChannel payload ownership exceeded the connection byte cap.
    case dataChannelEventByteBufferExceeded(limit: Int)
    /// The canonical event consumer terminated while the connection was active.
    case dataChannelEventStreamTerminated
    /// The sole ordered data-channel event stream already has a consumer.
    case dataChannelEventStreamAlreadyClaimed
    /// A read is already suspended on the sole ordered event consumer.
    case dataChannelEventReadAlreadyInProgress
    /// The task waiting for the next DataChannel event was cancelled.
    case dataChannelEventReadCancelled
    /// Internal read identities were exhausted and are never reused.
    case dataChannelEventReadIdentifiersExhausted
    case iceFailed(String)
    case invalidState(String)
    /// A media API was used on a data-channel-only connection.
    case mediaNotConfigured
    /// DTLS-SRTP has not completed authenticated key installation yet.
    case mediaNotReady
    /// Protected media requires the peer fingerprint to be bound by signaling.
    case mediaPeerAuthenticationRequired
    /// RTP/RTCP plaintext did not satisfy the negotiated wire contract.
    case mediaWireFailure(RTPWireError)
    /// The RTP payload type was not selected by signaling.
    case unnegotiatedRTPPayloadType(UInt8)
    /// SRTP/SRTCP protection failed.
    case mediaProtectionFailed(SRTPError)
    /// The synchronous transport boundary rejected an outbound datagram.
    case datagramSendFailed(WebRTCDatagramSendFailure)
    case timeout
    case closed
}
