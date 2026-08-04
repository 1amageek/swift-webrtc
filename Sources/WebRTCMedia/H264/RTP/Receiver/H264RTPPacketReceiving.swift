import WebRTC
/// Reorders and reconstructs one negotiated H.264 RTP stream.
public protocol H264RTPPacketReceiving: Sendable {
    /// Accepts ownership of one plaintext RTP packet.
    ///
    /// `layout` must have been produced from this exact owner; the receiver
    /// reparses and compares it before retaining state. Completed access-unit
    /// owners are transferred one at a time after the receiver releases its
    /// state mutex. Sink `.success` accepts ownership. Sink `.failure` must not
    /// retain the rejected owner, stops later delivery, flushes queued packet
    /// owners for safe resynchronization, and reports every observed effect.
    func receive<SinkFailure>(
        _ packet: consuming [UInt8],
        layout: RTPPacketLayout,
        arrivalTimeNanoseconds: UInt64,
        sink: (consuming H264RTPAccessUnit) -> Result<Void, SinkFailure>
    ) -> Result<H264RTPReceiveReport, H264RTPReceiveError<SinkFailure>>
    where SinkFailure: Error & Sendable

    /// Advances the reorder deadline without inventing a packet.
    func advanceTime<SinkFailure>(
        to timeNanoseconds: UInt64,
        sink: (consuming H264RTPAccessUnit) -> Result<Void, SinkFailure>
    ) -> Result<H264RTPReceiveReport, H264RTPReceiveError<SinkFailure>>
    where SinkFailure: Error & Sendable
}
