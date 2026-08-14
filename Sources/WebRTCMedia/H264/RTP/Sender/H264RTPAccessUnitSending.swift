import NetworkingCore

/// Packetizes one borrowed H.264 access unit and transfers packet owners to a sink.
public protocol H264RTPAccessUnitSending: Sendable {
    /// Emits plaintext RTP packet owners synchronously in sequence order.
    ///
    /// The sink's `.success` means it accepted ownership of that packet. If it
    /// fails, no later packet is emitted and the failure reports how many prior
    /// packets were accepted. Reserved RTP sequence numbers are never reused.
    func sendAccessUnit<SinkFailure>(
        _ accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>,
        captureTimeNanoseconds: UInt64,
        extensionProfile: UInt16?,
        extensionData: Span<UInt8>,
        sink: (consuming [UInt8]) -> Result<Void, SinkFailure>
    ) -> Result<H264RTPSendReport, H264RTPSendError<SinkFailure>>
    where SinkFailure: Error & Sendable
}
