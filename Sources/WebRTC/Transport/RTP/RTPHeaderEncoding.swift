import NetworkingCore

/// Encodes the small RTP header independently from media-payload ownership.
package protocol RTPHeaderEncoding: Sendable {
    /// Produces one owned header allocation. Payload bytes are never materialized here.
    func encodedHeader(
        _ header: RTPOutboundHeader,
        extensionProfile: UInt16?,
        extensionData: Span<UInt8>
    ) throws(RTPWireError) -> OwnedBytes
}
