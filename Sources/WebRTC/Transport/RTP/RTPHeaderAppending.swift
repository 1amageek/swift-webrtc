import P2PCoreBytes

/// Writes an RTP header directly into caller-owned packet storage.
package protocol RTPHeaderAppending: Sendable {
    /// Returns the exact encoded header size after validating all bounded fields.
    func headerByteCount(
        _ header: RTPOutboundHeader,
        extensionProfile: UInt16?,
        extensionData: Span<UInt8>
    ) throws(RTPWireError) -> Int

    /// Validates the complete header before reserving or mutating `destination`.
    func appendHeader(
        _ header: RTPOutboundHeader,
        extensionProfile: UInt16?,
        extensionData: Span<UInt8>,
        to destination: inout [UInt8]
    ) throws(RTPWireError)
}
