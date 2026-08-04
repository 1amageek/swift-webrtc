/// Scalar sender metadata retained until the peer cumulatively acknowledges a
/// skip. Payload ownership is released at abandonment; these fields preserve
/// the ordering and RFC 3758 F5 congestion-accounting contract only.
struct SCTPAbandonedChunk: Sendable, Equatable {
    let streamIdentifier: UInt16
    let streamSequenceNumber: UInt16
    let unordered: Bool
    let wasTransmitted: Bool
    var missIndications: Int
    var congestionResponseApplied: Bool
}
