/// Default plaintext packet sizing for an SCTP association.
enum SCTPAssociationLimits {
    /// Conservative SCTP plaintext packet budget used before PMTU discovery.
    static let defaultMaximumPacketByteCount = 1_200

    /// User-data bytes available after the common header and one DATA chunk.
    static let defaultMaximumDataPayloadByteCount = 1_172

    /// Smallest packet budget that can carry one nonempty DATA chunk.
    static let minimumMaximumPacketByteCount = 32
}
