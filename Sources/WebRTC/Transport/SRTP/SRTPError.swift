import NetworkingTime

/// Typed failures emitted by the RFC 3711 SRTP transform.
public enum SRTPError: Error, Sendable, Equatable {
    case invalidMasterKeyLength(expected: Int, actual: Int)
    case invalidMasterSaltLength(expected: Int, actual: Int)
    case invalidAuthenticationTagLength(expectedAtLeast: Int, actual: Int)
    case packetTooShort(kind: SRTPPacketKind, minimum: Int, actual: Int)
    case encryptedPortionTooLarge(kind: SRTPPacketKind, maximum: Int, actual: Int)
    case malformedRTP(RTPWireError)
    case malformedRTCP(RTPWireError)
    case authenticationFailure(kind: SRTPPacketKind)
    case replayedPacket(kind: SRTPPacketKind, synchronizationSource: UInt32, index: UInt64)
    case packetTooOld(kind: SRTPPacketKind, synchronizationSource: UInt32, index: UInt64)
    case outboundIndexReuse(synchronizationSource: UInt32, index: UInt64)
    case indexExhausted(kind: SRTPPacketKind, synchronizationSource: UInt32)
    case unencryptedSRTCPRejected
    case stateReservationLost(kind: SRTPPacketKind, synchronizationSource: UInt32, index: UInt64)
    case counterMode(AESCounterModeError)
}
