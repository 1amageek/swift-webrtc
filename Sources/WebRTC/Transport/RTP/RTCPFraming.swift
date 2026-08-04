/// The RTCP datagram rules selected by the negotiated session profile.
public enum RTCPFraming: Sendable, Equatable {
    case compound
    case reducedSize
}
