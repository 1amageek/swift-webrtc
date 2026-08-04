/// Reports whether RFC 6184 packet-layout traversal reached the access-unit end.
public enum H264RTPPacketTraversalOutcome: Sendable, Equatable {
    case completed
    case stopped
}
