/// Controls allocation-free traversal of RFC 6184 packet layouts.
public enum H264RTPPacketTraversalDecision: Sendable, Equatable {
    case proceed
    case stop
}
