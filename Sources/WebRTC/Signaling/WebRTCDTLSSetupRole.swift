/// DTLS role negotiation carried by SDP `a=setup`.
public enum WebRTCDTLSSetupRole: String, Sendable, Equatable {
    case actpass
    case active
    case passive
}
