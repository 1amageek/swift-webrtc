/// Which endpoint initiated a data channel whose open transition is reported.
public enum WebRTCDataChannelDirection: Sendable, Equatable {
    case local
    case remote
}
