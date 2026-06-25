/// WebRTC Errors

/// Errors in WebRTC operations
public enum WebRTCError: Error, Sendable {
    case connectionFailed(String)
    case dtlsHandshakeFailed(String)
    case sctpFailed(String)
    case iceFailed(String)
    case invalidState(String)
    case timeout
    case closed
}
