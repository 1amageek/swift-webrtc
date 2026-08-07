/// Failures while parsing or serializing WebRTC signaling values.
public enum WebRTCSessionDescriptionError: Error, Sendable, Equatable {
    case inputTooLarge(size: Int, maximum: Int)
    case malformedLine(String)
    case unsupportedMedia
    case missingICEUsernameFragment
    case missingICEPassword
    case missingFingerprint
    case invalidFingerprint
    case missingDTLSSetupRole
    case invalidDTLSSetupRole(String)
    case invalidCandidate(String)
    case invalidPort(String)
    case invalidPriority(String)
    case invalidSCTPPort(String)
    case invalidMaximumMessageSize(String)
    case invalidJSON(String)
    case missingCandidate
    case invalidMediaStreamIdentification(String)
    case invalidMediaLineIndex(UInt64)
    case invalidUsernameFragment(String)
}
