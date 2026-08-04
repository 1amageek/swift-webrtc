/// Typed failures raised while constructing a local WebRTC DTLS identity.
public enum WebRTCCertificateError: Error, Sendable, Equatable {
    /// The supplied DER is not a supported X.509 certificate or raw-public-key SPKI.
    case malformedCredential

    /// The supplied bytes are not a valid ECDSA P-256 private key.
    case malformedPrivateKey

    /// The public key in the credential does not correspond to the private key.
    case credentialKeyMismatch

    /// Self-signed certificate construction failed.
    case generationFailed

    /// The selected certificate clock cannot provide Unix wall-clock time.
    case clockUnavailable
}
