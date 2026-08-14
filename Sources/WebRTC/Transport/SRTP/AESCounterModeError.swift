/// Typed AES-CTR failures at the SRTP protocol boundary.
public enum AESCounterModeError: Error, Equatable, Sendable {
    case invalidKeyLength(expected: Int, actual: Int)
    case invalidCounterLength(expected: Int, actual: Int)
    case invalidRange(lowerBound: Int, upperBound: Int, bufferCount: Int)
    case primitiveFailure
}
