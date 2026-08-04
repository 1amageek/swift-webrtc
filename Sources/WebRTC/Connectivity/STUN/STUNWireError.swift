/// Unified typed-throws error for the Embedded-clean STUN wire codec.
///
/// Embedded Swift forbids untyped `throws` (which is `throws(any Error)`), so the
/// wire codec uses typed throws with this single error type. It wraps the two
/// error kinds the codec can raise:
/// - ``ByteError`` from the `P2PCoreBytes` reader/writer,
/// - ``STUNDecodeError`` for malformed STUN structure.
///
/// The `STUNCore` adapter unwraps this back to the original concrete `STUNError`
/// at the `Data`-based boundary, so callers (and the existing test suite)
/// continue to catch `STUNError` directly.

import P2PCoreBytes

/// Structural decoding failures for the STUN wire codec.
///
/// These mirror the historical `STUNError` cases that describe malformed wire
/// data. The adapter maps them back onto `STUNError` at the `Data` boundary.
enum STUNDecodeError: Error, Sendable, Equatable {
    case insufficientData(expected: Int, actual: Int)
    case invalidFormat(String)
    case invalidMagicCookie(UInt32)
}

/// The single typed-throws error raised by the STUN wire codec.
enum STUNWireError: Error, Sendable {
    case bytes(ByteError)
    case decode(STUNDecodeError)
}
