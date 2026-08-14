/// Unified typed-throws error for the Embedded-clean SCTP wire codec.
///
/// Embedded Swift forbids untyped `throws` (which is `throws(any Error)`), so the
/// wire codec uses typed throws with this single error type. It wraps the two
/// error kinds the codec can raise:
/// - ``ByteError`` from the `NetworkingCore` reader/writer,
/// - ``SCTPDecodeError`` for malformed SCTP wire structure.
///
/// The SCTP association adapter unwraps this back to the historical `SCTPError` at the
/// `Data`-based boundary, so callers (and the existing test suite) continue to
/// catch `SCTPError` directly.

import NetworkingCore

/// Structural decoding failures for the SCTP wire codec.
///
/// These mirror the historical `SCTPError` cases that describe malformed wire
/// data. The adapter maps them back onto `SCTPError` at the `Data` boundary.
public enum SCTPDecodeError: Error, Sendable, Equatable {
    case insufficientData(expected: Int, actual: Int)
    case invalidFormat(String)
    case checksumMismatch(expected: UInt32, actual: UInt32)
}

/// The single typed-throws error raised by the SCTP wire codec.
public enum SCTPWireError: Error, Sendable {
    case bytes(ByteError)
    case decode(SCTPDecodeError)
    /// A locally constructed chunk cannot represent its value in the RFC 4960
    /// 16-bit Chunk Length field.
    case chunkValueTooLarge(actual: Int, maximum: Int)
}
