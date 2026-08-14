/// Unified typed-throws error for the Embedded-clean DCEP wire codec.
///
/// Embedded Swift forbids untyped `throws` (which is `throws(any Error)`), so the
/// wire codec uses typed throws with this single error type. It wraps the two
/// error kinds the codec can raise:
/// - ``ByteError`` from the `NetworkingCore` reader/writer,
/// - ``DCEPDecodeError`` for malformed DCEP structure.
///
/// The `DataChannel` adapter unwraps this back to the historical
/// `DataChannelError` at the `Data`-based boundary, so callers (and the existing
/// test suite) continue to catch `DataChannelError` directly.

import NetworkingCore

/// Structural decoding failures for the DCEP wire codec.
enum DCEPDecodeError: Error, Sendable, Equatable {
    case invalidFormat(String)
}

/// The single typed-throws error raised by the DCEP wire codec.
enum DataChannelWireError: Error, Sendable {
    case bytes(ByteError)
    case decode(DCEPDecodeError)
}
