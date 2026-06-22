/// SCTP errors (historical concrete type).
///
/// The Embedded-clean SCTP wire codec in `SCTPWireCore` throws
/// ``SCTPWireError``; the adapter unwraps it back to this type at the
/// `Data`-based boundary so callers (and the existing test suite) continue to
/// catch `SCTPError` directly. The state machine (`SCTPAssociation`,
/// `FragmentAssembler`, `RetransmissionQueue`, `SCTPCookie`, …) also throws this
/// type for protocol-level violations.

import Foundation

public enum SCTPError: Error, Sendable {
    case insufficientData(expected: Int, actual: Int)
    case invalidFormat(String)
    case associationFailed(String)
    case streamReset(String)
    case timeout
    case checksumMismatch(expected: UInt32, actual: UInt32)
    case cookieValidationFailed
    case cookieExpired
    case maxRetransmitsExceeded
    case verificationTagMismatch(expected: UInt32, actual: UInt32)
    case associationAborted
    case invalidState(String)
    case receiveBufferExceeded(streamID: UInt16)
    case invalidStreamIdentifier(streamID: UInt16, negotiated: UInt16)
    case sendQueueFull(bytesInFlight: Int, limit: Int)
}
