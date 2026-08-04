/// Data channel errors (historical concrete type).
///
/// The Embedded-clean internal DCEP codec throws ``DataChannelWireError``; the
/// adapter unwraps it back to this type at the
/// `Data`-based boundary so callers (and the existing test suite) continue to
/// catch `DataChannelError` directly. The manager (`DataChannelManager`) also
/// throws this type for state-machine violations.

public enum DataChannelError: Error, Sendable {
    case invalidFormat(String)
    case channelClosed
    case notReady
    /// A DATA_CHANNEL_ACK arrived on a stream with no channel awaiting an ACK
    case unexpectedAck(streamID: UInt16)
    /// A DATA_CHANNEL_OPEN arrived on an SCTP stream already bound to a channel.
    /// RFC 8832 requires closing that channel without acknowledging the OPEN.
    case streamAlreadyInUse(streamID: UInt16)
    /// An incoming OPEN used a stream ID whose parity is reserved for the local
    /// side (RFC 8832 §6 even/odd partitioning)
    case streamParityViolation(streamID: UInt16)
    /// Too many channels open / pending (resource exhaustion guard)
    case tooManyChannels(limit: Int)
    /// Label or protocol field exceeds the configured maximum length
    case labelOrProtocolTooLong(limit: Int)
    /// No more usable stream IDs of the local parity remain
    case streamIDsExhausted
    /// The local lifecycle generation space was exhausted. Generations never
    /// wrap because delayed events must not alias a reused SCTP stream ID.
    case channelGenerationsExhausted
}
