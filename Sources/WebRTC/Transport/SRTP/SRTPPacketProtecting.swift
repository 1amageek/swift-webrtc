/// Stateful, in-place protection for one bidirectional SRTP session.
///
/// Callers provide an owned packet buffer. Protection appends protocol fields to
/// that same owner, and unprotection removes them after authentication. A buffer
/// passed to a throwing operation must be discarded when the operation fails;
/// a crypto provider may have partially transformed it before reporting failure.
protocol SRTPPacketProtecting: Sendable {
    func protectRTP(_ packet: inout [UInt8]) throws(SRTPError)
    func unprotectRTP(_ packet: inout [UInt8]) throws(SRTPError)
    func protectRTCP(_ packet: inout [UInt8]) throws(SRTPError)
    func unprotectRTCP(_ packet: inout [UInt8]) throws(SRTPError)
}
