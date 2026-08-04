/// The complete result of one SCTP packet-processing transaction.
///
/// A clean shutdown and a terminal protocol violation can both require a final
/// wire response. Keeping those outcomes distinct lets the transport owner
/// commit terminal state before external I/O while preserving a typed failure
/// only for abnormal termination.
enum SCTPProcessOutcome: Sendable {
    case processed(SCTPProcessResult)
    case closed(SCTPProcessResult)
    case terminal(SCTPProcessResult, SCTPError)
}
