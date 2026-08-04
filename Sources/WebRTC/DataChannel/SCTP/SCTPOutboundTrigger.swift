/// Event that gives the SCTP sender an opportunity to emit retained DATA.
package enum SCTPOutboundTrigger: Sendable, Equatable {
    /// A user message was admitted to the bounded sender queue.
    case application

    /// A valid SACK changed sender accounting or opened a window.
    case acknowledgment

    /// The association owner's monotonic timer fired.
    case timer
}
