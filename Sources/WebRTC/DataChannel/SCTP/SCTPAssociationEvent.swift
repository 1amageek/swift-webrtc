
/// An application-visible event produced by SCTP association processing.
enum SCTPAssociationEvent: Sendable, Equatable {
    /// The authenticated peer restart replaced the association TCB.
    case associationRestarted

    /// The peer's outgoing stream reset completed, so the listed local incoming
    /// streams now expect SSN zero.
    case incomingStreamsReset(SCTPStreamSelection)

    /// A locally requested outgoing reset completed successfully.
    case outgoingStreamsReset(SCTPStreamSelection)

    /// A locally requested outgoing reset was rejected by the peer.
    case outgoingStreamResetFailed(
        SCTPStreamSelection,
        SCTPReconfigurationResult
    )
}
