/// RFC 1982 ordering relation for a 32-bit SCTP Transmission Sequence Number.
enum SCTPSerialNumberRelation: Sendable, Equatable {
    case before
    case equal
    case after
    case ambiguous
}
