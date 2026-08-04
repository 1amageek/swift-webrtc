/// Sender-side persistence policy for one SCTP user message.
enum SCTPMessageReliability: Sendable, Equatable {
    case reliable
    case maximumRetransmissions(UInt32)
    case maximumLifetimeMilliseconds(UInt32)
}

/// Immutable policy stored beside every TSN assigned to one user message.
enum SCTPAssignedMessageReliability: Sendable, Equatable {
    case reliable
    case maximumRetransmissions(UInt32)
    case expiresAtMillis(UInt64)

    static func resolve(
        _ policy: SCTPMessageReliability,
        acceptedAtMillis: UInt64
    ) throws(SCTPError) -> SCTPAssignedMessageReliability {
        switch policy {
        case .reliable:
            return .reliable
        case .maximumRetransmissions(let count):
            return .maximumRetransmissions(count)
        case .maximumLifetimeMilliseconds(let lifetime):
            let (deadline, overflow) = acceptedAtMillis.addingReportingOverflow(
                UInt64(lifetime)
            )
            guard !overflow else {
                throw .monotonicClockValueOutOfRange
            }
            return .expiresAtMillis(deadline)
        }
    }

    func isExpired(at nowMillis: UInt64) -> Bool {
        guard case .expiresAtMillis(let deadline) = self else { return false }
        return nowMillis >= deadline
    }
}
