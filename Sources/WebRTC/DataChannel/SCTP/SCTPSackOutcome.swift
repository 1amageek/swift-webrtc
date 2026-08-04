/// A protocol violation detected while validating one SACK.
public enum SCTPSackViolation: Sendable, Equatable {
    case ambiguousSerialNumber(reference: UInt32, candidate: UInt32)
    case cumulativeAcknowledgesUnsentTSN(
        cumulativeTSN: UInt32,
        highestSentTSN: UInt32?
    )
    case gapAcknowledgesUnsentTSN(
        blockIndex: Int,
        highestAcknowledgedTSN: UInt32,
        highestSentTSN: UInt32?
    )
    case invalidGapBlock(
        index: Int,
        start: UInt16,
        end: UInt16
    )
    case accountingOverflow
}

/// Exact sender-state changes committed by one valid SACK.
struct SCTPSackUpdate: Sendable, Equatable {
    let cumulativeAdvanced: Bool
    let newlyCumulativelyAcknowledgedByteCount: Int
    let newlyGapAcknowledgedByteCount: Int
    let renegedByteCount: Int
    let highestNewlyAcknowledgedTSN: UInt32?
    let bytesInFlight: Int
    let retainedPayloadByteCount: Int
    let peerReceiverWindow: UInt64

    init(
        cumulativeAdvanced: Bool,
        newlyCumulativelyAcknowledgedByteCount: Int,
        newlyGapAcknowledgedByteCount: Int,
        renegedByteCount: Int,
        highestNewlyAcknowledgedTSN: UInt32?,
        bytesInFlight: Int,
        retainedPayloadByteCount: Int,
        peerReceiverWindow: UInt64
    ) {
        self.cumulativeAdvanced = cumulativeAdvanced
        self.newlyCumulativelyAcknowledgedByteCount = newlyCumulativelyAcknowledgedByteCount
        self.newlyGapAcknowledgedByteCount = newlyGapAcknowledgedByteCount
        self.renegedByteCount = renegedByteCount
        self.highestNewlyAcknowledgedTSN = highestNewlyAcknowledgedTSN
        self.bytesInFlight = bytesInFlight
        self.retainedPayloadByteCount = retainedPayloadByteCount
        self.peerReceiverWindow = peerReceiverWindow
    }
}

/// Typed result of validating and applying one SCTP SACK.
enum SCTPSackOutcome: Sendable, Equatable {
    /// The cumulative acknowledgment precedes the committed acknowledgment
    /// point. RFC 4960 requires the complete stale SACK to be discarded.
    case stale(cumulativeTSN: UInt32)

    /// The SACK was valid and the update was committed atomically.
    case applied(SCTPSackUpdate)

    /// The SACK was invalid and no sender state was changed.
    case protocolViolation(SCTPSackViolation)
}
