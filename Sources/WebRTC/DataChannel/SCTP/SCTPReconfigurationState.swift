
/// Caller-locked RFC 6525 state owned by `SCTPAssociationEngine`.
struct SCTPReconfigurationState: Sendable {
    /// Upper-layer DATA accepted while RFC 6525 temporarily blocks SSN
    /// assignment for its stream. The immutable Array remains the sole payload
    /// owner; DATA fragment descriptors are created only when the reset reaches
    /// a terminal result.
    struct PendingUserMessage: Sendable {
        let streamID: UInt16
        let payloadProtocolIdentifier: UInt32
        let data: [UInt8]
        let unordered: Bool
        let reliability: SCTPAssignedMessageReliability
        let maximumPacketByteCount: Int
        let fragmentCount: Int
    }

    struct PendingOutgoingReset: Sendable {
        let request: SCTPOutgoingSSNResetRequest
        let selection: SCTPStreamSelection
        let packet: SCTPPacket
        var lastSentMillis: UInt64
        var rtoMillis: UInt64
        var retransmitCount: Int
        var peerReportedInProgress: Bool
        var implicitlyAcknowledged: Bool
    }

    struct DeferredIncomingReset: Sendable {
        let request: SCTPOutgoingSSNResetRequest
        let selection: SCTPStreamSelection
        var heldDataChunks: [SCTPDataChunk]
        var heldByteCount: Int
    }

    struct CachedPeerResponse: Sendable {
        let requestSequenceNumbers: [UInt32]
        let chunk: SCTPChunk
    }

    static let maximumQueuedResetCount = 1_024
    static let maximumQueuedUserMessageCount = 1_024
    static let maximumDeferredMessageCount = 1_024
    static let maximumDeferredByteCount = 1 * 1_024 * 1_024
    static let maximumRetransmitCount = 10
    static let maximumRTOMillis: UInt64 = 60_000

    var nextLocalRequestSequenceNumber: UInt32
    var nextExpectedPeerRequestSequenceNumber: UInt32 = 0
    var pendingOutgoingReset: PendingOutgoingReset?
    var queuedOutgoingResets: [SCTPStreamSelection] = []
    var queuedOutgoingResetHead: Int = 0
    var deferredIncomingReset: DeferredIncomingReset?
    var cachedPeerResponse: CachedPeerResponse?
    var queuedUserMessages: [PendingUserMessage] = []
    private(set) var queuedUserDataByteCount = 0
    private(set) var queuedUserChunkCount = 0

    init(localInitialTSN: UInt32) {
        self.nextLocalRequestSequenceNumber = localInitialTSN
    }

    var queuedResetCount: Int {
        queuedOutgoingResets.count - queuedOutgoingResetHead
    }

    var queuedUserMessageCount: Int {
        queuedUserMessages.count
    }

    var hasQueuedUserMessages: Bool {
        !queuedUserMessages.isEmpty
    }

    mutating func enqueueUserMessage(
        _ message: PendingUserMessage
    ) throws(SCTPError) {
        guard queuedUserMessages.count < Self.maximumQueuedUserMessageCount else {
            throw .sendChunkLimitReached(
                retainedChunkCount: queuedUserMessages.count,
                limit: Self.maximumQueuedUserMessageCount
            )
        }
        let (projectedBytes, byteOverflow) = queuedUserDataByteCount
            .addingReportingOverflow(message.data.count)
        let (projectedChunks, chunkOverflow) = queuedUserChunkCount
            .addingReportingOverflow(message.fragmentCount)
        guard !byteOverflow, !chunkOverflow else {
            throw .sendQueueFull(
                bytesInFlight: queuedUserDataByteCount,
                limit: Int.max
            )
        }
        queuedUserMessages.append(message)
        queuedUserDataByteCount = projectedBytes
        queuedUserChunkCount = projectedChunks
    }

    func firstSendableUserMessageIndex() -> Int? {
        queuedUserMessages.firstIndex {
            !hasResetScheduled(for: $0.streamID)
        }
    }

    mutating func removeUserMessage(at index: Int) {
        let removed = queuedUserMessages.remove(at: index)
        queuedUserDataByteCount -= removed.data.count
        queuedUserChunkCount -= removed.fragmentCount
    }

    mutating func enqueue(_ selection: SCTPStreamSelection) throws(SCTPError) {
        guard queuedResetCount < Self.maximumQueuedResetCount else {
            throw .streamResetQueueFull(limit: Self.maximumQueuedResetCount)
        }
        queuedOutgoingResets.append(selection)
    }

    mutating func popQueuedReset() -> SCTPStreamSelection? {
        guard queuedOutgoingResetHead < queuedOutgoingResets.count else {
            queuedOutgoingResets.removeAll(keepingCapacity: true)
            queuedOutgoingResetHead = 0
            return nil
        }
        let selection = queuedOutgoingResets[queuedOutgoingResetHead]
        queuedOutgoingResetHead += 1
        if queuedOutgoingResetHead == queuedOutgoingResets.count {
            queuedOutgoingResets.removeAll(keepingCapacity: true)
            queuedOutgoingResetHead = 0
        }
        return selection
    }

    /// Cancel local stream-reset work superseded by association shutdown.
    ///
    /// Receive-side state and accepted user messages remain owned. The caller
    /// releases those messages into the retransmission queue before SHUTDOWN.
    mutating func cancelOutgoingResets() {
        pendingOutgoingReset = nil
        queuedOutgoingResets.removeAll(keepingCapacity: false)
        queuedOutgoingResetHead = 0
    }

    func hasResetScheduled(for streamID: UInt16) -> Bool {
        if pendingOutgoingReset?.selection.contains(streamID) == true {
            return true
        }
        for index in queuedOutgoingResetHead..<queuedOutgoingResets.count {
            if queuedOutgoingResets[index].contains(streamID) {
                return true
            }
        }
        return false
    }

    func hasResetScheduled(_ selection: SCTPStreamSelection) -> Bool {
        if pendingOutgoingReset?.selection == selection {
            return true
        }
        for index in queuedOutgoingResetHead..<queuedOutgoingResets.count {
            if queuedOutgoingResets[index] == selection {
                return true
            }
        }
        return false
    }

    /// Release retransmitted control packets, queued selections, cached peer
    /// responses, and deferred DATA owners at association teardown.
    mutating func removeAllRetainedState() {
        cancelOutgoingResets()
        queuedUserMessages.removeAll(keepingCapacity: false)
        queuedUserDataByteCount = 0
        queuedUserChunkCount = 0
        deferredIncomingReset = nil
        cachedPeerResponse = nil
    }
}
