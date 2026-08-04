/// WebRTC Data Channel (RFC 8831) — caller-locked adapter.
///
/// A single bidirectional data channel over SCTP, plus the `DataChannelManager`
/// that handles DCEP open/ack and channel lifecycle.
///
/// `DataChannelManager` is a `final class & Sendable` that holds its mutable
/// channel-table state value behind a ``FacadeLock`` (the proven caller-locked
/// pattern: the same `Synchronization.Mutex` contract on every target),
/// driving the internal DCEP wire codec. The currency is `[UInt8]`
/// (Embedded-clean); the historical `Data`-based `openChannel` /
/// `processIncomingDCEP` overloads are gated host-only.

import Synchronization
#if !hasFeature(Embedded) && !os(WASI)
import Foundation
#endif

/// Data channel state.
public enum DataChannelState: Sendable, Equatable {
    case connecting
    case open
    case closing
    case closed
}

/// A WebRTC data channel.
public struct DataChannel: Sendable, Equatable {
    /// Unique channel ID (SCTP stream identifier).
    public let id: UInt16

    /// Locally unique lifecycle generation for this stream identifier.
    ///
    /// SCTP stream identifiers may be reused after a successful RFC 6525 reset.
    /// The generation distinguishes queued events from an earlier use of the
    /// same identifier; it is local metadata and is never sent on the wire.
    public let generation: UInt64

    /// Channel label.
    public let label: String

    /// Negotiated sub-protocol.
    public let `protocol`: String

    /// Whether this channel is ordered.
    public let ordered: Bool

    /// Sender-side persistence policy for application messages on this channel.
    public let reliability: DataChannelReliability

    /// State at the instant this value was returned.
    ///
    /// `DataChannel` is an immutable descriptor snapshot. Query the manager or
    /// consume `WebRTCDataChannelEvent` values for later state transitions.
    public var state: DataChannelState

    public init(
        id: UInt16,
        generation: UInt64 = 0,
        label: String,
        protocol: String = "",
        ordered: Bool = true,
        reliability: DataChannelReliability = .reliable,
        state: DataChannelState = .connecting
    ) {
        self.id = id
        self.generation = generation
        self.label = label
        self.protocol = `protocol`
        self.ordered = ordered
        self.reliability = reliability
        self.state = state
    }
}

/// Data channel manager handling DCEP and channel lifecycle.
final class DataChannelManager: Sendable {
    private let managerState: FacadeLock<ManagerState>

    private struct ManagerState: Sendable {
        var channels: [UInt16: DataChannel] = [:]
        var nextStreamID: UInt16
        var nextChannelGeneration: UInt64? = 1
        var implicitlyAcknowledgedChannels: Set<UInt16> = []
        var resetProgress: [UInt16: ResetProgress] = [:]
    }

    private struct ResetProgress: Sendable {
        var localResetRequested = false
        var incomingResetCompleted = false
        var outgoingResetCompleted = false
        var outgoingResetFailureReported = false
    }

    /// Whether this is the initiator (even stream IDs) or responder (odd stream IDs).
    private let isInitiator: Bool

    /// Hard cap on simultaneously tracked channels (open + connecting).
    private let maxChannels: Int

    /// Maximum byte length accepted for a DCEP label or protocol field.
    private let maxLabelOrProtocolLength: Int

    init(
        isInitiator: Bool,
        maxChannels: Int = 65535,
        maxLabelOrProtocolLength: Int = Int(UInt16.max)
    ) {
        self.isInitiator = isInitiator
        self.maxChannels = maxChannels
        self.maxLabelOrProtocolLength = maxLabelOrProtocolLength
        self.managerState = FacadeLock(ManagerState(
            nextStreamID: isInitiator ? 0 : 1
        ))
    }

    // MARK: - [UInt8] surface (Embedded-clean)

    /// Open a new data channel (`[UInt8]` DCEP surface).
    /// - Returns: (channel, DCEP Open message bytes to send on SCTP).
    /// - Throws: `DataChannelError.streamIDsExhausted`, `.tooManyChannels`,
    ///   `.labelOrProtocolTooLong`.
    func openChannelBytes(
        label: String,
        ordered: Bool = true,
        protocol channelProtocol: String = "",
        reliabilityParameter: UInt32 = 0,
        priority: UInt16 = 0
    ) throws(DataChannelError) -> (DataChannel, [UInt8]) {
        try openChannelBytes(
            label: label,
            ordered: ordered,
            protocol: channelProtocol,
            reliability: reliabilityParameter == 0
                ? .reliable
                : .maximumRetransmissions(reliabilityParameter),
            priority: priority
        )
    }

    /// Open a new data channel with an explicit reliable, retransmit-count, or
    /// timed partial-reliability policy.
    func openChannelBytes(
        label: String,
        ordered: Bool = true,
        protocol channelProtocol: String = "",
        reliability: DataChannelReliability,
        priority: UInt16 = 0
    ) throws(DataChannelError) -> (DataChannel, [UInt8]) {
        guard label.utf8.count <= maxLabelOrProtocolLength,
              channelProtocol.utf8.count <= maxLabelOrProtocolLength else {
            throw DataChannelError.labelOrProtocolTooLong(limit: maxLabelOrProtocolLength)
        }

        let channelType = Self.channelType(
            ordered: ordered,
            reliability: reliability
        )
        let reliabilityParameter = Self.reliabilityParameter(reliability)
        let dcepBytes: [UInt8]
        do {
            dcepBytes = try DCEPOpen(
                channelType: channelType,
                priority: priority,
                reliabilityParameter: reliabilityParameter,
                label: label,
                protocol_: channelProtocol
            ).encodeBytes()
        } catch {
            try error.rethrowUnwrapped()
        }

        return try managerState.withLock { (s) throws(DataChannelError) -> (DataChannel, [UInt8]) in
            guard s.channels.count < maxChannels else {
                throw DataChannelError.tooManyChannels(limit: maxChannels)
            }

            // Find the next free stream ID of our parity. Detect exhaustion
            // instead of wrapping/trapping on UInt16 overflow, and skip IDs that
            // already have a live channel (collision check).
            let parityStart: UInt16 = isInitiator ? 0 : 1
            let streamID = try Self.allocateStreamID(
                start: s.nextStreamID,
                parityStart: parityStart,
                maximumStreamID: isInitiator ? UInt16.max - 1 : UInt16.max - 2,
                taken: s.channels
            )
            let maximumStreamID = isInitiator ? UInt16.max - 1 : UInt16.max - 2
            s.nextStreamID = streamID > maximumStreamID - 2
                ? parityStart
                : streamID + 2

            let channel = DataChannel(
                id: streamID,
                generation: try Self.allocateGeneration(state: &s),
                label: label,
                protocol: channelProtocol,
                ordered: ordered,
                reliability: reliability,
                state: .connecting
            )
            s.channels[streamID] = channel
            return (channel, dcepBytes)
        }
    }

    /// Process an incoming DCEP message on a stream (`[UInt8]` surface).
    /// - Returns: optional response bytes to send, and the opened channel if any.
    /// - Throws: `DataChannelError.streamParityViolation`, `.unexpectedAck`,
    ///   resource-cap errors, decode errors.
    func processIncomingDCEPBytes(
        streamID: UInt16,
        data: [UInt8]
    ) throws(DataChannelError) -> (response: [UInt8]?, channel: DataChannel?) {
        guard !data.isEmpty else {
            throw DataChannelError.invalidFormat("Empty DCEP message")
        }

        switch data[0] {
        case DCEPMessageType.dataChannelOpen.rawValue:
            // RFC 8832 §6: the side that did NOT initiate the channel must use the
            // opposite stream-ID parity. We open on (isInitiator ? even : odd), so
            // a peer-initiated OPEN must use (isInitiator ? odd : even).
            let isEven = (streamID % 2 == 0)
            let expectedEven = !isInitiator
            guard isEven == expectedEven else {
                throw DataChannelError.streamParityViolation(streamID: streamID)
            }

            let open: DCEPOpen
            do {
                open = try DCEPOpen.decode(from: data)
            } catch {
                try error.rethrowUnwrapped()
            }
            guard open.label.utf8.count <= maxLabelOrProtocolLength,
                  open.protocol_.utf8.count <= maxLabelOrProtocolLength else {
                throw DataChannelError.labelOrProtocolTooLong(limit: maxLabelOrProtocolLength)
            }
            let reliability = Self.reliability(
                channelType: open.channelType,
                parameter: open.reliabilityParameter
            )

            // RFC 8832 §8.2.2: high-order bit (0x80) indicates unordered delivery.
            let isOrdered = (open.channelType.rawValue & 0x80) == 0
            return try managerState.withLock { (s) throws(DataChannelError) -> ([UInt8]?, DataChannel?) in
                // RFC 8832 §6: an OPEN on a stream already used by a channel is
                // not acknowledged. The WebRTC owner converts this typed error
                // into an outgoing SCTP stream reset for the affected channel.
                if s.channels[streamID] != nil {
                    throw DataChannelError.streamAlreadyInUse(streamID: streamID)
                }

                guard s.channels.count < maxChannels else {
                    throw DataChannelError.tooManyChannels(limit: maxChannels)
                }
                let channel = DataChannel(
                    id: streamID,
                    generation: try Self.allocateGeneration(state: &s),
                    label: open.label,
                    protocol: open.protocol_,
                    ordered: isOrdered,
                    reliability: reliability,
                    state: .open
                )
                s.channels[streamID] = channel
                return (DCEPAck().encodeBytes(), channel)
            }

        case DCEPMessageType.dataChannelAck.rawValue:
            // RFC 8832 §5.2: an ACK is only valid for a channel we opened that is
            // awaiting confirmation. The local stream-ID parity proves that this
            // endpoint sent the OPEN; requiring `.connecting` prevents a delayed
            // or duplicate ACK from reopening a channel whose close already began.
            let expectedEven = isInitiator
            do {
                _ = try DCEPAck.decode(from: data)
            } catch {
                try error.rethrowUnwrapped()
            }
            let opened = try managerState.withLock { (s) throws(DataChannelError) -> DataChannel? in
                guard (streamID % 2 == 0) == expectedEven,
                      var channel = s.channels[streamID] else {
                    throw DataChannelError.unexpectedAck(streamID: streamID)
                }
                if channel.state == .connecting {
                    channel.state = .open
                    s.channels[streamID] = channel
                    return channel
                }
                if channel.state == .open,
                   s.implicitlyAcknowledgedChannels.remove(streamID) != nil {
                    return nil
                }
                throw DataChannelError.unexpectedAck(streamID: streamID)
            }
            return (nil, opened)

        default:
            throw DataChannelError.invalidFormat("Unknown DCEP type")
        }
    }

    #if !hasFeature(Embedded) && !os(WASI)
    // MARK: - Data surface (host-only)

    /// Open a new data channel (`Data` DCEP surface).
    func openChannel(
        label: String,
        ordered: Bool = true,
        protocol channelProtocol: String = "",
        reliabilityParameter: UInt32 = 0,
        priority: UInt16 = 0
    ) throws -> (DataChannel, Data) {
        let (channel, bytes) = try openChannelBytes(
            label: label,
            ordered: ordered,
            protocol: channelProtocol,
            reliabilityParameter: reliabilityParameter,
            priority: priority
        )
        return (channel, Data(bytes))
    }

    /// Open a host data channel with an explicit persistence policy.
    func openChannel(
        label: String,
        ordered: Bool = true,
        protocol channelProtocol: String = "",
        reliability: DataChannelReliability,
        priority: UInt16 = 0
    ) throws -> (DataChannel, Data) {
        let (channel, bytes) = try openChannelBytes(
            label: label,
            ordered: ordered,
            protocol: channelProtocol,
            reliability: reliability,
            priority: priority
        )
        return (channel, Data(bytes))
    }

    /// Process an incoming DCEP message on a stream (`Data` surface).
    func processIncomingDCEP(
        streamID: UInt16,
        data: Data
    ) throws -> (response: Data?, channel: DataChannel?) {
        let (response, channel) = try processIncomingDCEPBytes(streamID: streamID, data: [UInt8](data))
        return (response.map { Data($0) }, channel)
    }
    #endif

    // MARK: - Channel queries / lifecycle

    /// Allocate the next free stream ID at or after `start` of the same parity,
    /// skipping IDs already in use. Throws when the parity space is exhausted.
    private static func allocateStreamID(
        start: UInt16,
        parityStart: UInt16,
        maximumStreamID: UInt16,
        taken: [UInt16: DataChannel]
    ) throws(DataChannelError) -> UInt16 {
        guard start <= maximumStreamID,
              start % 2 == parityStart % 2 else {
            throw DataChannelError.streamIDsExhausted
        }
        var candidate = start
        repeat {
            if taken[candidate] == nil {
                return candidate
            }
            candidate = candidate > maximumStreamID - 2
                ? parityStart
                : candidate + 2
        } while candidate != start
        throw DataChannelError.streamIDsExhausted
    }

    /// Allocate monotonic local lifecycle identity without wrapping. Reusing a
    /// generation could make a delayed event from an old SCTP stream target a
    /// new channel, so exhaustion is explicit even though it is practically
    /// unreachable.
    private static func allocateGeneration(
        state: inout ManagerState
    ) throws(DataChannelError) -> UInt64 {
        guard let generation = state.nextChannelGeneration else {
            throw .channelGenerationsExhausted
        }
        state.nextChannelGeneration = generation == UInt64.max
            ? nil
            : generation + 1
        return generation
    }

    /// Map ordering and persistence into the exact DCEP channel type.
    private static func channelType(
        ordered: Bool,
        reliability: DataChannelReliability
    ) -> DCEPChannelType {
        switch reliability {
        case .reliable:
            return ordered ? .reliable : .reliableUnordered
        case .maximumRetransmissions:
            return ordered
                ? .partialReliableRexmit
                : .partialReliableRexmitUnordered
        case .maximumLifetimeMilliseconds:
            return ordered
                ? .partialReliableTimed
                : .partialReliableTimedUnordered
        }
    }

    private static func reliabilityParameter(
        _ reliability: DataChannelReliability
    ) -> UInt32 {
        switch reliability {
        case .reliable:
            return 0
        case .maximumRetransmissions(let count),
             .maximumLifetimeMilliseconds(let count):
            return count
        }
    }

    private static func reliability(
        channelType: DCEPChannelType,
        parameter: UInt32
    ) -> DataChannelReliability {
        switch channelType {
        case .reliable, .reliableUnordered:
            return .reliable
        case .partialReliableRexmit, .partialReliableRexmitUnordered:
            return .maximumRetransmissions(parameter)
        case .partialReliableTimed, .partialReliableTimedUnordered:
            return .maximumLifetimeMilliseconds(parameter)
        }
    }

    /// Get a channel by stream ID.
    func channel(id: UInt16) -> DataChannel? {
        managerState.withLock { $0.channels[id] }
    }

    /// Get all open channels.
    var channels: [DataChannel] {
        managerState.withLock { Array($0.channels.values) }
    }

    /// Atomically derive the SCTP ordering flag for one outbound message.
    /// Locally opened unordered channels remain ordered until the DCEP ACK or
    /// an implicit acknowledgement arrives, as required by RFC 8832 section 6.
    func sendPolicy(id: UInt16) throws(DataChannelError) -> DataChannelSendPolicy {
        try managerState.withLock { state throws(DataChannelError) in
            guard let channel = state.channels[id] else {
                throw .channelClosed
            }
            guard channel.state != .closing, channel.state != .closed else {
                throw .channelClosed
            }
            return DataChannelSendPolicy(
                unordered: !channel.ordered && channel.state == .open,
                reliability: Self.sctpReliability(channel.reliability)
            )
        }
    }

    private static func sctpReliability(
        _ reliability: DataChannelReliability
    ) -> SCTPMessageReliability {
        switch reliability {
        case .reliable:
            return .reliable
        case .maximumRetransmissions(let count):
            return .maximumRetransmissions(count)
        case .maximumLifetimeMilliseconds(let lifetime):
            return .maximumLifetimeMilliseconds(lifetime)
        }
    }

    /// Treat the first peer application message as an implicit DCEP ACK.
    /// Returns the new open-state snapshot only when this call transitioned the
    /// channel from connecting to open.
    func observeIncomingMessage(id: UInt16) throws(DataChannelError) -> DataChannel? {
        try managerState.withLock { state throws(DataChannelError) in
            guard var channel = state.channels[id] else {
                throw .channelClosed
            }
            guard channel.state == .connecting else { return nil }
            channel.state = .open
            state.channels[id] = channel
            state.implicitlyAcknowledgedChannels.insert(id)
            return channel
        }
    }

    /// Mark a locally initiated close before the SCTP reset request is emitted.
    /// - Returns: `true` only for the first request for this channel.
    func beginClose(id: UInt16) throws(DataChannelError) -> Bool {
        try managerState.withLock { state throws(DataChannelError) in
            guard var channel = state.channels[id] else {
                throw .channelClosed
            }
            var progress = state.resetProgress[id] ?? ResetProgress()
            guard !progress.localResetRequested else { return false }
            progress.localResetRequested = true
            channel.state = .closing
            state.channels[id] = channel
            state.resetProgress[id] = progress
            return true
        }
    }

    /// Apply an ordered SCTP reset event and derive reciprocal WebRTC work.
    func apply(
        _ event: SCTPAssociationEvent
    ) -> DataChannelResetTransition {
        managerState.withLock { state in
            switch event {
            case .associationRestarted:
                let channelIDs = state.channels.keys.sorted()
                var closeEvents: [DataChannelCloseEvent] = []
                closeEvents.reserveCapacity(channelIDs.count)
                for channelID in channelIDs {
                    guard let channel = state.channels[channelID] else { continue }
                    closeEvents.append(.closed(
                        channelID: channelID,
                        generation: channel.generation
                    ))
                }
                state.channels.removeAll(keepingCapacity: true)
                state.implicitlyAcknowledgedChannels.removeAll(keepingCapacity: true)
                state.resetProgress.removeAll(keepingCapacity: true)
                state.nextStreamID = isInitiator ? 0 : 1
                return DataChannelResetTransition(
                    reciprocalReset: nil,
                    closeEvents: closeEvents
                )

            case .incomingStreamsReset(let selection):
                let channelIDs = Self.selectedChannelIDs(
                    selection,
                    channels: state.channels
                )
                var reciprocal: [UInt16] = []
                var closeEvents: [DataChannelCloseEvent] = []
                for channelID in channelIDs {
                    guard var channel = state.channels[channelID] else { continue }
                    var progress = state.resetProgress[channelID] ?? ResetProgress()
                    if !progress.localResetRequested {
                        progress.localResetRequested = true
                        reciprocal.append(channelID)
                    }
                    progress.incomingResetCompleted = true
                    channel.state = .closing
                    state.channels[channelID] = channel
                    state.resetProgress[channelID] = progress
                    if progress.outgoingResetCompleted {
                        Self.removeChannel(
                            channelID,
                            state: &state,
                            localParity: isInitiator ? 0 : 1
                        )
                        closeEvents.append(.closed(
                            channelID: channelID,
                            generation: channel.generation
                        ))
                    }
                }
                return DataChannelResetTransition(
                    reciprocalReset: reciprocal.isEmpty ? nil : .listed(reciprocal),
                    closeEvents: closeEvents
                )

            case .outgoingStreamsReset(let selection):
                let channelIDs = Self.selectedChannelIDs(
                    selection,
                    channels: state.channels
                )
                var closeEvents: [DataChannelCloseEvent] = []
                for channelID in channelIDs {
                    guard var channel = state.channels[channelID] else { continue }
                    var progress = state.resetProgress[channelID] ?? ResetProgress()
                    progress.outgoingResetCompleted = true
                    channel.state = .closing
                    state.channels[channelID] = channel
                    state.resetProgress[channelID] = progress
                    if progress.incomingResetCompleted {
                        Self.removeChannel(
                            channelID,
                            state: &state,
                            localParity: isInitiator ? 0 : 1
                        )
                        closeEvents.append(.closed(
                            channelID: channelID,
                            generation: channel.generation
                        ))
                    }
                }
                return DataChannelResetTransition(
                    reciprocalReset: nil,
                    closeEvents: closeEvents
                )

            case .outgoingStreamResetFailed(let selection, let result):
                let channelIDs = Self.selectedChannelIDs(
                    selection,
                    channels: state.channels
                )
                var closeEvents: [DataChannelCloseEvent] = []
                closeEvents.reserveCapacity(channelIDs.count)
                for channelID in channelIDs {
                    guard var channel = state.channels[channelID] else { continue }
                    var progress = state.resetProgress[channelID] ?? ResetProgress()
                    guard !progress.outgoingResetFailureReported else { continue }
                    progress.outgoingResetFailureReported = true
                    channel.state = .closing
                    state.channels[channelID] = channel
                    state.resetProgress[channelID] = progress

                    // A denied or failed RFC 6525 reset does not establish that
                    // either SCTP direction is reset. Retain the channel binding
                    // until association shutdown so delayed DATA cannot be routed
                    // to a newly allocated channel that reuses the same SID.
                    closeEvents.append(.failed(
                        channelID: channelID,
                        generation: channel.generation,
                        result: result
                    ))
                }
                return DataChannelResetTransition(
                    reciprocalReset: nil,
                    closeEvents: closeEvents
                )
            }
        }
    }

    /// Reject writes after close has begun and reject unknown stream IDs.
    func requireWritableChannel(id: UInt16) throws(DataChannelError) {
        _ = try sendPolicy(id: id)
    }

    /// Begin an RFC 8831 channel close.
    ///
    /// The channel remains `.closing` until both SCTP stream directions report
    /// reset completion. `true` means the caller must emit the outgoing reset.
    func closeChannel(id: UInt16) throws(DataChannelError) -> Bool {
        try beginClose(id: id)
    }

    /// Shutdown the manager, closing all channels.
    func shutdown() {
        managerState.withLock { s in
            for channelID in s.channels.keys {
                s.channels[channelID]?.state = .closed
            }
            s.channels.removeAll()
            s.implicitlyAcknowledgedChannels.removeAll()
            s.resetProgress.removeAll()
        }
    }

    private static func selectedChannelIDs(
        _ selection: SCTPStreamSelection,
        channels: [UInt16: DataChannel]
    ) -> [UInt16] {
        let listed = selection.wireStreamIDs
        return listed.isEmpty ? channels.keys.sorted() : listed
    }

    private static func removeChannel(
        _ channelID: UInt16,
        state: inout ManagerState,
        localParity: UInt16
    ) {
        state.channels.removeValue(forKey: channelID)
        state.implicitlyAcknowledgedChannels.remove(channelID)
        if channelID % 2 == localParity {
            state.nextStreamID = channelID
        }
        state.resetProgress.removeValue(forKey: channelID)
    }
}
