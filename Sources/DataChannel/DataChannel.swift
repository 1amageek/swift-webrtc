/// WebRTC Data Channel (RFC 8831) — caller-locked adapter.
///
/// A single bidirectional data channel over SCTP, plus the `DataChannelManager`
/// that handles DCEP open/ack and channel lifecycle.
///
/// `DataChannelManager` is a `final class & Sendable` that holds its mutable
/// channel-table state value behind a ``FacadeLock`` (the proven caller-locked
/// pattern: `Synchronization.Mutex` on host, an `Atomic` spinlock under Embedded),
/// driving `DataChannelCore`'s DCEP codec. The currency is `[UInt8]`
/// (Embedded-clean); the historical `Data`-based `openChannel` /
/// `processIncomingDCEP` overloads are gated host-only.

import SCTPCore
import DataChannelCore
#if !hasFeature(Embedded)
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
public struct DataChannel: Sendable {
    /// Unique channel ID (SCTP stream identifier).
    public let id: UInt16

    /// Channel label.
    public let label: String

    /// Negotiated sub-protocol.
    public let `protocol`: String

    /// Whether this channel is ordered.
    public let ordered: Bool

    /// Current state.
    public var state: DataChannelState

    public init(
        id: UInt16,
        label: String,
        protocol: String = "",
        ordered: Bool = true,
        state: DataChannelState = .connecting
    ) {
        self.id = id
        self.label = label
        self.protocol = `protocol`
        self.ordered = ordered
        self.state = state
    }
}

/// Data channel manager handling DCEP and channel lifecycle.
public final class DataChannelManager: Sendable {
    private let managerState: FacadeLock<ManagerState>

    private struct ManagerState: Sendable {
        var channels: [UInt16: DataChannel] = [:]
        var nextStreamID: UInt16
        var pendingIncoming: [DataChannel] = []
    }

    /// Whether this is the initiator (even stream IDs) or responder (odd stream IDs).
    private let isInitiator: Bool

    /// Hard cap on simultaneously tracked channels (open + connecting).
    private let maxChannels: Int

    /// Hard cap on undelivered incoming channels awaiting `takePendingIncoming`.
    private let maxPendingIncoming: Int

    /// Maximum byte length accepted for a DCEP label or protocol field.
    private let maxLabelOrProtocolLength: Int

    public init(
        isInitiator: Bool,
        maxChannels: Int = 65535,
        maxPendingIncoming: Int = 1024,
        maxLabelOrProtocolLength: Int = 8192
    ) {
        self.isInitiator = isInitiator
        self.maxChannels = maxChannels
        self.maxPendingIncoming = maxPendingIncoming
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
    public func openChannelBytes(
        label: String,
        ordered: Bool = true,
        protocol channelProtocol: String = "",
        reliabilityParameter: UInt32 = 0,
        priority: UInt16 = 0
    ) throws(DataChannelError) -> (DataChannel, [UInt8]) {
        guard Array(label.utf8).count <= maxLabelOrProtocolLength,
              Array(channelProtocol.utf8).count <= maxLabelOrProtocolLength else {
            throw DataChannelError.labelOrProtocolTooLong(limit: maxLabelOrProtocolLength)
        }

        return try managerState.withLock { (s) throws(DataChannelError) -> (DataChannel, [UInt8]) in
            guard s.channels.count < maxChannels else {
                throw DataChannelError.tooManyChannels(limit: maxChannels)
            }

            // Find the next free stream ID of our parity. Detect exhaustion
            // instead of wrapping/trapping on UInt16 overflow, and skip IDs that
            // already have a live channel (collision check).
            let streamID = try Self.allocateStreamID(start: s.nextStreamID, taken: s.channels)
            let (advanced, overflow) = streamID.addingReportingOverflow(2)
            s.nextStreamID = overflow ? streamID : advanced

            let channelType = Self.channelType(
                ordered: ordered,
                reliabilityParameter: reliabilityParameter
            )

            let channel = DataChannel(
                id: streamID,
                label: label,
                protocol: channelProtocol,
                ordered: ordered,
                state: .connecting
            )
            s.channels[streamID] = channel

            let dcepOpen = DCEPOpen(
                channelType: channelType,
                priority: priority,
                reliabilityParameter: reliabilityParameter,
                label: label,
                protocol_: channelProtocol
            )

            return (channel, dcepOpen.encodeBytes())
        }
    }

    /// Process an incoming DCEP message on a stream (`[UInt8]` surface).
    /// - Returns: optional response bytes to send, and the opened channel if any.
    /// - Throws: `DataChannelError.streamParityViolation`, `.unexpectedAck`,
    ///   resource-cap errors, decode errors.
    public func processIncomingDCEPBytes(
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
            guard Array(open.label.utf8).count <= maxLabelOrProtocolLength,
                  Array(open.protocol_.utf8).count <= maxLabelOrProtocolLength else {
                throw DataChannelError.labelOrProtocolTooLong(limit: maxLabelOrProtocolLength)
            }

            // RFC 8832 §8.2.2: high-order bit (0x80) indicates unordered delivery.
            let isOrdered = (open.channelType.rawValue & 0x80) == 0
            let channel = DataChannel(
                id: streamID,
                label: open.label,
                protocol: open.protocol_,
                ordered: isOrdered,
                state: .open
            )

            return try managerState.withLock { (s) throws(DataChannelError) -> ([UInt8]?, DataChannel?) in
                // Duplicate OPEN (retransmitted): re-ACK idempotently without
                // replacing the live channel or re-queuing it as a new arrival.
                if let existing = s.channels[streamID] {
                    return (DCEPAck().encodeBytes(), existing)
                }

                guard s.channels.count < maxChannels else {
                    throw DataChannelError.tooManyChannels(limit: maxChannels)
                }
                guard s.pendingIncoming.count < maxPendingIncoming else {
                    throw DataChannelError.tooManyChannels(limit: maxPendingIncoming)
                }

                s.channels[streamID] = channel
                s.pendingIncoming.append(channel)
                return (DCEPAck().encodeBytes(), channel)
            }

        case DCEPMessageType.dataChannelAck.rawValue:
            // RFC 8832 §5.2: an ACK is only valid for a channel we opened that is
            // awaiting confirmation. A stray ACK is a protocol violation.
            try managerState.withLock { (s) throws(DataChannelError) -> Void in
                guard s.channels[streamID] != nil else {
                    throw DataChannelError.unexpectedAck(streamID: streamID)
                }
                s.channels[streamID]?.state = .open
            }
            return (nil, nil)

        default:
            throw DataChannelError.invalidFormat("Unknown DCEP type")
        }
    }

    #if !hasFeature(Embedded)
    // MARK: - Data surface (host-only)

    /// Open a new data channel (`Data` DCEP surface).
    public func openChannel(
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

    /// Process an incoming DCEP message on a stream (`Data` surface).
    public func processIncomingDCEP(
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
        taken: [UInt16: DataChannel]
    ) throws(DataChannelError) -> UInt16 {
        var candidate = start
        while taken[candidate] != nil {
            let (next, overflow) = candidate.addingReportingOverflow(2)
            if overflow {
                throw DataChannelError.streamIDsExhausted
            }
            candidate = next
        }
        return candidate
    }

    /// Map ordered/reliability into a DCEP channel type. A non-zero reliability
    /// parameter selects a partial-reliability (rexmit) channel type so the
    /// caller's reliability intent is not dropped.
    private static func channelType(
        ordered: Bool,
        reliabilityParameter: UInt32
    ) -> DCEPChannelType {
        if reliabilityParameter == 0 {
            return ordered ? .reliable : .reliableUnordered
        } else {
            return ordered ? .partialReliableRexmit : .partialReliableRexmitUnordered
        }
    }

    /// Get a channel by stream ID.
    public func channel(id: UInt16) -> DataChannel? {
        managerState.withLock { $0.channels[id] }
    }

    /// Get all open channels.
    public var channels: [DataChannel] {
        managerState.withLock { Array($0.channels.values) }
    }

    /// Take pending incoming channels.
    public func takePendingIncoming() -> [DataChannel] {
        managerState.withLock { s in
            let pending = s.pendingIncoming
            s.pendingIncoming.removeAll()
            return pending
        }
    }

    /// Close a channel.
    public func closeChannel(id: UInt16) {
        managerState.withLock { s in
            s.channels[id]?.state = .closed
        }
    }

    /// Shutdown the manager, closing all channels.
    public func shutdown() {
        managerState.withLock { s in
            for channelID in s.channels.keys {
                s.channels[channelID]?.state = .closed
            }
            s.channels.removeAll()
            s.pendingIncoming.removeAll()
        }
    }
}
