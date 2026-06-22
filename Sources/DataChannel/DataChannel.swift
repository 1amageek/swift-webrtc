/// WebRTC Data Channel (RFC 8831)
///
/// A single bidirectional data channel over SCTP.

import Foundation
import SCTPCore

/// Data channel state
public enum DataChannelState: Sendable, Equatable {
    case connecting
    case open
    case closing
    case closed
}

/// A WebRTC data channel
public struct DataChannel: Sendable {
    /// Unique channel ID (SCTP stream identifier)
    public let id: UInt16

    /// Channel label
    public let label: String

    /// Negotiated sub-protocol
    public let `protocol`: String

    /// Whether this channel is ordered
    public let ordered: Bool

    /// Current state
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

/// Data channel manager handling DCEP and channel lifecycle
public final class DataChannelManager: Sendable {
    private let managerState: Mutex<ManagerState>

    private struct ManagerState: Sendable {
        var channels: [UInt16: DataChannel] = [:]
        var nextStreamID: UInt16
        var pendingIncoming: [DataChannel] = []
    }

    /// Whether this is the initiator (even stream IDs) or responder (odd stream IDs)
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
        self.managerState = Mutex(ManagerState(
            nextStreamID: isInitiator ? 0 : 1
        ))
    }

    /// Open a new data channel
    /// - Parameters:
    ///   - label: Channel label
    ///   - ordered: Whether messages are ordered
    /// - Returns: (channel, DCEP Open message to send on SCTP)
    /// - Throws: `DataChannelError.streamIDsExhausted` when no further stream ID
    ///   of the local parity is available, `DataChannelError.tooManyChannels`
    ///   when the channel cap is reached, `DataChannelError.labelOrProtocolTooLong`
    ///   when the label exceeds the configured maximum.
    public func openChannel(
        label: String,
        ordered: Bool = true,
        protocol channelProtocol: String = "",
        reliabilityParameter: UInt32 = 0,
        priority: UInt16 = 0
    ) throws -> (DataChannel, Data) {
        guard Data(label.utf8).count <= maxLabelOrProtocolLength,
              Data(channelProtocol.utf8).count <= maxLabelOrProtocolLength else {
            throw DataChannelError.labelOrProtocolTooLong(limit: maxLabelOrProtocolLength)
        }

        return try managerState.withLock { s -> (DataChannel, Data) in
            guard s.channels.count < maxChannels else {
                throw DataChannelError.tooManyChannels(limit: maxChannels)
            }

            // Find the next free stream ID of our parity. Detect exhaustion
            // instead of wrapping/trapping on UInt16 overflow, and skip IDs
            // that already have a live channel (collision check).
            let streamID = try Self.allocateStreamID(start: s.nextStreamID, taken: s.channels)
            // Advance past the allocated ID, guarding the final-ID overflow.
            let (advanced, overflow) = streamID.addingReportingOverflow(2)
            s.nextStreamID = overflow ? streamID : advanced

            // Reliability/priority parameters are now threaded into the DCEP
            // OPEN so partial-reliability channels are not silently downgraded.
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

            return (channel, dcepOpen.encode())
        }
    }

    /// Process incoming DCEP message on a stream
    /// - Parameters:
    ///   - streamID: The SCTP stream ID
    ///   - data: The DCEP message data
    /// - Returns: Optional response data to send, and the opened channel if applicable
    /// - Throws: `DataChannelError.streamParityViolation` for an OPEN on a
    ///   stream ID of the local parity, `DataChannelError.unexpectedAck` for an
    ///   ACK on a stream with no channel awaiting one, and resource-cap errors.
    public func processIncomingDCEP(
        streamID: UInt16,
        data: Data
    ) throws -> (response: Data?, channel: DataChannel?) {
        guard !data.isEmpty else {
            throw DataChannelError.invalidFormat("Empty DCEP message")
        }

        switch data[0] {
        case DCEPMessageType.dataChannelOpen.rawValue:
            // RFC 8832 §6: the side that did NOT initiate the channel must use
            // the opposite stream-ID parity. We open on (isInitiator ? even :
            // odd), so a peer-initiated OPEN must use (isInitiator ? odd :
            // even). Reject a violation rather than accepting a colliding ID.
            let isEven = (streamID % 2 == 0)
            let expectedEven = !isInitiator
            guard isEven == expectedEven else {
                throw DataChannelError.streamParityViolation(streamID: streamID)
            }

            let open = try DCEPOpen.decode(from: data)
            guard Data(open.label.utf8).count <= maxLabelOrProtocolLength,
                  Data(open.protocol_.utf8).count <= maxLabelOrProtocolLength else {
                throw DataChannelError.labelOrProtocolTooLong(limit: maxLabelOrProtocolLength)
            }

            // RFC 8832 Section 8.2.2: High-order bit (0x80) indicates unordered delivery
            let isOrdered = (open.channelType.rawValue & 0x80) == 0
            let channel = DataChannel(
                id: streamID,
                label: open.label,
                protocol: open.protocol_,
                ordered: isOrdered,
                state: .open
            )

            return try managerState.withLock { s -> (Data?, DataChannel?) in
                // Duplicate OPEN (retransmitted): re-ACK idempotently without
                // replacing the live channel or re-queuing it as a new arrival.
                if let existing = s.channels[streamID] {
                    return (DCEPAck().encode(), existing)
                }

                guard s.channels.count < maxChannels else {
                    throw DataChannelError.tooManyChannels(limit: maxChannels)
                }
                guard s.pendingIncoming.count < maxPendingIncoming else {
                    throw DataChannelError.tooManyChannels(limit: maxPendingIncoming)
                }

                s.channels[streamID] = channel
                s.pendingIncoming.append(channel)
                return (DCEPAck().encode(), channel)
            }

        case DCEPMessageType.dataChannelAck.rawValue:
            // RFC 8832 §5.2: an ACK is only valid for a channel we opened that
            // is awaiting confirmation. A stray ACK is a protocol violation.
            try managerState.withLock { s in
                guard s.channels[streamID] != nil else {
                    throw DataChannelError.unexpectedAck(streamID: streamID)
                }
                s.channels[streamID]?.state = .open
            }
            return (nil, nil)

        default:
            throw DataChannelError.invalidFormat("Unknown DCEP type: \(data[0])")
        }
    }

    /// Allocate the next free stream ID at or after `start` of the same parity,
    /// skipping IDs already in use. Throws when the parity space is exhausted.
    private static func allocateStreamID(
        start: UInt16,
        taken: [UInt16: DataChannel]
    ) throws -> UInt16 {
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

    /// Get a channel by stream ID
    public func channel(id: UInt16) -> DataChannel? {
        managerState.withLock { $0.channels[id] }
    }

    /// Get all open channels
    public var channels: [DataChannel] {
        managerState.withLock { Array($0.channels.values) }
    }

    /// Take pending incoming channels
    public func takePendingIncoming() -> [DataChannel] {
        managerState.withLock { s in
            let pending = s.pendingIncoming
            s.pendingIncoming.removeAll()
            return pending
        }
    }

    /// Close a channel
    public func closeChannel(id: UInt16) {
        managerState.withLock { s in
            s.channels[id]?.state = .closed
        }
    }

    /// Shutdown the manager, closing all channels
    ///
    /// Call this method when the connection is being closed to ensure
    /// all channels are properly cleaned up.
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

// MARK: - Mutex import
import Synchronization
