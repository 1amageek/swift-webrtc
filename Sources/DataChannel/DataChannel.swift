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

    public init(isInitiator: Bool) {
        self.isInitiator = isInitiator
        self.managerState = Mutex(ManagerState(
            nextStreamID: isInitiator ? 0 : 1
        ))
    }

    /// Open a new data channel
    /// - Parameters:
    ///   - label: Channel label
    ///   - ordered: Whether messages are ordered
    /// - Returns: (channel, DCEP Open message to send on SCTP)
    public func openChannel(
        label: String,
        ordered: Bool = true
    ) -> (DataChannel, Data) {
        let (channel, dcepData) = managerState.withLock { s -> (DataChannel, Data) in
            let streamID = s.nextStreamID
            s.nextStreamID += 2 // Even for initiator, odd for responder

            let channel = DataChannel(
                id: streamID,
                label: label,
                ordered: ordered,
                state: .connecting
            )
            s.channels[streamID] = channel

            let dcepOpen = DCEPOpen(
                channelType: ordered ? .reliable : .reliableUnordered,
                label: label
            )

            return (channel, dcepOpen.encode())
        }

        return (channel, dcepData)
    }

    /// Process incoming DCEP message on a stream
    /// - Parameters:
    ///   - streamID: The SCTP stream ID
    ///   - data: The DCEP message data
    /// - Returns: Optional response data to send, and the opened channel if applicable
    public func processIncomingDCEP(
        streamID: UInt16,
        data: Data
    ) throws -> (response: Data?, channel: DataChannel?) {
        guard !data.isEmpty else {
            throw DataChannelError.invalidFormat("Empty DCEP message")
        }

        switch data[0] {
        case DCEPMessageType.dataChannelOpen.rawValue:
            let open = try DCEPOpen.decode(from: data)
            let channel = DataChannel(
                id: streamID,
                label: open.label,
                protocol: open.protocol_,
                ordered: open.channelType == .reliable,
                state: .open
            )
            managerState.withLock { s in
                s.channels[streamID] = channel
                s.pendingIncoming.append(channel)
            }
            let ack = DCEPAck()
            return (ack.encode(), channel)

        case DCEPMessageType.dataChannelAck.rawValue:
            managerState.withLock { s in
                s.channels[streamID]?.state = .open
            }
            return (nil, nil)

        default:
            throw DataChannelError.invalidFormat("Unknown DCEP type: \(data[0])")
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
}

// MARK: - Mutex import
import Synchronization
