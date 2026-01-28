/// WebRTC Data Channel Establishment Protocol (RFC 8832)
///
/// DCEP messages for opening data channels over SCTP.

import Foundation

/// DCEP message type
public enum DCEPMessageType: UInt8, Sendable {
    case dataChannelOpen = 0x03
    case dataChannelAck = 0x02
}

/// DCEP channel type
public enum DCEPChannelType: UInt8, Sendable {
    case reliable = 0x00
    case reliableUnordered = 0x80
    case partialReliableRexmit = 0x01
    case partialReliableRexmitUnordered = 0x81
    case partialReliableTimed = 0x02
    case partialReliableTimedUnordered = 0x82
}

/// DCEP DATA_CHANNEL_OPEN message
public struct DCEPOpen: Sendable {
    public let channelType: DCEPChannelType
    public let priority: UInt16
    public let reliabilityParameter: UInt32
    public let label: String
    public let protocol_: String

    public init(
        channelType: DCEPChannelType = .reliable,
        priority: UInt16 = 0,
        reliabilityParameter: UInt32 = 0,
        label: String,
        protocol_: String = ""
    ) {
        self.channelType = channelType
        self.priority = priority
        self.reliabilityParameter = reliabilityParameter
        self.label = label
        self.protocol_ = protocol_
    }

    /// Encode to wire format
    public func encode() -> Data {
        let labelData = Data(label.utf8)
        let protocolData = Data(protocol_.utf8)

        var data = Data(capacity: 12 + labelData.count + protocolData.count)
        data.append(DCEPMessageType.dataChannelOpen.rawValue)
        data.append(channelType.rawValue)
        data.append(UInt8(priority >> 8))
        data.append(UInt8(priority & 0xFF))
        data.append(UInt8(reliabilityParameter >> 24))
        data.append(UInt8((reliabilityParameter >> 16) & 0xFF))
        data.append(UInt8((reliabilityParameter >> 8) & 0xFF))
        data.append(UInt8(reliabilityParameter & 0xFF))

        let labelLen = UInt16(labelData.count)
        data.append(UInt8(labelLen >> 8))
        data.append(UInt8(labelLen & 0xFF))

        let protoLen = UInt16(protocolData.count)
        data.append(UInt8(protoLen >> 8))
        data.append(UInt8(protoLen & 0xFF))

        data.append(labelData)
        data.append(protocolData)

        return data
    }

    /// Decode from wire format
    public static func decode(from data: Data) throws -> DCEPOpen {
        guard data.count >= 12 else {
            throw DataChannelError.invalidFormat("DCEP Open too short")
        }
        guard data[0] == DCEPMessageType.dataChannelOpen.rawValue else {
            throw DataChannelError.invalidFormat("Not a DCEP Open message")
        }

        let channelType = DCEPChannelType(rawValue: data[1]) ?? .reliable
        let priority = UInt16(data[2]) << 8 | UInt16(data[3])
        let reliability = UInt32(data[4]) << 24 | UInt32(data[5]) << 16 | UInt32(data[6]) << 8 | UInt32(data[7])
        let labelLen = Int(UInt16(data[8]) << 8 | UInt16(data[9]))
        let protoLen = Int(UInt16(data[10]) << 8 | UInt16(data[11]))

        guard data.count >= 12 + labelLen + protoLen else {
            throw DataChannelError.invalidFormat("DCEP Open data too short for label/protocol")
        }

        let label = String(data: Data(data[12..<12 + labelLen]), encoding: .utf8) ?? ""
        let proto = String(data: Data(data[12 + labelLen..<12 + labelLen + protoLen]), encoding: .utf8) ?? ""

        return DCEPOpen(
            channelType: channelType,
            priority: priority,
            reliabilityParameter: reliability,
            label: label,
            protocol_: proto
        )
    }
}

/// DCEP DATA_CHANNEL_ACK message
public struct DCEPAck: Sendable {
    public init() {}

    public func encode() -> Data {
        Data([DCEPMessageType.dataChannelAck.rawValue])
    }

    public static func decode(from data: Data) throws -> DCEPAck {
        guard data.count >= 1, data[0] == DCEPMessageType.dataChannelAck.rawValue else {
            throw DataChannelError.invalidFormat("Not a DCEP Ack message")
        }
        return DCEPAck()
    }
}

/// Data channel errors
public enum DataChannelError: Error, Sendable {
    case invalidFormat(String)
    case channelClosed
    case notReady
}
