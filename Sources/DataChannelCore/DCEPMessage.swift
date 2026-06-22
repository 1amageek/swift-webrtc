/// WebRTC Data Channel Establishment Protocol (RFC 8832)
///
/// DCEP messages for opening data channels over SCTP.

import P2PCoreBytes

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

/// Strictly validate a UTF-8 byte sequence, returning `nil` on any malformed
/// scalar.
///
/// `String(decoding:as:)` lossily substitutes U+FFFD for invalid input, which
/// would silently accept malformed labels. RFC 8832 requires labels/protocols
/// to be valid UTF-8, so this validates explicitly and rejects on error.
func validatedUTF8String(_ bytes: [UInt8]) -> String? {
    var decoder = Unicode.UTF8()
    var iterator = bytes.makeIterator()
    var scalars = String.UnicodeScalarView()
    decodeLoop: while true {
        switch decoder.decode(&iterator) {
        case .scalarValue(let scalar):
            scalars.append(scalar)
        case .emptyInput:
            break decodeLoop
        case .error:
            return nil
        }
    }
    return String(scalars)
}

/// DCEP DATA_CHANNEL_OPEN message.
///
/// The Embedded-clean core encodes/decodes over `[UInt8]`. The `DataChannel`
/// adapter restores the `Data`-based `encode()`/`decode(from:Data)` surface.
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
    public func encodeBytes() -> [UInt8] {
        let labelData = Array(label.utf8)
        let protocolData = Array(protocol_.utf8)

        var data = [UInt8]()
        data.reserveCapacity(12 + labelData.count + protocolData.count)
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

        data.append(contentsOf: labelData)
        data.append(contentsOf: protocolData)

        return data
    }

    /// Decode from wire format
    public static func decode(from data: [UInt8]) throws(DataChannelWireError) -> DCEPOpen {
        guard data.count >= 12 else {
            throw .decode(.invalidFormat("DCEP Open too short"))
        }
        guard data[0] == DCEPMessageType.dataChannelOpen.rawValue else {
            throw .decode(.invalidFormat("Not a DCEP Open message"))
        }

        // RFC 8832 §5.1: unknown channel types must not be silently coerced —
        // accepting one as "reliable" would change delivery semantics
        guard let channelType = DCEPChannelType(rawValue: data[1]) else {
            throw .decode(.invalidFormat("Unknown DCEP channel type: \(data[1])"))
        }
        let priority = UInt16(data[2]) << 8 | UInt16(data[3])
        let reliability = UInt32(data[4]) << 24 | UInt32(data[5]) << 16 | UInt32(data[6]) << 8 | UInt32(data[7])
        let labelLen = Int(UInt16(data[8]) << 8 | UInt16(data[9]))
        let protoLen = Int(UInt16(data[10]) << 8 | UInt16(data[11]))

        guard data.count >= 12 + labelLen + protoLen else {
            throw .decode(.invalidFormat("DCEP Open data too short for label/protocol"))
        }

        // RFC 8832: Label and protocol MUST be valid UTF-8
        guard let label = validatedUTF8String(Array(data[12..<12 + labelLen])) else {
            throw .decode(.invalidFormat("Label is not valid UTF-8"))
        }
        guard let proto = validatedUTF8String(Array(data[12 + labelLen..<12 + labelLen + protoLen])) else {
            throw .decode(.invalidFormat("Protocol is not valid UTF-8"))
        }

        return DCEPOpen(
            channelType: channelType,
            priority: priority,
            reliabilityParameter: reliability,
            label: label,
            protocol_: proto
        )
    }
}

/// DCEP DATA_CHANNEL_ACK message.
public struct DCEPAck: Sendable {
    public init() {}

    public func encodeBytes() -> [UInt8] {
        [DCEPMessageType.dataChannelAck.rawValue]
    }

    public static func decode(from data: [UInt8]) throws(DataChannelWireError) -> DCEPAck {
        guard data.count >= 1, data[0] == DCEPMessageType.dataChannelAck.rawValue else {
            throw .decode(.invalidFormat("Not a DCEP Ack message"))
        }
        return DCEPAck()
    }
}
