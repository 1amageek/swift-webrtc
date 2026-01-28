/// STUN Attributes (RFC 5389)
///
/// Each STUN attribute is TLV: Type (2 bytes) + Length (2 bytes) + Value (variable)
/// Attributes are padded to 4-byte boundaries.

import Foundation

/// A STUN message attribute
public struct STUNAttribute: Sendable, Equatable {
    /// Attribute type
    public let type: UInt16

    /// Attribute value
    public let value: Data

    public init(type: UInt16, value: Data) {
        self.type = type
        self.value = value
    }

    /// Create a XOR-MAPPED-ADDRESS attribute
    /// - Parameters:
    ///   - address: IPv4 address (4 bytes) or IPv6 address (16 bytes)
    ///   - port: Port number
    ///   - transactionID: The STUN transaction ID for XOR
    /// - Returns: XOR-MAPPED-ADDRESS attribute
    public static func xorMappedAddress(
        address: Data,
        port: UInt16,
        transactionID: TransactionID
    ) -> STUNAttribute {
        let family: UInt8 = address.count == 4 ? 0x01 : 0x02
        let xPort = port ^ UInt16(stunMagicCookie >> 16)

        var value = Data()
        value.append(0x00) // reserved
        value.append(family)
        value.append(UInt8(xPort >> 8))
        value.append(UInt8(xPort & 0xFF))

        if address.count == 4 {
            // IPv4: XOR with magic cookie
            let magicBytes = withUnsafeBytes(of: stunMagicCookie.bigEndian) { Data($0) }
            for i in 0..<4 {
                value.append(address[i] ^ magicBytes[i])
            }
        } else {
            // IPv6: XOR with magic cookie + transaction ID
            var xorKey = Data()
            xorKey.append(contentsOf: withUnsafeBytes(of: stunMagicCookie.bigEndian) { Data($0) })
            xorKey.append(transactionID.bytes)
            for i in 0..<16 {
                value.append(address[i] ^ xorKey[i])
            }
        }

        return STUNAttribute(type: STUNAttributeType.xorMappedAddress.rawValue, value: value)
    }

    /// Parse a XOR-MAPPED-ADDRESS attribute
    /// - Parameter transactionID: The transaction ID for XOR
    /// - Returns: (address, port) or nil if invalid
    public func parseXorMappedAddress(transactionID: TransactionID) -> (address: Data, port: UInt16)? {
        guard type == STUNAttributeType.xorMappedAddress.rawValue,
              value.count >= 4 else {
            return nil
        }

        let family = value[1]
        let xPort = UInt16(value[2]) << 8 | UInt16(value[3])
        let port = xPort ^ UInt16(stunMagicCookie >> 16)

        if family == 0x01, value.count >= 8 {
            // IPv4
            let magicBytes = withUnsafeBytes(of: stunMagicCookie.bigEndian) { Data($0) }
            var address = Data(count: 4)
            for i in 0..<4 {
                address[i] = value[4 + i] ^ magicBytes[i]
            }
            return (address, port)
        } else if family == 0x02, value.count >= 20 {
            // IPv6
            var xorKey = Data()
            xorKey.append(contentsOf: withUnsafeBytes(of: stunMagicCookie.bigEndian) { Data($0) })
            xorKey.append(transactionID.bytes)
            var address = Data(count: 16)
            for i in 0..<16 {
                address[i] = value[4 + i] ^ xorKey[i]
            }
            return (address, port)
        }

        return nil
    }

    /// Create a USERNAME attribute
    public static func username(_ value: String) -> STUNAttribute {
        STUNAttribute(type: STUNAttributeType.username.rawValue, value: Data(value.utf8))
    }

    /// Create a PRIORITY attribute (ICE)
    public static func priority(_ value: UInt32) -> STUNAttribute {
        var data = Data(count: 4)
        data[0] = UInt8(value >> 24)
        data[1] = UInt8((value >> 16) & 0xFF)
        data[2] = UInt8((value >> 8) & 0xFF)
        data[3] = UInt8(value & 0xFF)
        return STUNAttribute(type: STUNAttributeType.priority.rawValue, value: data)
    }

    /// Create a USE-CANDIDATE attribute (ICE, empty value)
    public static func useCandidate() -> STUNAttribute {
        STUNAttribute(type: STUNAttributeType.useCandidate.rawValue, value: Data())
    }

    /// Create an ICE-CONTROLLING attribute
    public static func iceControlling(tiebreaker: UInt64) -> STUNAttribute {
        var data = Data(count: 8)
        for i in 0..<8 {
            data[i] = UInt8((tiebreaker >> (56 - i * 8)) & 0xFF)
        }
        return STUNAttribute(type: STUNAttributeType.iceControlling.rawValue, value: data)
    }

    /// Create an ICE-CONTROLLED attribute
    public static func iceControlled(tiebreaker: UInt64) -> STUNAttribute {
        var data = Data(count: 8)
        for i in 0..<8 {
            data[i] = UInt8((tiebreaker >> (56 - i * 8)) & 0xFF)
        }
        return STUNAttribute(type: STUNAttributeType.iceControlled.rawValue, value: data)
    }

    /// Create an ERROR-CODE attribute
    public static func errorCode(_ code: UInt16, reason: String) -> STUNAttribute {
        let errorClass = UInt8(code / 100)
        let errorNumber = UInt8(code % 100)
        var data = Data()
        data.append(0x00) // reserved
        data.append(0x00) // reserved
        data.append(errorClass)
        data.append(errorNumber)
        data.append(contentsOf: reason.utf8)
        return STUNAttribute(type: STUNAttributeType.errorCode.rawValue, value: data)
    }

    /// Padded length (value length rounded up to 4-byte boundary)
    public var paddedLength: Int {
        let len = value.count
        return (len + 3) & ~3
    }
}
