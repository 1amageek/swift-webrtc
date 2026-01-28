/// STUN Message (RFC 5389)
///
/// STUN header format (20 bytes):
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |0 0|     STUN Message Type     |         Message Length        |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                         Magic Cookie                         |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                                                               |
///  |                     Transaction ID (96 bits)                  |
///  |                                                               |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

import Foundation

/// STUN message type (method + class encoded in 14 bits)
public struct STUNMessageType: Sendable, Equatable, Hashable {
    public let rawValue: UInt16

    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    /// Create from method and class
    public init(method: STUNMethod, class: STUNClass) {
        // RFC 5389 encoding: M11..M0 combined with C1C0
        // Bits: M11 M10 M9 M8 M7 C1 M6 M5 M4 C0 M3 M2 M1 M0
        let m = method.rawValue
        let c = `class`.rawValue

        let m0_3 = m & 0x000F
        let m4_6 = (m & 0x0070) << 1
        let m7_11 = (m & 0x0F80) << 2

        let c0 = (c & 0x0010)       // C0 at bit 4
        let c1 = (c & 0x0100)       // C1 at bit 8

        rawValue = m0_3 | c0 | m4_6 | c1 | m7_11
    }

    /// Extract the method
    public var method: STUNMethod? {
        let m0_3 = rawValue & 0x000F
        let m4_6 = (rawValue & 0x00E0) >> 1
        let m7_11 = (rawValue & 0x3E00) >> 2
        return STUNMethod(rawValue: m0_3 | m4_6 | m7_11)
    }

    /// Extract the class
    public var messageClass: STUNClass? {
        let c0 = rawValue & 0x0010
        let c1 = rawValue & 0x0100
        return STUNClass(rawValue: c0 | c1)
    }

    // Common message types
    public static let bindingRequest = STUNMessageType(method: .binding, class: .request)
    public static let bindingSuccessResponse = STUNMessageType(method: .binding, class: .successResponse)
    public static let bindingErrorResponse = STUNMessageType(method: .binding, class: .errorResponse)
    public static let bindingIndication = STUNMessageType(method: .binding, class: .indication)
}

/// A STUN message
public struct STUNMessage: Sendable {
    /// Message type
    public let messageType: STUNMessageType

    /// Transaction ID
    public let transactionID: TransactionID

    /// Attributes
    public var attributes: [STUNAttribute]

    public init(
        messageType: STUNMessageType,
        transactionID: TransactionID = .random(),
        attributes: [STUNAttribute] = []
    ) {
        self.messageType = messageType
        self.transactionID = transactionID
        self.attributes = attributes
    }

    /// Create a Binding Request
    public static func bindingRequest(
        username: String? = nil,
        priority: UInt32? = nil,
        useCandidate: Bool = false,
        iceControlling: UInt64? = nil,
        iceControlled: UInt64? = nil
    ) -> STUNMessage {
        var attrs: [STUNAttribute] = []

        if let username {
            attrs.append(.username(username))
        }
        if let priority {
            attrs.append(.priority(priority))
        }
        if useCandidate {
            attrs.append(.useCandidate())
        }
        if let tiebreaker = iceControlling {
            attrs.append(.iceControlling(tiebreaker: tiebreaker))
        }
        if let tiebreaker = iceControlled {
            attrs.append(.iceControlled(tiebreaker: tiebreaker))
        }

        return STUNMessage(
            messageType: .bindingRequest,
            attributes: attrs
        )
    }

    /// Create a Binding Success Response
    public static func bindingSuccessResponse(
        transactionID: TransactionID,
        address: Data,
        port: UInt16
    ) -> STUNMessage {
        STUNMessage(
            messageType: .bindingSuccessResponse,
            transactionID: transactionID,
            attributes: [.xorMappedAddress(address: address, port: port, transactionID: transactionID)]
        )
    }

    /// Create a Binding Error Response
    public static func bindingErrorResponse(
        transactionID: TransactionID,
        errorCode: UInt16,
        reason: String
    ) -> STUNMessage {
        STUNMessage(
            messageType: .bindingErrorResponse,
            transactionID: transactionID,
            attributes: [.errorCode(errorCode, reason: reason)]
        )
    }

    /// Find the first attribute with the given type
    public func attribute(ofType type: STUNAttributeType) -> STUNAttribute? {
        attributes.first { $0.type == type.rawValue }
    }

    /// Check if this is a STUN message (first two bits are 0)
    public static func isSTUN(_ data: Data) -> Bool {
        guard data.count >= stunHeaderSize else { return false }
        return data[0] & 0xC0 == 0
    }

    // MARK: - Encoding

    /// Encode the STUN message to wire format (without MESSAGE-INTEGRITY or FINGERPRINT)
    public func encode() -> Data {
        let attrData = encodeAttributes()

        var data = Data(capacity: stunHeaderSize + attrData.count)

        // Message type (2 bytes)
        data.append(UInt8(messageType.rawValue >> 8))
        data.append(UInt8(messageType.rawValue & 0xFF))

        // Message length (2 bytes, excluding header)
        let length = UInt16(attrData.count)
        data.append(UInt8(length >> 8))
        data.append(UInt8(length & 0xFF))

        // Magic cookie (4 bytes)
        data.append(UInt8(stunMagicCookie >> 24))
        data.append(UInt8((stunMagicCookie >> 16) & 0xFF))
        data.append(UInt8((stunMagicCookie >> 8) & 0xFF))
        data.append(UInt8(stunMagicCookie & 0xFF))

        // Transaction ID (12 bytes)
        data.append(transactionID.bytes)

        // Attributes
        data.append(attrData)

        return data
    }

    /// Encode with MESSAGE-INTEGRITY and FINGERPRINT
    /// - Parameter key: The HMAC-SHA1 key (ICE password)
    /// - Returns: Encoded message with integrity and fingerprint
    public func encodeWithIntegrity(key: Data) -> Data {
        var msg = self
        let attrDataWithoutIntegrity = encodeAttributes()

        // Build header with length including MESSAGE-INTEGRITY (24 bytes)
        let lengthWithIntegrity = UInt16(attrDataWithoutIntegrity.count + stunAttributeHeaderSize + 20)
        var preIntegrity = Data(capacity: stunHeaderSize + attrDataWithoutIntegrity.count)

        preIntegrity.append(UInt8(messageType.rawValue >> 8))
        preIntegrity.append(UInt8(messageType.rawValue & 0xFF))
        preIntegrity.append(UInt8(lengthWithIntegrity >> 8))
        preIntegrity.append(UInt8(lengthWithIntegrity & 0xFF))
        preIntegrity.append(UInt8(stunMagicCookie >> 24))
        preIntegrity.append(UInt8((stunMagicCookie >> 16) & 0xFF))
        preIntegrity.append(UInt8((stunMagicCookie >> 8) & 0xFF))
        preIntegrity.append(UInt8(stunMagicCookie & 0xFF))
        preIntegrity.append(transactionID.bytes)
        preIntegrity.append(attrDataWithoutIntegrity)

        let hmac = MessageIntegrity.compute(data: preIntegrity, key: key)
        msg.attributes.append(STUNAttribute(
            type: STUNAttributeType.messageIntegrity.rawValue,
            value: hmac
        ))

        // Now encode with FINGERPRINT
        let attrDataWithIntegrity = msg.encodeAttributes()
        let lengthWithFingerprint = UInt16(attrDataWithIntegrity.count + stunAttributeHeaderSize + 4)

        var preFingerprint = Data(capacity: stunHeaderSize + attrDataWithIntegrity.count)
        preFingerprint.append(UInt8(messageType.rawValue >> 8))
        preFingerprint.append(UInt8(messageType.rawValue & 0xFF))
        preFingerprint.append(UInt8(lengthWithFingerprint >> 8))
        preFingerprint.append(UInt8(lengthWithFingerprint & 0xFF))
        preFingerprint.append(UInt8(stunMagicCookie >> 24))
        preFingerprint.append(UInt8((stunMagicCookie >> 16) & 0xFF))
        preFingerprint.append(UInt8((stunMagicCookie >> 8) & 0xFF))
        preFingerprint.append(UInt8(stunMagicCookie & 0xFF))
        preFingerprint.append(transactionID.bytes)
        preFingerprint.append(attrDataWithIntegrity)

        let fp = STUNFingerprint.compute(data: preFingerprint)
        msg.attributes.append(STUNAttribute(
            type: STUNAttributeType.fingerprint.rawValue,
            value: fp
        ))

        return msg.encode()
    }

    private func encodeAttributes() -> Data {
        var data = Data()
        for attr in attributes {
            // Type (2 bytes)
            data.append(UInt8(attr.type >> 8))
            data.append(UInt8(attr.type & 0xFF))

            // Length (2 bytes, actual value length without padding)
            let length = UInt16(attr.value.count)
            data.append(UInt8(length >> 8))
            data.append(UInt8(length & 0xFF))

            // Value
            data.append(attr.value)

            // Padding to 4-byte boundary
            let padding = (4 - (attr.value.count % 4)) % 4
            if padding > 0 {
                data.append(Data(repeating: 0, count: padding))
            }
        }
        return data
    }

    // MARK: - Decoding

    /// Decode a STUN message from wire format
    public static func decode(from data: Data) throws -> STUNMessage {
        guard data.count >= stunHeaderSize else {
            throw STUNError.insufficientData(expected: stunHeaderSize, actual: data.count)
        }

        // First two bits must be 0
        guard data[0] & 0xC0 == 0 else {
            throw STUNError.invalidFormat("First two bits must be 0")
        }

        let messageType = UInt16(data[0]) << 8 | UInt16(data[1])
        let messageLength = Int(UInt16(data[2]) << 8 | UInt16(data[3]))
        let magicCookie = UInt32(data[4]) << 24 | UInt32(data[5]) << 16 | UInt32(data[6]) << 8 | UInt32(data[7])

        guard magicCookie == stunMagicCookie else {
            throw STUNError.invalidMagicCookie(magicCookie)
        }

        guard data.count >= stunHeaderSize + messageLength else {
            throw STUNError.insufficientData(expected: stunHeaderSize + messageLength, actual: data.count)
        }

        let transactionID = TransactionID(bytes: Data(data[8..<20]))

        // Parse attributes
        var attributes: [STUNAttribute] = []
        var offset = stunHeaderSize
        let end = stunHeaderSize + messageLength

        while offset + stunAttributeHeaderSize <= end {
            let attrType = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
            let attrLength = Int(UInt16(data[offset + 2]) << 8 | UInt16(data[offset + 3]))
            offset += stunAttributeHeaderSize

            guard offset + attrLength <= end else {
                throw STUNError.invalidFormat("Attribute extends beyond message")
            }

            let attrValue = Data(data[offset..<offset + attrLength])
            attributes.append(STUNAttribute(type: attrType, value: attrValue))

            // Skip padding
            let paddedLength = (attrLength + 3) & ~3
            offset += paddedLength
        }

        return STUNMessage(
            messageType: STUNMessageType(rawValue: messageType),
            transactionID: transactionID,
            attributes: attributes
        )
    }
}

/// STUN errors
public enum STUNError: Error, Sendable {
    case insufficientData(expected: Int, actual: Int)
    case invalidFormat(String)
    case invalidMagicCookie(UInt32)
    case integrityCheckFailed
    case fingerprintCheckFailed
}
