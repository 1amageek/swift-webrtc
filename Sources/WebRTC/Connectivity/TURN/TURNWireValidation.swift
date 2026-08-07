enum TURNWireValidation: Sendable {
    struct Challenge: Sendable, Equatable {
        let realm: String
        let nonce: String
    }

    static func decodeExact(
        _ bytes: [UInt8],
        transactionID: TransactionID? = nil
    ) throws(TURNError) -> STUNMessage {
        guard bytes.count >= stunHeaderSize else { throw .malformedMessage }
        let declaredLength = Int(UInt16(bytes[2]) << 8 | UInt16(bytes[3]))
        guard declaredLength.isMultiple(of: 4),
              bytes.count == stunHeaderSize + declaredLength else {
            throw .malformedMessage
        }
        let message: STUNMessage
        do {
            message = try STUNMessage.decode(from: bytes)
        } catch {
            throw .malformedMessage
        }
        if let transactionID, message.transactionID != transactionID {
            throw .transactionMismatch
        }
        if message.attribute(ofType: .fingerprint) != nil,
           !STUNFingerprint.verify(message: bytes) {
            throw .malformedMessage
        }
        return message
    }

    static func singleAttribute(
        _ type: STUNAttributeType,
        in message: STUNMessage
    ) throws(TURNError) -> STUNAttribute? {
        var match: STUNAttribute?
        for attribute in message.attributes where attribute.type == type.rawValue {
            guard match == nil else { throw .duplicateAttribute(type.rawValue) }
            match = attribute
        }
        return match
    }

    static func requiredString(
        _ type: STUNAttributeType,
        in message: STUNMessage
    ) throws(TURNError) -> String {
        guard let attribute = try singleAttribute(type, in: message),
              !attribute.value.isEmpty else {
            throw .missingAuthenticationChallenge
        }
        let value = String(decoding: attribute.value, as: UTF8.self)
        guard Array(value.utf8) == attribute.value else {
            throw .malformedMessage
        }
        return value
    }

    static func challenge(in message: STUNMessage) throws(TURNError) -> Challenge {
        try Challenge(
            realm: requiredString(.realm, in: message),
            nonce: requiredString(.nonce, in: message)
        )
    }

    static func error(
        in message: STUNMessage
    ) throws(TURNError) -> (code: UInt16, reason: String) {
        guard let attribute = try singleAttribute(.errorCode, in: message),
              attribute.value.count >= 4,
              attribute.value[2] <= 6,
              attribute.value[3] <= 99 else {
            throw .malformedMessage
        }
        let code = UInt16(attribute.value[2]) * 100
            + UInt16(attribute.value[3])
        let reason = String(
            decoding: attribute.value.dropFirst(4),
            as: UTF8.self
        )
        return (code, reason)
    }

    static func requireIntegrity(
        in bytes: [UInt8],
        context: TURNAuthenticationContext
    ) throws(TURNError) {
        guard MessageIntegrity.verifyWithResultBytes(
            message: bytes,
            key: context.integrityKey
        ) == .valid else {
            throw .authenticationFailed
        }
    }

    static func uint32(
        _ type: STUNAttributeType,
        in message: STUNMessage
    ) throws(TURNError) -> UInt32? {
        guard let attribute = try singleAttribute(type, in: message) else {
            return nil
        }
        guard attribute.value.count == 4 else { throw .malformedMessage }
        return UInt32(attribute.value[0]) << 24
            | UInt32(attribute.value[1]) << 16
            | UInt32(attribute.value[2]) << 8
            | UInt32(attribute.value[3])
    }

    static func uint32Attribute(
        type: STUNAttributeType,
        value: UInt32
    ) -> STUNAttribute {
        STUNAttribute(type: type.rawValue, value: [
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value),
        ])
    }
}
