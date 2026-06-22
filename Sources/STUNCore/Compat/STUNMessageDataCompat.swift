/// `Data`-based convenience surface for the moved `STUNMessage` type, plus the
/// crypto-bearing `encodeWithIntegrity` which must stay Foundation/Crypto side.

import Foundation
import STUNWireCore

extension STUNMessage {
    // MARK: - Defaulted convenience inits (random transaction ID)

    /// Creates a STUN message with a random transaction ID by default.
    public init(
        messageType: STUNMessageType,
        attributes: [STUNAttribute] = []
    ) {
        self.init(
            messageType: messageType,
            transactionID: .random(),
            attributes: attributes
        )
    }

    // MARK: - Binding Request (random transaction ID)

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
            transactionID: .random(),
            attributes: attrs
        )
    }

    /// Create a Binding Success Response from a `Data` address.
    public static func bindingSuccessResponse(
        transactionID: TransactionID,
        address: Data,
        port: UInt16
    ) -> STUNMessage {
        bindingSuccessResponse(
            transactionID: transactionID,
            address: [UInt8](address),
            port: port
        )
    }

    // MARK: - Data encoding

    /// Encode the STUN message to wire format as `Data`.
    public func encode() -> Data {
        Data(encodeBytes())
    }

    /// Check if these `Data` bytes are a STUN message.
    public static func isSTUN(_ data: Data) -> Bool {
        // Index relative to startIndex: the caller may pass a Data slice
        // (non-zero startIndex). Normalize to a zero-based array.
        isSTUN([UInt8](data))
    }

    /// Decode a STUN message from `Data` wire format.
    public static func decode(from input: Data) throws -> STUNMessage {
        // `[UInt8](input)` is always zero-based, so a Data slice with a non-zero
        // startIndex is normalized here (matching the historical behaviour).
        do {
            return try decode(from: [UInt8](input))
        } catch {
            try error.rethrowUnwrapped()
        }
    }

    // MARK: - Encode with MESSAGE-INTEGRITY and FINGERPRINT (crypto, adapter-side)

    /// Encode with MESSAGE-INTEGRITY and FINGERPRINT.
    /// - Parameter key: The HMAC-SHA1 key (ICE password)
    /// - Returns: Encoded message with integrity and fingerprint
    ///
    /// Builds the wire format in a single buffer: the header length field is
    /// first written to cover MESSAGE-INTEGRITY for the HMAC input, then
    /// patched in place to also cover FINGERPRINT for the CRC input
    /// (RFC 5389 §15.4, §15.5).
    public func encodeWithIntegrity(key: Data) -> Data {
        let attrData = Data(STUNMessage.encodeAttributes(attributes))

        let integrityAttrSize = stunAttributeHeaderSize + 20 // HMAC-SHA1
        let fingerprintAttrSize = stunAttributeHeaderSize + 4 // CRC-32

        var data = Data(capacity: stunHeaderSize + attrData.count + integrityAttrSize + fingerprintAttrSize)

        // Header — length covers attributes + MESSAGE-INTEGRITY
        let lengthWithIntegrity = UInt16(attrData.count + integrityAttrSize)
        data.append(UInt8(messageType.rawValue >> 8))
        data.append(UInt8(messageType.rawValue & 0xFF))
        data.append(UInt8(lengthWithIntegrity >> 8))
        data.append(UInt8(lengthWithIntegrity & 0xFF))
        data.append(UInt8(stunMagicCookie >> 24))
        data.append(UInt8((stunMagicCookie >> 16) & 0xFF))
        data.append(UInt8((stunMagicCookie >> 8) & 0xFF))
        data.append(UInt8(stunMagicCookie & 0xFF))
        data.append(transactionID.bytes)
        data.append(attrData)

        // MESSAGE-INTEGRITY over the buffer so far (value is 20 bytes,
        // already 4-byte aligned — no padding needed)
        let hmac = MessageIntegrity.compute(data: data, key: key)
        data.append(UInt8(STUNAttributeType.messageIntegrity.rawValue >> 8))
        data.append(UInt8(STUNAttributeType.messageIntegrity.rawValue & 0xFF))
        data.append(0)
        data.append(20)
        data.append(hmac)

        // Patch the length in place to also cover FINGERPRINT
        let lengthWithFingerprint = UInt16(attrData.count + integrityAttrSize + fingerprintAttrSize)
        data[2] = UInt8(lengthWithFingerprint >> 8)
        data[3] = UInt8(lengthWithFingerprint & 0xFF)

        // FINGERPRINT over the buffer so far (value is 4 bytes, aligned)
        let fp = STUNFingerprint.compute(data: data)
        data.append(UInt8(STUNAttributeType.fingerprint.rawValue >> 8))
        data.append(UInt8(STUNAttributeType.fingerprint.rawValue & 0xFF))
        data.append(0)
        data.append(4)
        data.append(fp)

        return data
    }
}

// MARK: - STUNFingerprint (Data surface)

extension STUNFingerprint {
    /// Compute FINGERPRINT value over `Data`.
    public static func compute(data: Data) -> Data {
        Data(compute(data: [UInt8](data)))
    }

    /// Verify FINGERPRINT in a `Data` STUN message.
    public static func verify(message input: Data) -> Bool {
        // Normalize a possible Data slice to a zero-based array.
        verify(message: [UInt8](input))
    }
}
