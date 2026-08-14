/// `[UInt8]` STUN encode-with-integrity (RFC 5389 §15.4, §15.5) — Embedded-clean.
///
/// Builds the wire format in a single `[UInt8]` buffer: the header length field is
/// first written to cover MESSAGE-INTEGRITY for the HMAC input, then patched in
/// place to also cover FINGERPRINT for the CRC input. The HMAC routes through the
/// `MessageAuthenticationCode` seam backed by `SSLCrypto.HMACSHA1`, so the same
/// code signs identically on every build.
///
/// This is the Embedded-clean counterpart of the historical
/// `STUNMessage.encodeWithIntegrity(key: Data)` (host-only, in
/// `STUNMessageDataCompat`). Both are byte-identical on the wire.


extension STUNMessage {
    /// Encode with MESSAGE-INTEGRITY and FINGERPRINT over a `[UInt8]` key.
    /// - Parameter key: the HMAC-SHA1 key (ICE password as UTF-8 bytes).
    /// - Returns: the encoded message with integrity and fingerprint.
    func encodeWithIntegrityBytes(key: [UInt8]) -> [UInt8] {
        let attrData = STUNMessage.encodeAttributes(attributes)

        let integrityAttrSize = stunAttributeHeaderSize + 20 // HMAC-SHA1
        let fingerprintAttrSize = stunAttributeHeaderSize + 4 // CRC-32

        var data = [UInt8]()
        data.reserveCapacity(stunHeaderSize + attrData.count + integrityAttrSize + fingerprintAttrSize)

        // Header — length covers attributes + MESSAGE-INTEGRITY.
        let lengthWithIntegrity = UInt16(attrData.count + integrityAttrSize)
        data.append(UInt8(messageType.rawValue >> 8))
        data.append(UInt8(messageType.rawValue & 0xFF))
        data.append(UInt8(lengthWithIntegrity >> 8))
        data.append(UInt8(lengthWithIntegrity & 0xFF))
        data.append(UInt8(stunMagicCookie >> 24))
        data.append(UInt8((stunMagicCookie >> 16) & 0xFF))
        data.append(UInt8((stunMagicCookie >> 8) & 0xFF))
        data.append(UInt8(stunMagicCookie & 0xFF))
        data.append(contentsOf: transactionID.byteValues)
        data.append(contentsOf: attrData)

        // MESSAGE-INTEGRITY over the buffer so far (20 bytes, already aligned).
        let hmac = MessageIntegrity.computeBytes(data: data, key: key)
        data.append(UInt8(STUNAttributeType.messageIntegrity.rawValue >> 8))
        data.append(UInt8(STUNAttributeType.messageIntegrity.rawValue & 0xFF))
        data.append(0)
        data.append(20)
        data.append(contentsOf: hmac)

        // Patch the length in place to also cover FINGERPRINT.
        let lengthWithFingerprint = UInt16(attrData.count + integrityAttrSize + fingerprintAttrSize)
        data[2] = UInt8(lengthWithFingerprint >> 8)
        data[3] = UInt8(lengthWithFingerprint & 0xFF)

        // FINGERPRINT over the buffer so far (4 bytes, aligned).
        let fp = STUNFingerprint.compute(data: data)
        data.append(UInt8(STUNAttributeType.fingerprint.rawValue >> 8))
        data.append(UInt8(STUNAttributeType.fingerprint.rawValue & 0xFF))
        data.append(0)
        data.append(4)
        data.append(contentsOf: fp)

        return data
    }
}
