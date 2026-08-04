/// Owned DTLS-SRTP master keying material for one packet direction.
///
/// AES_CM_128_HMAC_SHA1_80 uses a 16-byte master key and a 14-byte master
/// salt. The bytes are copied only by normal Swift value semantics at this
/// small, fixed-size key boundary; media packet bytes are never materialized.
struct SRTPMasterKeyMaterial: Sendable {
    static let masterKeyByteCount = 16
    static let masterSaltByteCount = 14

    let masterKey: [UInt8]
    let masterSalt: [UInt8]

    init(
        masterKey: [UInt8],
        masterSalt: [UInt8]
    ) throws(SRTPError) {
        guard masterKey.count == Self.masterKeyByteCount else {
            throw .invalidMasterKeyLength(
                expected: Self.masterKeyByteCount,
                actual: masterKey.count
            )
        }
        guard masterSalt.count == Self.masterSaltByteCount else {
            throw .invalidMasterSaltLength(
                expected: Self.masterSaltByteCount,
                actual: masterSalt.count
            )
        }
        self.masterKey = masterKey
        self.masterSalt = masterSalt
    }
}
