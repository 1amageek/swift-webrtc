import NetworkingTime

/// RFC 3711 Section 4.3 AES-CM PRF with a fixed key-derivation rate of zero.
struct RFC3711KeyDeriver: Sendable {
    private let masterCipher: SRTPAES128CounterModeContext

    init(
        masterKey: [UInt8],
        crypto: SRTPCryptoContext
    ) throws(AESCounterModeError) {
        self.masterCipher = try crypto.makeAES128CounterMode(key: masterKey)
    }

    func derive(
        masterSalt: [UInt8],
        label: UInt8,
        outputByteCount: Int
    ) throws(AESCounterModeError) -> [UInt8] {
        guard outputByteCount >= 0 else {
            throw .invalidRange(
                lowerBound: 0,
                upperBound: outputByteCount,
                bufferCount: 0
            )
        }

        // With kdr=0, r is six zero octets. Right-aligned key_id is therefore
        // label at octet 7 followed by six zero octets. Appending two zero
        // octets implements the RFC's x * 2^16 AES-CM input.
        var initialCounter = [UInt8](repeating: 0, count: 16)
        for index in 0..<masterSalt.count {
            initialCounter[index] = masterSalt[index]
        }
        initialCounter[7] ^= label

        var output = [UInt8](repeating: 0, count: outputByteCount)
        try masterCipher.applyKeystream(
            to: &output,
            range: output.indices,
            initialCounter: initialCounter
        )
        return output
    }
}

struct SRTPDirectionalSessionKeys: Sendable {
    let rtpCipher: SRTPAES128CounterModeContext
    let rtpAuthenticationKey: [UInt8]
    let rtpSalt: [UInt8]
    let rtcpCipher: SRTPAES128CounterModeContext
    let rtcpAuthenticationKey: [UInt8]
    let rtcpSalt: [UInt8]
}

func deriveSessionKeys(
    from material: SRTPMasterKeyMaterial,
    crypto: SRTPCryptoContext
) throws(AESCounterModeError) -> SRTPDirectionalSessionKeys {
    let deriver = try RFC3711KeyDeriver(
        masterKey: material.masterKey,
        crypto: crypto
    )
    let rtpEncryptionKey = try deriver.derive(
        masterSalt: material.masterSalt,
        label: 0,
        outputByteCount: 16
    )
    let rtpAuthenticationKey = try deriver.derive(
        masterSalt: material.masterSalt,
        label: 1,
        outputByteCount: 20
    )
    let rtpSalt = try deriver.derive(
        masterSalt: material.masterSalt,
        label: 2,
        outputByteCount: 14
    )
    let rtcpEncryptionKey = try deriver.derive(
        masterSalt: material.masterSalt,
        label: 3,
        outputByteCount: 16
    )
    let rtcpAuthenticationKey = try deriver.derive(
        masterSalt: material.masterSalt,
        label: 4,
        outputByteCount: 20
    )
    let rtcpSalt = try deriver.derive(
        masterSalt: material.masterSalt,
        label: 5,
        outputByteCount: 14
    )

    return SRTPDirectionalSessionKeys(
        rtpCipher: try crypto.makeAES128CounterMode(key: rtpEncryptionKey),
        rtpAuthenticationKey: rtpAuthenticationKey,
        rtpSalt: rtpSalt,
        rtcpCipher: try crypto.makeAES128CounterMode(key: rtcpEncryptionKey),
        rtcpAuthenticationKey: rtcpAuthenticationKey,
        rtcpSalt: rtcpSalt
    )
}
