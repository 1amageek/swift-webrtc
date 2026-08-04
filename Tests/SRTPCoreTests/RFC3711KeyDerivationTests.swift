import P2PCoreCrypto
import P2PCrypto
import Testing
@testable import WebRTC
@Suite("RFC 3711 key derivation")
struct RFC3711KeyDerivationTests {
    @Test("Appendix B.3 derives the cipher key, salt, and full PRF output")
    func appendixB3() throws {
        let masterKey = try fixtureBytes("E1F97A0D3E018BE0D64FA32C06DE4139")
        let masterSalt = try fixtureBytes("0EC675AD498AFEEBB6960B3AABE6")
        let deriver = try RFC3711KeyDeriver(
            masterKey: masterKey,
            crypto: defaultSRTPCryptoContext()
        )

        let encryptionKey = try deriver.derive(
            masterSalt: masterSalt,
            label: 0,
            outputByteCount: 16
        )
        let salt = try deriver.derive(
            masterSalt: masterSalt,
            label: 2,
            outputByteCount: 14
        )
        let authenticationKey = try deriver.derive(
            masterSalt: masterSalt,
            label: 1,
            outputByteCount: 94
        )

        #expect(try encryptionKey == fixtureBytes("C61E7A93744F39EE10734AFE3FF7A087"))
        #expect(try salt == fixtureBytes("30CBBC08863D8C85D49DB34A9AE1"))
        #expect(try authenticationKey == fixtureBytes(
            "CEBE321F6FF7716B6FD4AB49AF256A15"
                + "6D38BAA48F0A0ACF3C34E2359E6CDBCE"
                + "E049646C43D9327AD175578EF7227098"
                + "6371C10C9A369AC2F94A8C5FBCDDDC25"
                + "6D6E919A48B610EF17C2041E47403576"
                + "6B68642C59BBFC2F34DB60DBDFB2"
        ))
    }

    @Test("Appendix B.2 AES-CM counter sequence matches the first blocks")
    func appendixB2() throws {
        let key = try fixtureBytes("2B7E151628AED2A6ABF7158809CF4F3C")
        let counter = try fixtureBytes("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000")
        let cipher = try DefaultCryptoProvider.makeAES128CounterMode(key: key.span)
        var output = [UInt8](repeating: 0, count: 48)

        try cipher.applyKeystream(
            to: &output,
            range: output.indices,
            initialCounter: counter.span
        )

        #expect(try output == fixtureBytes(
            "E03EAD0935C95E80E166B16DD92B4EB4"
                + "D23513162B02D0F72A43A2FE4A5F97AB"
                + "41E95B3BB0A2E8DD477901E4FCA894C0"
        ))
    }
}
