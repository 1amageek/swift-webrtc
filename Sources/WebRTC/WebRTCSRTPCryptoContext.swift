import P2PCoreBytes
import P2PCoreCrypto
import P2PCrypto

extension SRTPCryptoContext {
    /// Resolves the package-selected crypto backend once per media context.
    ///
    /// The returned closures strongly retain immutable keyed cipher owners.
    /// Packet and counter storage is borrowed only for each synchronous call;
    /// no pointer or array view escapes the operation.
    package static func webRTCDefault() -> SRTPCryptoContext {
        SRTPCryptoContext(
            hmacSHA1ByteCount: DefaultCryptoProvider.HMACSHA1.macLength,
            makeAES128CounterMode: { @Sendable (
                key: [UInt8]
            ) throws(AESCounterModeError) -> SRTPAES128CounterModeContext in
                let cipher = try DefaultCryptoProvider.makeAES128CounterMode(
                    key: key.span
                )
                return SRTPAES128CounterModeContext(
                    applyKeystream: { @Sendable (
                        bytes: inout [UInt8],
                        range: Range<Int>,
                        initialCounter: [UInt8]
                    ) throws(AESCounterModeError) in
                        try cipher.applyKeystream(
                            to: &bytes,
                            range: range,
                            initialCounter: initialCounter.span
                        )
                    }
                )
            },
            authenticateSHA1: { @Sendable (
                message: [UInt8],
                authenticatedRange: Range<Int>,
                suffix: [UInt8]?,
                key: [UInt8]
            ) -> [UInt8] in
                var authenticator = DefaultCryptoProvider.HMACSHA1(key: key.span)
                authenticator.update(message.span.extracting(authenticatedRange))
                if let suffix {
                    authenticator.update(suffix.span)
                }
                return authenticator.finalize()
            }
        )
    }
}
