import NetworkingCore
import SSLCrypto

private final class WebRTCAES128CounterModeOwner: Sendable {
    private let primitive: AES128CounterMode

    init(key: Span<UInt8>) throws(AESCounterModeError) {
        do {
            primitive = try AES128CounterMode(key: key)
        } catch let error {
            throw Self.map(error)
        }
    }

    func applyKeystream(
        to bytes: inout [UInt8],
        range: Range<Int>,
        initialCounter: Span<UInt8>
    ) throws(AESCounterModeError) {
        do {
            try primitive.applyKeystream(
                to: &bytes,
                range: range,
                initialCounter: initialCounter
            )
        } catch let error {
            switch error {
            case .invalidLength(let expected, let actual):
                throw .invalidCounterLength(expected: expected, actual: actual)
            case .invalidRange:
                throw .invalidRange(
                    lowerBound: range.lowerBound,
                    upperBound: range.upperBound,
                    bufferCount: bytes.count
                )
            default:
                throw .primitiveFailure
            }
        }
    }

    private static func map(_ error: CryptoInputError) -> AESCounterModeError {
        switch error {
        case .invalidLength(let expected, let actual):
            return .invalidKeyLength(expected: expected, actual: actual)
        default:
            return .primitiveFailure
        }
    }
}

extension SRTPCryptoContext {
    /// Resolves the package-selected crypto backend once per media context.
    ///
    /// The returned closures strongly retain immutable keyed cipher owners.
    /// Packet and counter storage is borrowed only for each synchronous call;
    /// no pointer or array view escapes the operation.
    package static func webRTCDefault() -> SRTPCryptoContext {
        SRTPCryptoContext(
            hmacSHA1ByteCount: HMACSHA1.tagByteCount,
            makeAES128CounterMode: { @Sendable (
                key: [UInt8]
            ) throws(AESCounterModeError) -> SRTPAES128CounterModeContext in
                let cipher = try WebRTCAES128CounterModeOwner(key: key.span)
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
                var output = [UInt8](repeating: 0, count: HMACSHA1.tagByteCount)
                do {
                    var authenticator = try HMACSHA1.makeContext(
                        authenticatingWith: key.span
                    )
                    try authenticator.update(
                        message.span.extracting(authenticatedRange)
                    )
                    if let suffix {
                        try authenticator.update(suffix.span)
                    }
                    var destination = output.mutableSpan
                    try authenticator.finalize(into: &destination)
                } catch {
                    preconditionFailure(
                        "Validated SRTP HMAC input exceeded the primitive contract"
                    )
                }
                return output
            }
        )
    }
}
