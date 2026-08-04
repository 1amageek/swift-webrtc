import P2PCoreCrypto

/// Immutable owner of one keyed AES-128 counter-mode operation.
///
/// A crypto adapter captures its concrete cipher in `applyKeystreamOperation`.
/// The capture keeps that cipher alive exactly as long as this owner. Each call
/// borrows the caller's packet owner and counter synchronously; neither value
/// may be retained after the operation returns. The operation must transform
/// only `range` and must preserve the typed `AESCounterModeError` contract.
final class SRTPAES128CounterModeContext: Sendable {
    typealias ApplyKeystreamOperation = @Sendable (
        _ bytes: inout [UInt8],
        _ range: Range<Int>,
        _ initialCounter: [UInt8]
    ) throws(AESCounterModeError) -> Void

    private let applyKeystreamOperation: ApplyKeystreamOperation

    init(
        applyKeystream: @escaping ApplyKeystreamOperation
    ) {
        self.applyKeystreamOperation = applyKeystream
    }

    package func applyKeystream(
        to bytes: inout [UInt8],
        range: Range<Int>,
        initialCounter: [UInt8]
    ) throws(AESCounterModeError) {
        try applyKeystreamOperation(&bytes, range, initialCounter)
    }
}
