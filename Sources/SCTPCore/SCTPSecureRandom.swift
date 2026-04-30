import Crypto
import Foundation

enum SCTPSecureRandom {
    static func data(count: Int) -> Data {
        guard count > 0 else {
            return Data()
        }

        let key = SymmetricKey(size: SymmetricKeySize(bitCount: count * 8))
        return key.withUnsafeBytes { bytes in
            Data(bytes)
        }
    }

    static func uint32() -> UInt32 {
        var value: UInt32 = 0
        let bytes = data(count: MemoryLayout<UInt32>.size)
        _ = withUnsafeMutableBytes(of: &value) { target in
            bytes.copyBytes(to: target)
        }
        return value
    }
}
