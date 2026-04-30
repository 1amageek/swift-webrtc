import Crypto
import Foundation

public enum SecureRandom {
    public static func data(count: Int) -> Data {
        guard count > 0 else {
            return Data()
        }

        let key = SymmetricKey(size: SymmetricKeySize(bitCount: count * 8))
        return key.withUnsafeBytes { bytes in
            Data(bytes)
        }
    }

    public static func byte() -> UInt8 {
        data(count: 1)[0]
    }
}
