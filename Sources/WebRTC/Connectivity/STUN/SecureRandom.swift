/// CSPRNG for STUN/ICE material (transaction IDs, ufrag/password generation)
/// routed through the Embedded-clean `RandomSource` seam.
///
/// The same `DefaultRandom` backend is used on Native, WASI, and Embedded.
/// This keeps the file Embedded-clean and the randomness contract identical
/// across targets.

import P2PCoreCrypto
import P2PCrypto

enum SecureRandom {
    private static let source = DefaultRandom()

    /// Returns `count` fresh random bytes.
    static func bytes(count: Int) -> [UInt8] {
        guard count > 0 else { return [] }
        return source.randomBytes(count)
    }

    static func byte() -> UInt8 {
        bytes(count: 1)[0]
    }
}

#if !hasFeature(Embedded) && !os(WASI)
import Foundation

extension SecureRandom {
    /// `count` fresh random bytes as `Data`. Host-only convenience kept for the
    /// historical `Data`-based STUN surface and the test suite.
    static func data(count: Int) -> Data {
        Data(bytes(count: count))
    }
}
#endif
