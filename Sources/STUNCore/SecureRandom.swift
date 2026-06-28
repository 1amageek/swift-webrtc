/// CSPRNG for STUN/ICE material (transaction IDs, ufrag/password generation)
/// routed through the Embedded-clean `RandomSource` seam.
///
/// The concrete backend is selected at the host boundary: swift-crypto-backed
/// `FoundationEssentialsRandom` on host, BoringSSL `BoringRandom` under Embedded. This keeps
/// the file Embedded-clean (no Foundation, no `any`); only the concrete
/// `RandomSource` instantiated differs between builds.

import P2PCoreCrypto
import P2PCrypto

public enum SecureRandom {
    #if !hasFeature(Embedded)
    private static let source: any RandomSource = FoundationEssentialsRandom()
    #else
    private static let source = BoringRandom()
    #endif

    /// Returns `count` fresh random bytes.
    public static func bytes(count: Int) -> [UInt8] {
        guard count > 0 else { return [] }
        return source.randomBytes(count)
    }

    public static func byte() -> UInt8 {
        bytes(count: 1)[0]
    }
}

#if !hasFeature(Embedded)
import Foundation

extension SecureRandom {
    /// `count` fresh random bytes as `Data`. Host-only convenience kept for the
    /// historical `Data`-based STUN surface and the test suite.
    public static func data(count: Int) -> Data {
        Data(bytes(count: count))
    }
}
#endif
