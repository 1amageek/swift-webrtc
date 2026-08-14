/// CSPRNG for SCTP handshake material (initiate tags, initial TSN, cookie
/// secret) routed through the Embedded-clean `RandomSource` seam.
///
/// The same `SystemRandom` backend is used on Native, WASI, and Embedded.
/// The seam keeps this file Embedded-clean and prevents platform-specific
/// weakening of the randomness contract.

import SSLCrypto
import NetworkingCore

enum SCTPSecureRandom {
    /// The concrete CSPRNG for this build.
    /// Returns `count` fresh random bytes.
    static func bytes(count: Int) -> [UInt8] {
        guard count > 0 else { return [] }
        var bytes = [UInt8](repeating: 0, count: count)
        do {
            var destination = bytes.mutableSpan
            try SystemRandom.fill(&destination)
        } catch {
            preconditionFailure("Secure random generation failed: \(error)")
        }
        return bytes
    }

    static func uint32() -> UInt32 {
        let b = bytes(count: 4)
        return UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
    }

    /// Random UInt32 guaranteed to be non-zero.
    ///
    /// RFC 4960 §3.3.2: the Initiate Tag must not be 0.
    static func uint32NonZero() -> UInt32 {
        while true {
            let value = uint32()
            if value != 0 {
                return value
            }
        }
    }
}

#if !hasFeature(Embedded) && !os(WASI)
import Foundation

extension SCTPSecureRandom {
    /// `count` fresh random bytes as `Data`. Host-only convenience kept for the
    /// historical `Data`-based cookie surface and the benchmark suite.
    static func data(count: Int) -> Data {
        Data(bytes(count: count))
    }
}
#endif
