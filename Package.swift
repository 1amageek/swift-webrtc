// swift-tools-version: 6.2
import PackageDescription

// Embedded toggle controls the experimental Embedded feature + WMO for the
// Embedded-clean cores. Lifetimes is enabled in BOTH modes because Span-returning
// members of the P2PCoreBytes dependency require @_lifetime.
let embeddedEnabled = Context.environment["P2P_CORE_EMBEDDED"] == "1"

let coreSettings: [SwiftSetting] = {
    var s: [SwiftSetting] = [.enableExperimentalFeature("Lifetimes")]
    if embeddedEnabled {
        s += [.enableExperimentalFeature("Embedded"), .unsafeFlags(["-wmo"])]
    }
    return s
}()

// The Tier-1 `WebRTC` facade's dependencies. The DTLS facade (`TLS`) and the
// Embedded-clean cores dual-build under `P2P_CORE_EMBEDDED`. Host-only packages
// — swift-certificates / swift-asn1 (self-signed X.509 generation) and swift-log
// (logging) — are dropped under Embedded, where the facade gates the matching
// imports behind `#if !hasFeature(Embedded)` and uses the no-op logger shim +
// the externally-provisioned-identity path. Under Embedded the facade hashes the
// DTLS-SRTP fingerprint via `P2PCryptoEmbedded`'s `BoringSHA256` (preserving
// fail-closed verification) and schedules its retransmission tick through
// `P2PCoreCrypto`'s `AsyncTimer` seam.
//
// The adapter layer (`STUNCore` / `ICELite` / `SCTPCore` / `DataChannel`) is now
// cored + dual-built: each adapter is a `final class & Sendable` holding an
// Embedded-clean value-type engine behind a `FacadeLock`, driving the `*WireCore`
// codecs through the crypto/random/clock seams. All eight adapter/core targets
// Embedded-compile under `P2P_CORE_EMBEDDED=1 P2P_CRYPTO_EMBEDDED=1`.
//
// The `WebRTC` facade now Embedded-compiles end to end: a full
// `P2P_CORE_EMBEDDED=1 P2P_CRYPTO_EMBEDDED=1 swift build --target WebRTC -c release`
// builds clean. The facade exposes a `[UInt8]` public surface (with host-only
// `Data` convenience overloads gated `#if !hasFeature(Embedded)`, so swift-libp2p's
// `Data`-based consumers are unaffected); Foundation / Logging / swift-crypto /
// swift-certificates are host-only `#if`-gated imports, the fingerprint SHA-256 is
// routed through `P2PCryptoEmbedded`'s `BoringSHA256`, the retransmission driver
// uses the `AsyncTimer` seam, and every throwing entry point is typed-throws
// (`throws(WebRTCError)`) with static / structured error reasons (no
// `String(describing:)`). See CONTEXT.md.
let webrtcFacadeDependencies: [Target.Dependency] = {
    var d: [Target.Dependency] = [
        "STUNCore", "ICELite", "SCTPCore", "DataChannel",
        // The DTLS handshake/record engine is driven through swift-tls's Tier-1
        // `TLS` facade (`DTLSClient`/`DTLSServer`).
        .product(name: "TLS", package: "swift-tls"),
        // Time + deadline-sleep seam for the retransmission driver (dual-build).
        .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
    ]
    if embeddedEnabled {
        d += [
            // Embedded fingerprint SHA-256 + the `Span` currency it consumes.
            .product(name: "P2PCryptoEmbedded", package: "swift-p2p-crypto"),
            .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
        ]
    } else {
        d += [
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "SwiftASN1", package: "swift-asn1"),
            .product(name: "Logging", package: "swift-log"),
        ]
    }
    return d
}()

// The Embedded-clean crypto seam providers each caller-locked adapter needs. On
// host the `MessageAuthenticationCode` / `RandomSource` seams resolve to the
// swift-crypto–backed `P2PCryptoFoundation` providers; under Embedded they
// resolve to the BoringSSL-backed `P2PCryptoEmbedded` providers. `P2PCoreCrypto`
// (the seam protocols) is needed in both modes. swift-crypto is still pulled in
// on host for the historical `Data` wrappers' direct use; it is dropped under
// Embedded.
func adapterSeamDependencies(extra: [Target.Dependency] = []) -> [Target.Dependency] {
    var d: [Target.Dependency] = [
        .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
    ]
    if embeddedEnabled {
        d += [.product(name: "P2PCryptoEmbedded", package: "swift-p2p-crypto")]
    } else {
        d += [
            .product(name: "P2PCryptoFoundation", package: "swift-p2p-crypto"),
            .product(name: "Crypto", package: "swift-crypto"),
        ]
    }
    return d + extra
}

let sctpAdapterDependencies: [Target.Dependency] = adapterSeamDependencies(extra: ["SCTPWireCore"])
let stunAdapterDependencies: [Target.Dependency] = adapterSeamDependencies(extra: ["STUNWireCore"])
let iceAdapterDependencies: [Target.Dependency] = adapterSeamDependencies(extra: ["STUNCore", "ICELiteCore"])
let dataChannelAdapterDependencies: [Target.Dependency] = adapterSeamDependencies(extra: ["SCTPCore", "DataChannelCore"])

let packageDependencies: [Package.Dependency] = {
    var d: [Package.Dependency] = [
        // The DTLS handshake/record engine is driven through swift-tls's Tier-1
        // `TLS` facade (`DTLSClient`/`DTLSServer`).
        .package(url: "https://github.com/1amageek/swift-tls.git", from: "1.3.1"),
        .package(url: "https://github.com/1amageek/swift-p2p-core.git", from: "0.1.0"),
        // Provides `P2PCryptoEmbedded.BoringSHA256` for the Embedded DTLS-SRTP
        // fingerprint (fail-closed on both builds).
        .package(url: "https://github.com/1amageek/swift-p2p-crypto.git", from: "0.1.0"),
    ]
    if !embeddedEnabled {
        d += [
            .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),
            // WebRTC owns its DTLS-SRTP leaf certificate (self-signed ECDSA P-256)
            // and its SHA-256 fingerprint locally, because the `TLS` facade takes a
            // `TLSIdentity` (DER + raw key) rather than generating certificates.
            .package(url: "https://github.com/apple/swift-certificates.git", from: "1.17.1"),
            .package(url: "https://github.com/apple/swift-asn1.git", from: "1.5.1"),
            .package(url: "https://github.com/apple/swift-log.git", from: "1.9.0"),
        ]
    }
    return d
}()

let package = Package(
    name: "swift-webrtc",
    platforms: [
        .macOS(.v26), .iOS(.v26), .tvOS(.v26),
        .watchOS(.v26), .visionOS(.v26),
    ],
    products: [
        .library(name: "WebRTC", targets: ["WebRTC"]),
        .library(name: "STUNWireCore", targets: ["STUNWireCore"]),
        .library(name: "STUNCore", targets: ["STUNCore"]),
        .library(name: "ICELiteCore", targets: ["ICELiteCore"]),
        .library(name: "ICELite", targets: ["ICELite"]),
        .library(name: "SCTPWireCore", targets: ["SCTPWireCore"]),
        .library(name: "SCTPCore", targets: ["SCTPCore"]),
        .library(name: "DataChannelCore", targets: ["DataChannelCore"]),
        .library(name: "DataChannel", targets: ["DataChannel"]),
    ],
    dependencies: packageDependencies,
    targets: [
        // ---- Embedded-clean STUN wire codec (dual-build: host + Embedded) ----
        .target(
            name: "STUNWireCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
            ],
            path: "Sources/STUNWireCore",
            swiftSettings: coreSettings
        ),
        // ---- Caller-locked STUN adapter (dual-build: host + Embedded) ----
        // Keeps the Data-based STUN API; routes MESSAGE-INTEGRITY HMAC-SHA1 and
        // CSPRNG through the seams (host: swift-crypto; Embedded: BoringSSL).
        .target(
            name: "STUNCore",
            dependencies: stunAdapterDependencies,
            path: "Sources/STUNCore",
            swiftSettings: coreSettings
        ),
        // ---- Embedded-clean ICE Lite state machine (dual-build: host + Embedded) ----
        .target(
            name: "ICELiteCore",
            dependencies: ["STUNWireCore"],
            path: "Sources/ICELiteCore",
            swiftSettings: coreSettings
        ),
        // ---- Caller-locked ICE Lite adapter (dual-build: host + Embedded) ----
        // Holds the Embedded-clean `ICELiteStateMachine` behind a `FacadeLock`;
        // the wire decode + crypto (FINGERPRINT / MESSAGE-INTEGRITY) route through
        // STUNCore's seams. Gated `Data`/`Foundation` boundary only.
        .target(
            name: "ICELite",
            dependencies: iceAdapterDependencies,
            path: "Sources/ICELite",
            swiftSettings: coreSettings
        ),
        // ---- Embedded-clean SCTP wire codec (dual-build: host + Embedded) ----
        .target(
            name: "SCTPWireCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
            ],
            path: "Sources/SCTPWireCore",
            swiftSettings: coreSettings
        ),
        // ---- Caller-locked SCTP association adapter (dual-build: host + Embedded) ----
        // Holds the Embedded-clean value-type `SCTPAssociationEngine` behind a
        // `FacadeLock`. Host: swift-crypto cookie HMAC + `FoundationRandom` +
        // `ContinuousClock` boundary. Embedded: `BoringHMACSHA256` + `BoringRandom`
        // + `clock_gettime`; the `Data`/`ContinuousClock` wrappers are gated out.
        .target(
            name: "SCTPCore",
            dependencies: sctpAdapterDependencies,
            path: "Sources/SCTPCore",
            swiftSettings: coreSettings
        ),
        // ---- Embedded-clean DCEP wire codec (dual-build: host + Embedded) ----
        .target(
            name: "DataChannelCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
            ],
            path: "Sources/DataChannelCore",
            swiftSettings: coreSettings
        ),
        // ---- Caller-locked DCEP / data-channel adapter (dual-build: host + Embedded) ----
        // Holds the Embedded-clean `DataChannelManagerState` value type behind a
        // `FacadeLock`, driving DataChannelCore's DCEP codec. Gated `Data`/`Foundation`
        // boundary only.
        .target(
            name: "DataChannel",
            dependencies: dataChannelAdapterDependencies,
            path: "Sources/DataChannel",
            swiftSettings: coreSettings
        ),
        // ---- Tier-1 facade: WebRTCEndpoint/Connection/Listener/DataChannel ----
        // Dual-build orchestrator. Host: `Mutex` / `ContinuousClock` / swift-log /
        // swift-certificates. Embedded: those host-only deps are dropped (gated
        // `#if !hasFeature(Embedded)`); the lock becomes an `Atomic` spinlock, the
        // retransmission timer the `clock_gettime`-backed `WebRTCEmbeddedTimer`,
        // the logger a no-op shim, and the DTLS-SRTP fingerprint a `BoringSHA256`.
        // The externally-provisioned-identity path replaces X.509 generation.
        .target(
            name: "WebRTC",
            dependencies: webrtcFacadeDependencies,
            path: "Sources/WebRTC",
            exclude: ["CONTEXT.md"],
            swiftSettings: coreSettings
        ),
        // Tests
        .testTarget(name: "STUNCoreTests", dependencies: ["STUNCore"], path: "Tests/STUNCoreTests"),
        .testTarget(name: "ICELiteTests", dependencies: ["ICELite", "STUNCore"], path: "Tests/ICELiteTests"),
        .testTarget(name: "ICELiteCoreTests", dependencies: ["ICELiteCore"], path: "Tests/ICELiteCoreTests"),
        .testTarget(name: "SCTPCoreTests", dependencies: ["SCTPCore"], path: "Tests/SCTPCoreTests"),
        .testTarget(name: "DataChannelTests", dependencies: ["DataChannel", "SCTPCore"], path: "Tests/DataChannelTests"),
        .testTarget(name: "WebRTCTests", dependencies: ["WebRTC"], path: "Tests/WebRTCTests"),
        // Performance Tests
        .testTarget(
            name: "PerformanceTests",
            dependencies: ["STUNCore", "ICELite", "SCTPCore", "DataChannel", "WebRTC"],
            path: "Tests/PerformanceTests"
        ),
    ]
)
