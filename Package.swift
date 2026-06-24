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
    dependencies: [
        // Local path on the `embedded` branch: the DTLS handshake/record engine is
        // driven through swift-tls's Tier-1 `TLS` facade (`DTLSClient`/`DTLSServer`).
        // The former `DTLSCore`/`DTLSRecord` products were demoted to `package` in
        // the tls facade redesign and are no longer importable here. NOT for release.
        .package(path: "../swift-tls"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),
        // WebRTC owns its DTLS-SRTP leaf certificate (self-signed ECDSA P-256) and
        // its SHA-256 fingerprint locally, because the `TLS` facade takes a
        // `TLSIdentity` (DER + raw key) rather than generating certificates. X.509
        // generation needs swift-certificates + swift-asn1 (already in the graph
        // transitively via swift-tls).
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.17.1"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.5.1"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.9.0"),
        .package(path: "../swift-p2p-core"),
    ],
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
        // ---- Foundation adapter: keeps the existing Data-based STUN API ----
        .target(
            name: "STUNCore",
            dependencies: [
                "STUNWireCore",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/STUNCore"
        ),
        // ---- Embedded-clean ICE Lite state machine (dual-build: host + Embedded) ----
        .target(
            name: "ICELiteCore",
            dependencies: ["STUNWireCore"],
            path: "Sources/ICELiteCore",
            swiftSettings: coreSettings
        ),
        // ---- Foundation adapter: wire decode + crypto + Mutex over the core ----
        .target(
            name: "ICELite",
            dependencies: ["STUNCore", "ICELiteCore"],
            path: "Sources/ICELite"
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
        // ---- Foundation adapter: keeps the existing Data-based SCTP API ----
        .target(
            name: "SCTPCore",
            dependencies: [
                "SCTPWireCore",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/SCTPCore"
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
        // ---- Foundation adapter: keeps the existing Data-based DCEP API ----
        .target(
            name: "DataChannel",
            dependencies: ["SCTPCore", "DataChannelCore"],
            path: "Sources/DataChannel"
        ),
        .target(
            name: "WebRTC",
            dependencies: [
                "STUNCore", "ICELite", "SCTPCore", "DataChannel",
                // The DTLS handshake/record engine is driven through swift-tls's
                // Tier-1 `TLS` facade (`DTLSClient`/`DTLSServer`). The former
                // `DTLSCore`/`DTLSRecord` products were demoted to `package` in the
                // tls facade redesign and are no longer importable here.
                .product(name: "TLS", package: "swift-tls"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/WebRTC"
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
