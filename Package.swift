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
        .library(name: "ICELite", targets: ["ICELite"]),
        .library(name: "SCTPCore", targets: ["SCTPCore"]),
        .library(name: "DataChannel", targets: ["DataChannel"]),
    ],
    dependencies: [
        .package(url: "https://github.com/1amageek/swift-tls.git", from: "1.3.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.9.0"),
        .package(path: "../swift-p2p-core"),
    ],
    targets: [
        // ---- Embedded-clean STUN wire codec (dual-build: host + Embedded) ----
        .target(
            name: "STUNWireCore",
            dependencies: [
                .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
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
        .target(
            name: "ICELite",
            dependencies: ["STUNCore"],
            path: "Sources/ICELite"
        ),
        .target(
            name: "SCTPCore",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/SCTPCore"
        ),
        .target(
            name: "DataChannel",
            dependencies: ["SCTPCore"],
            path: "Sources/DataChannel"
        ),
        .target(
            name: "WebRTC",
            dependencies: [
                "STUNCore", "ICELite", "SCTPCore", "DataChannel",
                .product(name: "DTLSCore", package: "swift-tls"),
                .product(name: "DTLSRecord", package: "swift-tls"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/WebRTC"
        ),
        // Tests
        .testTarget(name: "STUNCoreTests", dependencies: ["STUNCore"], path: "Tests/STUNCoreTests"),
        .testTarget(name: "ICELiteTests", dependencies: ["ICELite", "STUNCore"], path: "Tests/ICELiteTests"),
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
