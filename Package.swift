// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "swift-webrtc",
    platforms: [
        .macOS(.v15), .iOS(.v18), .tvOS(.v18),
        .watchOS(.v11), .visionOS(.v2),
    ],
    products: [
        .library(name: "WebRTC", targets: ["WebRTC"]),
        .library(name: "STUNCore", targets: ["STUNCore"]),
        .library(name: "ICELite", targets: ["ICELite"]),
        .library(name: "SCTPCore", targets: ["SCTPCore"]),
        .library(name: "DataChannel", targets: ["DataChannel"]),
    ],
    dependencies: [
        .package(path: "../swift-tls"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.2.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.9.0"),
    ],
    targets: [
        .target(
            name: "STUNCore",
            dependencies: [
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
            dependencies: [],
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
    ]
)
