// swift-tools-version: 6.4
import PackageDescription

// Embedded toggle controls the experimental Embedded feature + WMO for the
// Embedded-clean cores. Lifetimes is enabled in BOTH modes because Span-returning
// members of the P2PCoreBytes dependency require @_lifetime.
let embeddedEnabled = Context.environment["P2P_CORE_EMBEDDED"] == "1"
let wasiEnabled = Context.environment["P2P_CORE_WASM"] == "1"
let portableEnabled = embeddedEnabled || wasiEnabled

// Logging remains available on Linux even though identity crypto is portable.
let loggingPlatforms: [Platform] = [
    .macOS, .macCatalyst, .iOS, .tvOS, .watchOS, .visionOS, .linux,
]

let coreSettings: [SwiftSetting] = {
    var s: [SwiftSetting] = [.enableExperimentalFeature("Lifetimes")]
    if embeddedEnabled {
        s += [.enableExperimentalFeature("Embedded"), .unsafeFlags(["-wmo"])]
    }
    return s
}()

// Keep production libraries optimized in release builds. The pinned Swift 6.4
// WASM snapshot miscompiles local generic Array value-witness destruction in
// the executable-only runtime probe, so compile only that harness at `-Onone`.
// Its Embedded code generation also asserts while emitting conflicting DWARF
// locations; the documented Embedded command therefore selects SwiftPM's
// `-debug-info-format none` build option.
// The probe still links and exercises the release-built WebRTC/TLS/crypto code.
let platformProbeSettings: [SwiftSetting] = {
    var s = coreSettings
    if portableEnabled {
        s += [.unsafeFlags(["-Onone"])]
    }
    return s
}()

// The Swift 6.4 Embedded WASM SDK ships Unicode normalization/grapheme data as
// an optional static library. WebRTC's public diagnostics and ICE credentials
// exercise String operations that reference those symbols, so every Embedded
// executable consuming the facade must receive this link dependency. Keep the
// target-independent Swift sources unchanged; this is a platform link contract.
let embeddedWebRTCLinkerSettings: [LinkerSetting] = embeddedEnabled
    ? [.linkedLibrary("swiftUnicodeDataTables")]
    : []

// Dependencies for the single secure-transport module. STUN, ICE, SCTP,
// DataChannel, RTP, RTCP, and SRTP are implementation directories within
// `WebRTC`; they are not separately consumable Swift modules.
//
// The DTLS facade (`TLS`) and the portable protocol implementation dual-build
// under `P2P_CORE_EMBEDDED`. Certificate generation, parsing, and fingerprinting
// use the same Pure Swift path on Native, WASI, and Embedded. Native, WASI, and
// Embedded schedule both DTLS flight and SCTP
// retransmission deadlines through an injected `P2PCoreCrypto.AsyncTimer`.
//
// `WebRTC` Embedded-compiles end to end: a full
// `P2P_CORE_EMBEDDED=1 swift build --target WebRTC -c release`
// builds the same module. The facade exposes a `[UInt8]` public surface (with host-only
// `Data` convenience overloads gated by `canImport(Foundation)`, so swift-libp2p's
// `Data`-based consumers are unaffected); Foundation / Logging are optional imports, the fingerprint SHA-256 is
// routed through `P2PCrypto`'s `DefaultSHA256`, the retransmission driver
// uses the `AsyncTimer` seam, and the public facade's throwing entry points use
// typed throws (`throws(WebRTCError)`). Host builds retain underlying error
// descriptions where available; Embedded builds use stable operation context
// without reflection. See CONTEXT.md.
let webRTCDependencies: [Target.Dependency] = {
    var d: [Target.Dependency] = [
        // The DTLS handshake/record engine is exposed through
        // swift-tls-sessions' Tier-1 `TLS` facade (`DTLSClient`/`DTLSServer`).
        // Its DTLS 1.2 mechanism is owned by swift-ssl.
        .product(name: "TLS", package: "swift-tls-sessions"),
        // Time + deadline-sleep seam for the retransmission driver (dual-build).
        .product(name: "P2PCoreCrypto", package: "swift-ssl"),
        // Concrete AES-CTR and HMAC-SHA1 provider used by SRTPCore.
        .product(name: "P2PCrypto", package: "swift-p2p-core"),
        // Externally-provisioned identity parsing and portable fingerprinting
        // are required by WASI/Embedded and remain available on hosts.
        .product(name: "P2PCoreBytes", package: "swift-ssl"),
        .product(name: "P2PCoreDER", package: "swift-p2p-core"),
    ]
    d += [
        .product(
            name: "Logging",
            package: "swift-log",
            condition: .when(platforms: loggingPlatforms)
        ),
    ]
    return d
}()

let packageDependencies: [Package.Dependency] = {
    var d: [Package.Dependency] = [
        // The DTLS handshake/record engine is exposed through
        // swift-tls-sessions' Tier-1 `TLS` facade (`DTLSClient`/`DTLSServer`).
        // Its DTLS 1.2 mechanism is owned by swift-ssl/SSLDTLS.
        .package(name: "swift-tls-sessions", path: "../swift-tls"),
        .package(name: "swift-p2p-core", path: "../swift-p2p-core"),
        .package(name: "swift-ssl", path: "../../swift-ssl"),
        // `swift-p2p-core` also owns the P2PCrypto protocol adapter module.
    ]
    d += [
        .package(url: "https://github.com/apple/swift-log.git", from: "1.9.0"),
    ]
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
        .library(name: "WebRTCMedia", targets: ["WebRTCMedia"]),
    ],
    dependencies: packageDependencies,
    targets: [
        // Public secure WebRTC transport. Connectivity, SCTP/DataChannel,
        // RTP/RTCP, and SRTP implementations are source subdirectories of this
        // single module rather than separately consumable Swift libraries.
        .target(
            name: "WebRTC",
            dependencies: webRTCDependencies,
            path: "Sources/WebRTC",
            exclude: [
                "CONTEXT.md",
                "Transport/RTP/CONTEXT.md",
                "Transport/SRTP/CONTEXT.md",
            ],
            swiftSettings: coreSettings,
            linkerSettings: embeddedWebRTCLinkerSettings
        ),
        // Optional H.264 composition module. It consumes package-scoped RTP
        // primitives from WebRTC and preserves borrowed ranges and packet owners.
        .target(
            name: "WebRTCMedia",
            dependencies: [
                "WebRTC",
                .product(name: "P2PCoreBytes", package: "swift-ssl"),
            ],
            path: "Sources/WebRTCMedia",
            exclude: [
                "CONTEXT.md",
                "H264/ByteStream/CONTEXT.md",
                "H264/RTP/CONTEXT.md",
                "H264/RTP/Payload/CONTEXT.md",
                "H264/RTP/Receiver/CONTEXT.md",
                "H264/RTP/Sender/CONTEXT.md",
            ],
            swiftSettings: coreSettings
        ),
        // Test-only executable used to prove that the complete portable path
        // links and runs without XCTest/Swift Testing. Embedded WASM does not
        // provide the Testing module, so a Tests-contained executable is the
        // runtime gate for external certificate provisioning, mutual DTLS,
        // use_srtp/exporter setup, typed transport failure, timer cancellation,
        // and the authenticated H.264 sender-to-receiver path. It is
        // intentionally not a library product and does not exercise real UDP.
        .executableTarget(
            name: "WebRTCPlatformIntegrationProbe",
            dependencies: [
                "WebRTC",
                "WebRTCMedia",
                .product(name: "P2PCoreDER", package: "swift-p2p-core"),
            ],
            path: "Tests/WebRTCPlatformIntegrationProbe",
            swiftSettings: platformProbeSettings
        ),
        // Tests
        .testTarget(
            name: "RTPWireCoreTests",
            dependencies: ["WebRTC"],
            path: "Tests/RTPWireCoreTests",
            swiftSettings: coreSettings
        ),
        .testTarget(
            name: "H264ByteStreamCoreTests",
            dependencies: ["WebRTCMedia"],
            path: "Tests/H264ByteStreamCoreTests",
            swiftSettings: coreSettings
        ),
        .testTarget(
            name: "H264RTPPayloadCoreTests",
            dependencies: ["WebRTCMedia"],
            path: "Tests/H264RTPPayloadCoreTests",
            swiftSettings: coreSettings
        ),
        .testTarget(
            name: "H264RTPTests",
            dependencies: ["WebRTCMedia", "WebRTC"],
            path: "Tests/H264RTPTests",
            swiftSettings: coreSettings
        ),
        .testTarget(
            name: "H264RTPSenderTests",
            dependencies: ["WebRTCMedia", "WebRTC"],
            path: "Tests/H264RTPSenderTests",
            swiftSettings: coreSettings
        ),
        .testTarget(
            name: "H264RTPReceiverTests",
            dependencies: [
                "WebRTCMedia",
                "WebRTC",
            ],
            path: "Tests/H264RTPReceiverTests",
            swiftSettings: coreSettings
        ),
        .testTarget(
            name: "SRTPCoreTests",
            dependencies: [
                "WebRTC",
                .product(name: "P2PCoreCrypto", package: "swift-ssl"),
                .product(name: "P2PCrypto", package: "swift-p2p-core"),
            ],
            path: "Tests/SRTPCoreTests",
            swiftSettings: coreSettings
        ),
        .testTarget(name: "STUNCoreTests", dependencies: ["WebRTC"], path: "Tests/STUNCoreTests"),
        .testTarget(name: "ICELiteTests", dependencies: ["WebRTC"], path: "Tests/ICELiteTests"),
        .testTarget(name: "ICELiteCoreTests", dependencies: ["WebRTC"], path: "Tests/ICELiteCoreTests"),
        .testTarget(
            name: "SCTPCoreTests",
            dependencies: [
                "WebRTC",
                .product(name: "P2PCoreBytes", package: "swift-ssl"),
                .product(name: "P2PCoreCrypto", package: "swift-ssl"),
                .product(name: "P2PCrypto", package: "swift-p2p-core"),
            ],
            path: "Tests/SCTPCoreTests"
        ),
        .testTarget(
            name: "DataChannelTests",
            dependencies: ["WebRTC"],
            path: "Tests/DataChannelTests"
        ),
        .testTarget(
            name: "WebRTCTests",
            dependencies: [
                "WebRTC",
                .product(name: "P2PCoreCrypto", package: "swift-ssl"),
                .product(name: "P2PCoreDER", package: "swift-p2p-core"),
            ],
            path: "Tests/WebRTCTests"
        ),
        .testTarget(
            name: "RTPWireCorePerformanceTests",
            dependencies: ["WebRTC"],
            path: "Tests/RTPWireCorePerformanceTests",
            swiftSettings: coreSettings
        ),
        .testTarget(
            name: "H264RTPPayloadCorePerformanceTests",
            dependencies: ["WebRTCMedia"],
            path: "Tests/H264RTPPayloadCorePerformanceTests",
            swiftSettings: coreSettings
        ),
        // Performance Tests
        .testTarget(
            name: "PerformanceTests",
            dependencies: ["WebRTC"],
            path: "Tests/PerformanceTests",
            swiftSettings: coreSettings
        ),
    ],
    swiftLanguageModes: [.v6]
)
