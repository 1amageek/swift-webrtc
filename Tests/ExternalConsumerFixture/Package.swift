// swift-tools-version: 6.4
import PackageDescription

let embeddedEnabled = Context.environment["SWIFT_NETWORKING_EMBEDDED"] == "1"
let portableEnabled =
    embeddedEnabled
    || Context.environment["WEBRTC_PORTABLE"] == "1"
let mediaOnlyEnabled =
    Context.environment["WEBRTC_MEDIA_ONLY"] == "1"

let webRTCDependency: Package.Dependency = portableEnabled
    ? .package(path: "../..", traits: [])
    : .package(path: "../..")

let consumerSourcePath: String = {
    if mediaOnlyEnabled {
        return "Sources/WebRTCMediaOnlyConsumerFixture"
    }
    return switch Context.environment["WEBRTC_BOUNDARY_PROBE"] {
    case "data-channel-manager":
        "Negative/DataChannelManager"
    case "rtp-parser":
        "Negative/RTPParser"
    case "internal-module":
        "Negative/InternalModule"
    default:
        "Sources/WebRTCExternalConsumerFixture"
    }
}()

let consumerDependencies: [Target.Dependency] = mediaOnlyEnabled
    ? [
        .product(name: "WebRTCMedia", package: "swift-webrtc"),
    ]
    : [
        .product(name: "WebRTC", package: "swift-webrtc"),
        .product(name: "WebRTCMedia", package: "swift-webrtc"),
    ]

let fixtureSettings: [SwiftSetting] = {
    var settings: [SwiftSetting] = [
        .enableExperimentalFeature("Lifetimes"),
    ]
    if embeddedEnabled {
        settings += [
            .enableExperimentalFeature("Embedded"),
            .unsafeFlags(["-wmo"]),
        ]
    }
    return settings
}()

let package = Package(
    name: "WebRTCExternalConsumerFixture",
    platforms: [
        .macOS(.v26), .iOS(.v26), .tvOS(.v26),
        .watchOS(.v26), .visionOS(.v26),
    ],
    dependencies: [
        webRTCDependency,
    ],
    targets: [
        .executableTarget(
            name: "WebRTCExternalConsumerFixture",
            dependencies: consumerDependencies,
            path: consumerSourcePath,
            swiftSettings: fixtureSettings,
            linkerSettings: embeddedEnabled
                ? [.linkedLibrary("swiftUnicodeDataTables")]
                : []
        ),
    ],
    swiftLanguageModes: [.v6]
)
