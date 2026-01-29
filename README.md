# swift-webrtc

A pure Swift implementation of WebRTC data channels.

Built entirely from scratch — no C/C++ WebRTC library dependency. Implements the full protocol stack required for WebRTC Direct data channel communication:

```
UDP → STUN / ICE Lite → DTLS 1.2 → SCTP → Data Channels
```

## Requirements

- Swift 6.2+
- macOS 15+ / iOS 18+ / tvOS 18+ / watchOS 11+ / visionOS 2+

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/1amageek/swift-webrtc.git", from: "0.0.1"),
]
```

## Architecture

The library is split into independent modules:

| Module | Description | RFC |
|---|---|---|
| **STUNCore** | STUN message encoding/decoding, MESSAGE-INTEGRITY, FINGERPRINT | [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) |
| **ICELite** | ICE Lite agent for server-side connectivity checks | [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445) |
| **SCTPCore** | SCTP association, chunk encoding/decoding, stream management | [RFC 4960](https://datatracker.ietf.org/doc/html/rfc4960) |
| **DataChannel** | Data channel lifecycle, DCEP (open/ack) messages | [RFC 8831](https://datatracker.ietf.org/doc/html/rfc8831) |
| **WebRTC** | Top-level API integrating all layers | — |

DTLS is provided by [swift-tls](https://github.com/1amageek/swift-tls).

## Usage

### Creating an endpoint

```swift
import WebRTC

let endpoint = try WebRTCEndpoint.create()
print(endpoint.localFingerprint.sdpFormat)
```

### Client

```swift
let connection = try endpoint.connect(
    remoteFingerprint: remoteFingerprint,
    sendHandler: { data in
        // Send raw bytes over UDP
    }
)

connection.setRemoteICECredentials(ufrag: remoteUfrag, password: remotePassword)
try connection.start()

let channel = try connection.openDataChannel(label: "data")
try connection.send(payload, on: channel.id)
```

### Server

```swift
let listener = try endpoint.listen()

for await connection in listener.connections {
    try connection.start()

    for await channel in connection.incomingChannels {
        print("Channel opened: \(channel.label)")
    }
}
```

## Design

- **Transport-agnostic** — Callers provide a `SendHandler` closure and feed incoming bytes via `receive(_:)`. This allows integration with any UDP transport.
- **Sendable** — All public types conform to `Sendable`. Thread safety is achieved using `Mutex<T>`.
- **Modular** — Each protocol layer is a standalone library that can be used independently.

## Benchmarks

Performance benchmarks are included under `Tests/PerformanceTests/`. Each module has a dedicated benchmark suite:

| Suite | Coverage |
|---|---|
| `SCTPBenchmarks` | CRC-32C, packet encode/decode, TSN tracking, fragment assembly |
| `STUNBenchmarks` | Message encode/decode, FINGERPRINT, MESSAGE-INTEGRITY |
| `ICEBenchmarks` | STUN request processing, credential generation, peer validation |
| `DataChannelBenchmarks` | DCEP encode/decode, channel open/lookup |

### Running benchmarks

```bash
# All benchmarks (debug)
swift test --filter PerformanceTests

# All benchmarks (release — recommended for accurate numbers)
swift test -c release --filter PerformanceTests

# Single suite
swift test -c release --filter SCTPBenchmarks
```

Release mode is strongly recommended. Debug builds include bounds checks and disable compiler optimizations, resulting in measurements that do not reflect production performance.

### Key results (Apple Silicon, release build)

| Operation | Throughput |
|---|---|
| CRC-32C (1500 B) | 2.7 GB/s |
| SCTP packet encode | 845K ops/s |
| SCTP packet decode | 1.5M ops/s |
| TSN gap block computation | 577K ops/s |
| STUN FINGERPRINT compute | 2.9M ops/s |
| Fragment assembly (multi-chunk) | 526K ops/s |

CRC-32C uses a slicing-by-8 lookup table algorithm. Checksum validation avoids packet-level copies by computing the CRC with the checksum field treated as zeros in-place.

## License

MIT
