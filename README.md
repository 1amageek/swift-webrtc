# swift-webrtc

A pure Swift implementation of WebRTC data channels.

Built entirely from scratch — no C/C++ WebRTC library dependency. Implements the full protocol stack required for WebRTC Direct data channel communication:

```
UDP → STUN / ICE Lite → DTLS 1.2 → SCTP → Data Channels
```

## Requirements

- Swift 6.2+
- macOS 26+ / iOS 26+ / tvOS 26+ / watchOS 26+ / visionOS 26+

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/1amageek/swift-webrtc.git", from: "1.5.0"),
]
```

## Architecture

The library is split into independent modules:

| Module | Description | RFC |
|---|---|---|
| **STUNCore** | STUN message encoding/decoding, MESSAGE-INTEGRITY, FINGERPRINT | [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) |
| **ICELite** | ICE Lite agent for server-side connectivity checks | [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445) |
| **SCTPCore** | SCTP association, chunk encoding/decoding, stream management | [RFC 4960](https://datatracker.ietf.org/doc/html/rfc4960) |
| **DataChannel** | Data channel lifecycle, DCEP (open/ack) messages | [RFC 8831](https://datatracker.ietf.org/doc/html/rfc8831), [RFC 8832](https://datatracker.ietf.org/doc/html/rfc8832) |
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

The listener accepts connections as the transport feeds incoming datagrams
(`listener.acceptConnection(peerID:sendHandler:)` starts each connection's DTLS
handshake). Consume accepted connections from the `connections` stream:

```swift
let listener = try endpoint.listen()

for await connection in listener.connections {
    // Handle each connection concurrently so the accept loop keeps running.
    Task {
        for await channel in connection.incomingChannels {
            print("Channel opened: \(channel.label)")
        }
        // The verified remote certificate fingerprint is available after the
        // mutual DTLS handshake completes.
        if let remote = connection.remoteFingerprint {
            print("Authenticated peer: \(remote.sdpFormat)")
        }
    }
}
```

> The server **requires** the client to present a certificate and prove
> possession of its private key (mutual DTLS authentication). Pass a known
> dialer fingerprint to `WebRTCConnection.asServer(certificate:remoteFingerprint:sendHandler:logger:)`
> to fail the handshake on mismatch, or read the verified `remoteFingerprint` /
> `remoteCertificateDER` afterwards to bind the peer identity in an upper layer.

## Design

- **Transport-agnostic** — Callers provide a `SendHandler` closure and feed incoming bytes via `receive(_:)`. This allows integration with any UDP transport.
- **Sendable** — All public types conform to `Sendable`. Thread safety is achieved using `Mutex<T>`.
- **Modular** — Each protocol layer is a standalone library that can be used independently.

## Security

- **Mutual DTLS authentication** — The server requires the client to present a
  certificate and prove possession of its private key, preventing inbound peer
  impersonation. The verified remote fingerprint is exposed via
  `remoteFingerprint` / `remoteCertificateDER` after the handshake.
- **SCTP hardening** — Zero-length-chunk DoS is rejected (the chunk parser
  always advances), reassembly and out-of-order buffers are byte-bounded,
  COOKIE-ECHO replay is rejected, the negotiated inbound stream count is
  enforced, retransmissions are bounded (the association aborts after the
  maximum), and spoofed / reflected-tag ABORTs are discarded per RFC 4960 §8.5.
- **STUN parsing** — Decoding and `isSTUN()` are safe for sliced `Data` (a
  non-zero `startIndex` no longer traps or misreads).
- **Throwing APIs** — Operations that can fail surface errors explicitly:
  `SCTPAssociation.sendData` throws on send-queue backpressure, and DataChannel
  `openChannel` throws on stream-ID exhaustion / resource caps. DCEP handling
  rejects stray ACKs, parity violations, and idempotently re-ACKs duplicate
  OPENs.

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
