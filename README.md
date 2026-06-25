# swift-webrtc

A pure Swift implementation of WebRTC data channels, built entirely from scratch — no C/C++ WebRTC library dependency. It implements the full protocol stack required for WebRTC Direct data channel communication, with `Data`-based public APIs over Embedded-clean `[UInt8]` value-type cores:

```
UDP → STUN / ICE Lite → DTLS 1.2 → SCTP → Data Channels
```

> **Release status.** The released `1.5.0` ships the prior API. The Embedded-first API documented here (the Tier-1 `TLS`-facade DTLS wiring and the local `WebRTCCertificate` / `CertificateFingerprint` / fail-closed DTLS-SRTP certificate ownership) lives on the unreleased `embedded` branch (M8 pending) and is not tagged — pin to the branch to use it. That branch references `swift-tls` by local path, so it is not yet consumable as a versioned dependency.

## Features

- Pure Swift WebRTC Direct data channel stack — no C/C++ WebRTC dependency
- STUN / ICE Lite for server-side connectivity checks ([RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389), [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445))
- DTLS 1.2 driven through the swift-tls Tier-1 `TLS` facade ([RFC 6347](https://www.rfc-editor.org/rfc/rfc6347))
- SCTP association, stream management, and reassembly ([RFC 4960](https://datatracker.ietf.org/doc/html/rfc4960))
- Data channels with the Data Channel Establishment Protocol ([RFC 8831](https://datatracker.ietf.org/doc/html/rfc8831), [RFC 8832](https://datatracker.ietf.org/doc/html/rfc8832))
- DTLS-SRTP mutual authentication with fail-closed fingerprint verification ([RFC 8122](https://www.rfc-editor.org/rfc/rfc8122))
- Local self-signed ECDSA P-256 certificate generation and SHA-256 fingerprint (SDP / libp2p `/certhash`)
- Transport-agnostic, sans-IO design (caller-supplied `SendHandler`)
- Embedded-clean value-type cores (`STUNWireCore` / `ICELiteCore` / `SCTPWireCore` / `DataChannelCore`) that dual-build for Embedded Swift
- Swift 6 strict concurrency (`Sendable`, `Mutex`-based thread safety)

## Requirements

- Swift 6.2+
- macOS 26+ / iOS 26+ / tvOS 26+ / watchOS 26+ / visionOS 26+

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/1amageek/swift-webrtc.git", branch: "embedded"),
]
```

The four `*WireCore` / `ICELiteCore` cores dual-build for Embedded Swift
(`P2P_CORE_EMBEDDED=1 swift build --target <Core> -c release`).

## Quick Start

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

## Products

The library is split into independent modules. Each protocol layer has an
Embedded-clean `*WireCore`/`*Core` (value types, no Foundation) and a Foundation
adapter built on top of it that preserves the `Data`-based API:

| Module | Description | RFC |
|---|---|---|
| **STUNWireCore** | Embedded-clean STUN wire codec | [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) |
| **STUNCore** | Foundation STUN API, MESSAGE-INTEGRITY, FINGERPRINT | [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) |
| **ICELiteCore** | Embedded-clean ICE Lite state machine | [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445) |
| **ICELite** | ICE Lite agent for server-side connectivity checks | [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445) |
| **SCTPWireCore** | Embedded-clean SCTP wire codec (chunks, packets, TSN) | [RFC 4960](https://datatracker.ietf.org/doc/html/rfc4960) |
| **SCTPCore** | Foundation SCTP API, association, stream management | [RFC 4960](https://datatracker.ietf.org/doc/html/rfc4960) |
| **DataChannelCore** | Embedded-clean DCEP wire codec | [RFC 8832](https://datatracker.ietf.org/doc/html/rfc8832) |
| **DataChannel** | Data channel lifecycle, DCEP (open/ack) messages | [RFC 8831](https://datatracker.ietf.org/doc/html/rfc8831), [RFC 8832](https://datatracker.ietf.org/doc/html/rfc8832) |
| **WebRTC** | Top-level API integrating all layers | — |

## Architecture

Each protocol layer is split into an Embedded-clean `*WireCore`/`*Core` value-type
core (no Foundation) and a Foundation adapter that keeps the `Data`-based API and
adds `Mutex` / swift-crypto. The four cores dual-build (host + Embedded).

- **Transport-agnostic** — Callers provide a `SendHandler` closure and feed incoming bytes via `receive(_:)`, so the library integrates with any UDP transport (no socket binding inside the library).
- **Sendable** — All public types conform to `Sendable`. Thread safety uses `Synchronization.Mutex<T>` (not actors) for high-frequency internal state.
- **Modular** — Each protocol layer is a standalone library that can be used independently.

DTLS is driven through the Tier-1 `TLS` facade of
[swift-tls](https://github.com/1amageek/swift-tls) (`DTLSClient` / `DTLSServer`).
WebRTC owns its DTLS-SRTP certificate layer locally — `WebRTCCertificate`
(self-signed ECDSA P-256 → DER + `TLSIdentity`) and `CertificateFingerprint`
(SHA-256, SDP / `/certhash`) — because the facade takes a `TLSIdentity` rather
than generating certificates.

`WebRTCConnection.receive(_:)` demultiplexes the inbound byte stream by first byte
(RFC 5764 §5.1.2): `20–63` is a DTLS record, `0–3` (plus the `isSTUN` check) is a
STUN message.

## Security

- **Fail-closed DTLS-SRTP authentication** — The peer's leaf certificate is
  surfaced via `WebRTCConnection.remoteCertificateDER` (delegating to
  `DTLSEndpoint`). `onHandshakeComplete()` computes the peer fingerprint from that
  DER and, when an expected fingerprint is configured, accepts ONLY on an exact
  match — rejecting on mismatch OR when the peer certificate is unavailable. It
  never silently accepts an unverified peer; the verified fingerprint is then
  exposed via `remoteFingerprint`.
- **Mutual DTLS authentication** — The server requires the client to present a
  certificate and prove possession of its private key, preventing inbound peer
  impersonation.
- **SCTP hardening** — Zero-length-chunk DoS is rejected (the chunk parser
  always advances), reassembly and out-of-order buffers are count- and
  byte-bounded, COOKIE-ECHO replay is rejected, the negotiated inbound stream
  count is enforced, retransmissions are bounded (the association aborts after the
  maximum), and spoofed / reflected-tag ABORTs are discarded per RFC 4960 §8.5.
  TSN (32-bit) and SSN (16-bit) ordering use RFC 1982 serial-number arithmetic so
  wraparound is handled.
- **ICE Lite peer cap** — The validated-peer set is capped (1000) and evicts the
  oldest entry FIFO, so a spoofed-source-address flood cannot grow it without
  bound; the cap does not relax authentication.
- **STUN parsing** — Decoding and `isSTUN()` are safe for sliced `Data` (a
  non-zero `startIndex` no longer traps or misreads).
- **Throwing APIs** — Operations that can fail surface errors explicitly:
  `SCTPAssociation.sendData` throws on send-queue backpressure, and DataChannel
  `openChannel` throws on stream-ID exhaustion / resource caps. DCEP handling
  rejects stray ACKs, parity violations, and idempotently re-ACKs duplicate
  OPENs.

## Performance

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

## Testing

```bash
# All tests (use a timeout to prevent hangs)
timeout 60 swift test

# A single module
timeout 30 swift test --filter STUNCoreTests
timeout 30 swift test --filter SCTPCoreTests
timeout 30 swift test --filter WebRTCTests
```

## References

- [RFC 4960 — Stream Control Transmission Protocol](https://datatracker.ietf.org/doc/html/rfc4960)
- [RFC 5389 — Session Traversal Utilities for NAT (STUN)](https://datatracker.ietf.org/doc/html/rfc5389)
- [RFC 6347 — Datagram Transport Layer Security Version 1.2](https://www.rfc-editor.org/rfc/rfc6347)
- [RFC 8122 — Connection-Oriented Media Transport over TLS in SDP](https://www.rfc-editor.org/rfc/rfc8122)
- [RFC 8445 — Interactive Connectivity Establishment (ICE)](https://datatracker.ietf.org/doc/html/rfc8445)
- [RFC 8831 — WebRTC Data Channels](https://datatracker.ietf.org/doc/html/rfc8831)
- [RFC 8832 — WebRTC Data Channel Establishment Protocol](https://datatracker.ietf.org/doc/html/rfc8832)

## License

MIT
