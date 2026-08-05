# swift-webrtc

A pure Swift WebRTC Direct implementation with data channels and an
authenticated RTP/RTCP transport. It does not embed a C/C++ WebRTC stack;
portable cryptography is supplied by `swift-ssl` through
`swift-p2p-core`'s `P2PCrypto` module. The current development
working tree also contains zero-copy-oriented H.264 sender and bounded receiver
pipelines exposed through one optional media facade:

```
                                  ┌→ SCTP → Data Channels
UDP → STUN / ICE Lite → DTLS 1.2 ─┤
                                  └→ SRTP/SRTCP → RTP/RTCP handlers

encoded H.264 access unit
  → Annex B/AVCC ranges
  → RFC 6184 payload layouts
  → one-owner RTP packets
  → WebRTCConnection.sendRTP

authenticated plaintext RTP packet owner
  → bounded reorder and loss quarantine
  → range-only H.264 reconstruction plan
  → one exact decoder-bound access-unit owner
```

> **Release status.** The latest stable tag is `1.5.3`; it contains the data
> channel stack, but not the media facade described below. That product
> currently exists only in this uncommitted development working tree
> and depends on coordinated unreleased changes in swift-p2p-core, swift-ssl,
> and swift-tls.
>
> **Media status.** The unreleased tree implements RTP/RTCP wire parsing,
> DTLS `use_srtp`, the RFC 5705 exporter, AES-CM/HMAC-SHA1-80 SRTP/SRTCP, and
> authenticated RTP/RTCP send/receive on `WebRTCConnection`. Its H.264 sender
> path extracts borrowed Annex B/AVCC NAL ranges, packetizes Single NAL/STAP-A/
> FU-A payloads, assigns sequence numbers and 90 kHz timestamps, and assembles
> one-owner RTP packets. The receiver reorders packets, quarantines uncertain
> timestamps after loss, reconstructs Single NAL/STAP-A/FU-A into one exact-size
> Annex B or AVCC owner, and delivers one unit at a time outside its mutex.
> NACK/PLI, pacing, codec ownership, UDP integration, and Lume integration remain
> future milestones.

## Secure-transport boundary

`swift-webrtc` owns SDP/security generations, ICE/STUN, DTLS role and fingerprint
binding, timer delivery, SRTP/SRTCP, SCTP/DataChannel, and RTP/RTCP. It
consumes the public DTLS session through `swift-tls/DTLS`, while
`swift-ssl` owns the Pure Swift cryptographic, PKI, wire, record, replay,
flight, exporter, and handshake mechanisms.

```text
swift-libp2p -> swift-webrtc -> swift-tls / DTLS -> swift-ssl
```

WebRTC DTLS 1.2 interoperability is a deliberately narrow profile, not a general
TLS 1.2 fallback. The `swift-tls` facade is the public session boundary;
its mechanism implementation is supplied by `swift-ssl`. See the
[workspace secure-transport architecture](../../SECURE_TRANSPORT_ARCHITECTURE.md).

## Features

- Pure Swift WebRTC Direct data channel stack — no C/C++ WebRTC dependency
- STUN / ICE Lite for server-side connectivity checks ([RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389), [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445))
- DTLS 1.2 driven through the swift-tls Tier-1 `TLS` facade ([RFC 6347](https://www.rfc-editor.org/rfc/rfc6347))
- SCTP association, stream management, and reassembly ([RFC 4960](https://datatracker.ietf.org/doc/html/rfc4960))
- Data channels with the Data Channel Establishment Protocol ([RFC 8831](https://datatracker.ietf.org/doc/html/rfc8831), [RFC 8832](https://datatracker.ietf.org/doc/html/rfc8832))
- Mutual DTLS certificate authentication with fail-closed fingerprint verification ([RFC 8122](https://www.rfc-editor.org/rfc/rfc8122))
- Zero-copy RTP and bounded RTCP wire layouts, including compound and reduced-size validation ([RFC 3550](https://www.rfc-editor.org/rfc/rfc3550), [RFC 5506](https://www.rfc-editor.org/rfc/rfc5506))
- RTP/RTCP mux classification and negotiated payload-type validation ([RFC 5761](https://www.rfc-editor.org/rfc/rfc5761))
- DTLS-SRTP profile negotiation and directional key export ([RFC 5764](https://www.rfc-editor.org/rfc/rfc5764), [RFC 5705](https://www.rfc-editor.org/rfc/rfc5705))
- In-place AES_CM_128_HMAC_SHA1_80 SRTP/SRTCP with per-SSRC packet indices and replay protection ([RFC 3711](https://www.rfc-editor.org/rfc/rfc3711))
- Borrowed Annex B/AVCC NAL-range extraction without copying encoded media bytes
- RFC 6184 mode 0/1 H.264 Single NAL, STAP-A, and FU-A payload planning/parsing with allocation-free short-circuit traversal
- Stateful H.264 RTP sender policy with sequence reservation, 90 kHz timestamps, and a typed synchronous sink
- Bounded H.264 access units (2,048 packets by default, at most 32,766) with consuming packet-owner transfer
- Stateful H.264 RTP receiver with bounded reordering, conservative loss quarantine, timestamp boundary fallback, and typed sink effects
- Range-only receiver assembly followed by exact-size bulk materialization outside `Mutex`
- Pure Swift self-signed ECDSA P-256 certificate generation on every target, portable externally provisioned identities, and SHA-256 fingerprints (SDP / libp2p `/certhash`)
- Transport-agnostic, sans-IO design (caller-supplied `SendHandler`)
- Injected monotonic timer driver for DTLS flight and SCTP retransmission
  scheduling; cancellation remains typed on Native, WASM, and Embedded
- Foundation-free media and wire paths that share one implementation across Native, WASM, and Embedded Swift
- Swift 6.4 strict concurrency (`Sendable`, common `Mutex`-based thread safety)

## Requirements

These requirements describe the current development working tree; stable tags
retain their own manifest requirements.

- Swift 6.4 development snapshot `2026-07-23`
- macOS 26+ / iOS 26+ / tvOS 26+ / watchOS 26+ / visionOS 26+
- Matching normal and Embedded WASM SDKs for portable verification

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/1amageek/swift-webrtc.git", from: "1.5.3"),
]
```

This installs the stable data-channel release. Do not expect the unreleased
media product from that tag. The media-capable changes have been validated
against coordinated local working trees. Before the next release, publish the
compatible dependency commits, replace the development path dependencies with
public URLs, and rerun the complete matrix against that public graph.

## Quick Start

### Creating an endpoint

```swift
import WebRTC

let endpoint = try WebRTCEndpoint.create()
print(endpoint.localFingerprint.sdpFormat)
```

`create()` uses the shared Pure Swift certificate builder on targets with a
system wall clock. Embedded deployments inject a `WebRTCCertificateClock` or
provision a DER leaf plus its raw P-256 private scalar and construct
`WebRTCEndpoint(certificate:)`; unavailable clock services fail explicitly.

### Client

```swift
let connection = try endpoint.connect(
    remoteFingerprint: remoteFingerprint,
    sendHandler: { datagram in
        // Return success only after a bounded UDP transport accepts ownership.
        udpTransport.admit(consume datagram)
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
        do {
            let events = try connection.claimDataChannelEvents()
            while let event = try await events.next() {
                switch event {
                case .opened(let channel, let direction):
                    print("Channel opened: \(channel.label), direction: \(direction)")
                case .message(let channelID, let generation, let payload):
                    print(
                        "Channel \(channelID)/\(generation) received \(payload.count) bytes"
                    )
                case .closed(let closeEvent):
                    print("Channel closed: \(closeEvent)")
                }
            }
        } catch {
            print("DataChannel event consumer unavailable: \(error)")
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
> dialer fingerprint to
> `WebRTCConnection.asServer(certificate:remoteFingerprint:sendHandler:timer:logger:)`
> to fail the handshake on mismatch. Without that expected value,
> `remoteCertificateDER` contains only the presented certificate bytes; an upper
> layer must bind them to identity before they are trusted, and
> `remoteFingerprint` remains `nil`.

### Unreleased H.264 media composition

```swift
import WebRTC
import WebRTCMedia
```

The `WebRTCMedia` product does not own a camera, encoder, socket, or signaling session.
An adapter retains the encoded access-unit owner, extracts NAL ranges, and then
hands the borrowed bytes to one sender session. The sender transfers each final
plaintext RTP packet owner to a typed sink; `WebRTCConnection.sendRTP` protects
that owner in place and forwards it through the configured `SendHandler`.

```text
camera / hardware encoder owner
    -> WebRTCMedia               borrowed Annex B/AVCC NAL ranges
        -> internal RFC 6184     range-only packet layouts
        -> internal RTP sender  one final allocation + sequence/timestamp policy
    -> WebRTC                    SRTP protection + transport callback
```

For `.aes128CMHMACSHA180`, pass
`mediaConfiguration.protectionProfile.rtpProtectionTrailerByteCount` to
`H264RTPSenderConfiguration.protectionTrailerByteCount`. The configured maximum
datagram size covers the RTP header, RTP payload, and SRTP trailer; it does not
include UDP or IP headers. The encoder owner must remain alive and immutable
until `sendAccessUnit` returns.

`H264RTPSenderConfiguration.maximumPacketsPerAccessUnit` defaults to 2,048 and
cannot exceed 32,766. Keeping one reservation below RTP's half-sequence-space
boundary makes packet order unambiguous after a partial sink failure. The sink
parameter is `consuming`; successful handoff does not retain a second framework
owner for that packet.

On receive, `H264RTPReceiverSession` consumes an authenticated plaintext RTP
packet owner plus the layout parsed from that exact owner. It reparses the owner
to reject layout substitution, retains packet owners and ranges while the unit
is incomplete, then materializes one exact-size decoder-bound owner outside its
state mutex. RTP marker is used as an early boundary signal, but timestamp
transition is also supported. After a declared packet gap, the first observed
timestamp is quarantined because the missing packet may have been its first
packet.

## Products

The package publishes exactly two library products backed by exactly two Swift
library targets. Protocol boundaries remain explicit as source directories and
focused test targets; they are not separate importable modules.

| Product / import | Responsibility |
|---|---|
| **WebRTC** | ICE, DTLS, SCTP, data channels, DTLS-SRTP, and authenticated RTP/RTCP owner transfer |
| **WebRTCMedia** | Optional H.264 Annex B/AVCC framing, RFC 6184 packetization, sender policy, and bounded receiver |

This product and module reduction is a major-version API boundary. The stable
`1.5.x` line exposed lower protocol products directly. Consumers must migrate
lower protocol imports to `WebRTC`, and H.264 imports to `WebRTCMedia`, before
the next major release.

## Architecture

Foundation-free wire and media components use borrowed `Span` inputs plus
scalar/range outputs. Stateful adapters expose `[UInt8]` on every platform and
add `Data` conveniences only where Foundation is available. Native, normal
WASM, and Embedded builds keep the same ownership and synchronization
contracts.

```text
Sources/
├── WebRTC/                         Swift target and public product
│   ├── Connectivity/
│   │   ├── ICE/
│   │   └── STUN/
│   ├── DataChannel/
│   │   ├── Compatibility/
│   │   └── SCTP/
│   └── Transport/
│       ├── RTP/
│       └── SRTP/
└── WebRTCMedia/                    Swift target and public product
    └── H264/
        ├── ByteStream/
        └── RTP/
            ├── Payload/
            ├── Sender/
            └── Receiver/
```

- **Transport-agnostic** — Callers provide a `SendHandler` closure and feed incoming bytes via `receive(_:)`, so the library integrates with any UDP transport (no socket binding inside the library).
- **Sendable** — Public values that cross concurrency boundaries conform to
  `Sendable`. Native, WASM, and Embedded builds use the same
  `Synchronization.Mutex<T>` contract for shared mutable state.
- **Modular internally** — Protocol boundaries remain explicit source
  components with focused test targets without expanding the public product or
  import surface.
- **Codec-independent transport** — `WebRTC` does not depend on
  `WebRTCMedia`. `WebRTCMedia` depends on `WebRTC` for RTP wire contracts;
  callers may instead use another codec adapter or raw negotiated RTP.

DTLS is driven through the Tier-1 `TLS` facade of
`swift-tls` (`DTLSClient` / `DTLSServer`).
WebRTC owns its DTLS certificate layer locally — `WebRTCCertificate`
(self-signed ECDSA P-256 → DER + `TLSIdentity`) and `CertificateFingerprint`
(SHA-256, SDP / `/certhash`) — because the facade takes a `TLSIdentity` rather
than generating certificates.

`WebRTCConnection.receive(_:)` demultiplexes datagrams under RFC 7983: `20–63`
is DTLS, `0–3` plus STUN validation is STUN, and `128–191` is protected media.
Protected media is further classified as RTP or RTCP under RFC 5761, then must
pass SRTP/SRTCP authentication and replay checks before the internal RTP/RTCP
wire parser reads it and a media handler receives it.

## Security

- **Fail-closed DTLS certificate authentication** — The peer's leaf certificate
  is read from `DTLSEndpoint` when the handshake completes and retained by
  `WebRTCConnection.remoteCertificateDER`. `onHandshakeComplete()` computes the
  peer fingerprint from that DER and, when an expected fingerprint is
  configured, accepts ONLY on an exact
  match — rejecting on mismatch OR when the peer certificate is unavailable. It
  never silently accepts an unverified peer; the verified fingerprint is then
  exposed via `remoteFingerprint`.
- **Mutual DTLS authentication** — The server requires the client to present a
  certificate and prove possession of its private key, preventing inbound peer
  impersonation.
- **Authenticated media only** — Enabling media requires a signaling-bound peer
  fingerprint and successful `use_srtp` negotiation. RTP/RTCP handlers receive
  only authenticated, non-replayed plaintext. Invalid protected media is dropped
  without being reinterpreted as DTLS application data or a data channel packet.
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
  rejects stray ACKs and parity violations. A duplicate OPEN is not ACKed; the
  affected SCTP stream is reset. Partial-reliability channel types are rejected
  explicitly until FORWARD-TSN is implemented.

## Performance

The current benchmark targets cover the established data-channel paths, the RTP
parser's payload-size-independence gate, and the H.264 final-payload bulk-copy
regression gate. Media ownership tests also compare buffer base addresses across
reserved RTP/SRTCP egress and authenticated RTP/RTCP ingress. These tests prove
the audited owner paths, not all dependencies: the current swift-tls Tier-1 DTLS
facade still materializes record/application arrays internally. End-to-end
Jetson allocation and latency measurements are downstream Jetson/Lume
integration gates; they do not block release of this transport foundation.

| Suite | Coverage |
|---|---|
| `RTPWireCorePerformanceTests` | RTP parser latency remains independent of payload size |
| `H264RTPPayloadCorePerformanceTests` | 4 KiB/64 KiB contiguous final-payload materialization remains faster than the scalar reference |
| `SCTPBenchmarks` | CRC-32C, packet encode/decode, TSN tracking, fragment assembly |
| `STUNBenchmarks` | Message encode/decode, FINGERPRINT, MESSAGE-INTEGRITY |
| `ICEBenchmarks` | STUN request processing, credential generation, peer validation |
| `DataChannelBenchmarks` | DCEP encode/decode, channel open/lookup |

### Running benchmarks

```bash
SWIFT_TOOLCHAIN_USR="$(dirname "$(dirname "$(xcrun --toolchain org.swift.64202607231a --find swift)")")"

# Build the package with the pinned Swift 6.4 snapshot
TOOLCHAINS=org.swift.64202607231a \
  xcodebuild build -scheme swift-webrtc-Package \
  -configuration Release -destination 'platform=macOS'

# Run the data-channel benchmarks with an explicit timeout
TOOLCHAINS=org.swift.64202607231a \
  xcodebuild test -scheme swift-webrtc-Package \
  -configuration Release \
  -destination 'platform=macOS' \
  -only-testing:PerformanceTests \
  -maximum-test-execution-time-allowance 60 \
  ENABLE_TESTABILITY=YES \
  "LD_RUNPATH_SEARCH_PATHS=\$(inherited) ${SWIFT_TOOLCHAIN_USR}/lib/swift/macosx/testing"

# Run the independent RTP asymptotic gate
TOOLCHAINS=org.swift.64202607231a \
  xcodebuild test -scheme swift-webrtc-Package \
  -configuration Release \
  -destination 'platform=macOS' \
  -only-testing:RTPWireCorePerformanceTests \
  -maximum-test-execution-time-allowance 60 \
  ENABLE_TESTABILITY=YES \
  "LD_RUNPATH_SEARCH_PATHS=\$(inherited) ${SWIFT_TOOLCHAIN_USR}/lib/swift/macosx/testing"

# Run the H.264 final-materialization regression gate
TOOLCHAINS=org.swift.64202607231a \
  xcodebuild test -scheme swift-webrtc-Package \
  -configuration Release \
  -destination 'platform=macOS' \
  -only-testing:H264RTPPayloadCorePerformanceTests \
  -maximum-test-execution-time-allowance 60 \
  ENABLE_TESTABILITY=YES \
  "LD_RUNPATH_SEARCH_PATHS=\$(inherited) ${SWIFT_TOOLCHAIN_USR}/lib/swift/macosx/testing"
```

Release mode is strongly recommended. Debug builds include bounds checks and disable compiler optimizations, resulting in measurements that do not reflect production performance.

### Historical data-channel baseline

The following Apple Silicon release-build figures predate the current media
graph. They are retained as regression context and are not evidence for the
H.264 path or the pinned Swift 6.4 snapshot until remeasured.

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
SWIFT_TOOLCHAIN_USR="$(dirname "$(dirname "$(xcrun --toolchain org.swift.64202607231a --find swift)")")"

# Native tests with the pinned Swift 6.4 snapshot
TOOLCHAINS=org.swift.64202607231a \
  xcodebuild test -scheme swift-webrtc-Package \
  -destination 'platform=macOS' \
  -maximum-test-execution-time-allowance 60 \
  "LD_RUNPATH_SEARCH_PATHS=\$(inherited) ${SWIFT_TOOLCHAIN_USR}/lib/swift/macosx/testing"

# A focused test suite
TOOLCHAINS=org.swift.64202607231a \
  xcodebuild test -scheme swift-webrtc-Package \
  -destination 'platform=macOS' \
  -only-testing:H264RTPReceiverTests \
  -maximum-test-execution-time-allowance 60 \
  "LD_RUNPATH_SEARCH_PATHS=\$(inherited) ${SWIFT_TOOLCHAIN_USR}/lib/swift/macosx/testing"

# Normal WASM portable runtime probe
P2P_CORE_WASM=1 \
"$(xcrun --toolchain org.swift.64202607231a --find swift)" run \
  --package-path . --build-system swiftbuild -c release \
  --scratch-path /tmp/swift-webrtc-wasm-normal \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm \
  WebRTCPlatformIntegrationProbe

# Embedded WASM portable runtime probe
P2P_CORE_EMBEDDED=1 \
  "$(xcrun --toolchain org.swift.64202607231a --find swift)" run \
  --package-path . --build-system swiftbuild -c release \
  -debug-info-format none \
  --scratch-path /tmp/swift-webrtc-wasm-embedded \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded \
  WebRTCPlatformIntegrationProbe
```

The portable probe provisions two identities, completes a mutual in-memory DTLS
handshake, negotiates `use_srtp`, derives directional exporter keys, protects
and authenticates an SRTP H.264 sender-to-receiver byte round trip, verifies a
typed transport rejection, and verifies timer heartbeat plus cancellation. The
exact 2026-07-23 normal and Embedded WASM probes pass in isolated scratch paths.
They do not use real UDP and therefore do not prove browser interoperability,
target-parallel Mutex behavior, a production event-loop timer, or real
camera/encoder integration.

The pinned 2026-07-23 Embedded compiler asserts while emitting DWARF for the
probe's async task graph. `-debug-info-format none` avoids that compiler-only
failure; it does not change optimization or the runtime behavior under test.

The latest focused Native H.264 results are byte stream 6/6, RTP payload 24/24,
RTP packet assembly 3/3, sender 9/9, and receiver 36/36.

## References

- [RFC 3550 — RTP: A Transport Protocol for Real-Time Applications](https://www.rfc-editor.org/rfc/rfc3550)
- [RFC 5506 — Reduced-Size RTCP](https://www.rfc-editor.org/rfc/rfc5506)
- [RFC 5761 — Multiplexing RTP and RTCP](https://www.rfc-editor.org/rfc/rfc5761)
- [RFC 5764 — DTLS Extension to Establish Keys for SRTP](https://www.rfc-editor.org/rfc/rfc5764)
- [RFC 5705 — Keying Material Exporters for TLS](https://www.rfc-editor.org/rfc/rfc5705)
- [RFC 3711 — The Secure Real-time Transport Protocol](https://www.rfc-editor.org/rfc/rfc3711)
- [RFC 7983 — Multiplexing Scheme Updates for DTLS-SRTP](https://www.rfc-editor.org/rfc/rfc7983)
- [RFC 6184 — RTP Payload Format for H.264 Video](https://www.rfc-editor.org/rfc/rfc6184)
- [RFC 4960 — Stream Control Transmission Protocol](https://datatracker.ietf.org/doc/html/rfc4960)
- [RFC 5389 — Session Traversal Utilities for NAT (STUN)](https://datatracker.ietf.org/doc/html/rfc5389)
- [RFC 6347 — Datagram Transport Layer Security Version 1.2](https://www.rfc-editor.org/rfc/rfc6347)
- [RFC 8122 — Connection-Oriented Media Transport over TLS in SDP](https://www.rfc-editor.org/rfc/rfc8122)
- [RFC 8445 — Interactive Connectivity Establishment (ICE)](https://datatracker.ietf.org/doc/html/rfc8445)
- [RFC 8831 — WebRTC Data Channels](https://datatracker.ietf.org/doc/html/rfc8831)
- [RFC 8832 — WebRTC Data Channel Establishment Protocol](https://datatracker.ietf.org/doc/html/rfc8832)

## License

MIT
