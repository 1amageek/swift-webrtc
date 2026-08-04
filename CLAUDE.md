# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
SWIFT_TOOLCHAIN_USR="$(dirname "$(dirname "$(xcrun --toolchain org.swift.64202607231a --find swift)")")"

# Build with Swift 6.4 snapshot 2026-07-23
TOOLCHAINS=org.swift.64202607231a \
  xcodebuild build -scheme swift-webrtc-Package -destination 'platform=macOS'

# Run all tests (use timeout to prevent hangs)
TOOLCHAINS=org.swift.64202607231a \
  xcodebuild test -scheme swift-webrtc-Package -destination 'platform=macOS' \
  -maximum-test-execution-time-allowance 60 \
  "LD_RUNPATH_SEARCH_PATHS=\$(inherited) ${SWIFT_TOOLCHAIN_USR}/lib/swift/macosx/testing"

# Run focused test targets
TOOLCHAINS=org.swift.64202607231a \
  xcodebuild test -scheme swift-webrtc-Package -destination 'platform=macOS' \
  -only-testing:RTPWireCoreTests -maximum-test-execution-time-allowance 60 \
  "LD_RUNPATH_SEARCH_PATHS=\$(inherited) ${SWIFT_TOOLCHAIN_USR}/lib/swift/macosx/testing"
TOOLCHAINS=org.swift.64202607231a \
  xcodebuild test -scheme swift-webrtc-Package -destination 'platform=macOS' \
  -only-testing:H264RTPSenderTests -maximum-test-execution-time-allowance 60 \
  "LD_RUNPATH_SEARCH_PATHS=\$(inherited) ${SWIFT_TOOLCHAIN_USR}/lib/swift/macosx/testing"

# Normal WASM runtime probe using the matching SDK.
P2P_CORE_WASM=1 \
"$(xcrun --toolchain org.swift.64202607231a --find swift)" run \
  --package-path . --build-system swiftbuild -c release \
  --scratch-path /tmp/swift-webrtc-wasm-normal \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm \
  WebRTCPlatformIntegrationProbe

# Embedded WASM runtime probe. Release is required for Embedded WMO.
P2P_CORE_EMBEDDED=1 \
  "$(xcrun --toolchain org.swift.64202607231a --find swift)" run \
  --package-path . --build-system swiftbuild -c release \
  --scratch-path /tmp/swift-webrtc-wasm-embedded \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded \
  WebRTCPlatformIntegrationProbe
```

## Architecture

This is a pure Swift WebRTC Direct implementation with no C/C++ WebRTC stack.
Portable cryptography uses `swift-ssl` through `swift-p2p-core/P2PCrypto` on every target. The protocol stack is:

```
                                  ┌→ SCTP → Data Channels
UDP → STUN / ICE Lite → DTLS 1.2 ─┤
                                  └→ SRTP/SRTCP → RTP/RTCP handlers
```

### Product and Target Hierarchy

The package has exactly two public products and two Swift library targets:
`WebRTC` and `WebRTCMedia`. Foundation-free wire/media components use borrowed
`Span` inputs and scalar/range outputs. Stateful adapters expose `[UInt8]` on
all platforms and add Foundation conveniences only where available. Focused
test targets remain separate without creating additional library modules. All
shared state keeps the same `Mutex` contract on Native, normal WASM, and
Embedded.

```
WebRTC target and product
├── Connectivity/{ICE,STUN}
├── DataChannel/{Compatibility,SCTP}
├── Transport/{RTP,SRTP}
└── TLS dependency: swift-tls Tier-1 DTLS facade

WebRTCMedia target and product
└── H264/{ByteStream,RTP/{Payload,Sender,Receiver}}
        └── depends on WebRTC RTP contracts
```

### DTLS wiring (swift-tls Tier-1 facade)

WebRTC drives DTLS through swift-tls's Tier-1 `TLS` facade value types
(`DTLSClient` / `DTLSServer`). The former swift-tls `DTLSCore` / `DTLSRecord`
products were demoted to `package` visibility in the facade redesign and are no
longer importable here (swift-tls now exports only `TLS`, `TLSWire`, `DTLSWire`).
swift-tls is consumed through its `TLS` product. The current unreleased
integration has been validated against coordinated local working trees. The
development manifest uses sibling path dependencies; no swift-webrtc tag may be
created until compatible dependency commits are published, those paths are
replaced with public URLs, and the public graph passes the same validation matrix.

- **DTLSEndpoint** (`Sources/WebRTC/DTLSEndpoint.swift`) - Internal enum wrapping
  `DTLSClient` / `DTLSServer` behind one sans-IO surface: `receive` / `send` /
  `handleTimeout` / `startHandshake`, plus `isEstablished` and
  `remoteCertificateDER`. The server is configured with
  `requireClientCertificate: true` (mutual DTLS).

### Security / certificate model

WebRTC OWNS its DTLS certificate layer locally, because the `TLS` facade
takes a `TLSIdentity` (raw key + DER chain) rather than generating certificates:

- **WebRTCCertificate** (`Sources/WebRTC/WebRTCCertificate.swift`) - Owns a
  Pure Swift self-signed ECDSA P-256 v3 leaf (`digitalSignature`, not a CA,
  1-year validity) and raw private-key scalar. The validity clock is an
  injectable `WebRTCCertificateClock`; targets without a wall clock fail with a
  typed error unless the embedder supplies one. An externally provisioned DER +
  raw-scalar path is also available. `tlsIdentity` exposes the
  `TLS.TLSIdentity` the facade requires on every supported platform.
- **CertificateFingerprint** (same file) - SHA-256 fingerprint with `.sdpFormat`
  (`sha-256 AB:CD:...`), `.multihash` / `.multibaseEncoded` (libp2p `/certhash`),
  `fromDER` (hashes), and `fromDigest` (wraps an existing digest, no re-hash).
- **Fail-closed DTLS certificate auth** - The peer's leaf certificate is read
  from `DTLSEndpoint` when the handshake completes and retained by
  `WebRTCConnection.remoteCertificateDER`. `onHandshakeComplete()` computes the
  peer fingerprint from that DER and, when an expected fingerprint is
  configured, rejects the handshake on mismatch OR when the peer certificate
  is unavailable — it never silently accepts an unverified peer. The verified
  fingerprint is then exposed via `remoteFingerprint`.

### Key Classes

- **WebRTCEndpoint** (`Sources/WebRTC/WebRTCEndpoint.swift`) - Entry point. Creates connections and listeners. Owns the DTLS certificate.

- **WebRTCConnection** (`Sources/WebRTC/WebRTCConnection.swift`) - Integrates ICE, DTLS, SCTP/data channels, and authenticated RTP/RTCP transport. Codec packetization and RTP sender policy remain externally composed.

- **ICELiteAgent** (`Sources/WebRTC/Connectivity/ICE/ICELiteAgent.swift`) - Responds to ICE connectivity checks. Server-side only (no active candidate gathering). The underlying `ICELiteStateMachine` component caps its `validatedPeers` set at `maxValidatedPeers` (1000) and evicts the oldest entry FIFO so a roaming peer cannot grow it without bound.

- **SCTPAssociation** (`Sources/WebRTC/DataChannel/SCTP/SCTPAssociation.swift`) - Manages SCTP state machine, TSN tracking, and stream sequence numbers. TSN and 16-bit SSN ordering use RFC 1982 serial-number arithmetic (so wraparound is handled), and the out-of-order / reassembly buffers are count- and byte-capped.

- **DataChannelManager** (`Sources/WebRTC/DataChannel/DataChannel.swift`) - Handles DCEP (Data Channel Establishment Protocol) open/ack messages.

### Design Principles

- **Transport-agnostic**: Callers provide a `SendHandler` closure for outgoing data and call `receive(_:)` for incoming. No UDP socket binding inside the library.

- **Sendable + Mutex**: Public values that cross concurrency boundaries conform
  to `Sendable`. Native, WASM, and Embedded builds use the same
  `Synchronization.Mutex<T>` state-isolation contract for shared mutable state.

- **Injected timer + tokenized Task ownership**: One `WebRTCTimer` drives DTLS
  flight and SCTP retransmission deadlines. The timer Task registry reserves a
  token, creates the Task outside its mutex, then identity-checks handle
  attachment. Close removes handles under the mutex and cancels outside it.
  Production WASI/Embedded integrations inject an event-loop timer; the portable
  default is a bounded blocking runtime fallback.

- **Canonical DataChannel event consumer**:
  `WebRTCConnection.claimDataChannelEvents()` claims the single bounded ordered
  surface for `OPEN`, application `DATA`, and `CLOSE`. It must be finished on
  close/failure. Never split these transitions across independent callbacks or
  silently discard overflow.

### Protocol Demultiplexing

`WebRTCConnection.receive(_:)` demultiplexes by first byte (RFC 7983):
- `20-63`: DTLS record
- `0-3` (and `isSTUN` check): STUN message
- `128-191`: protected RTP/RTCP. A media-configured connection authenticates,
  checks replay state, decrypts, validates, and then invokes its media handler.
  A data-channel-only connection discards this range.

The presence of the internal RTP/RTCP wire parser does not make media ready.
Network RTP/RTCP must be authenticated and decrypted before that parser or a
media sink sees it.
