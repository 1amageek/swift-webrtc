# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Build
swift build

# Run all tests (use timeout to prevent hangs)
timeout 60 swift test

# Run tests for a specific module
timeout 30 swift test --filter STUNCoreTests
timeout 30 swift test --filter ICELiteTests
timeout 30 swift test --filter ICELiteCoreTests
timeout 30 swift test --filter SCTPCoreTests
timeout 30 swift test --filter DataChannelTests
timeout 30 swift test --filter WebRTCTests
timeout 60 swift test --filter PerformanceTests

# Embedded build of the dual-build cores (Package.swift gates Embedded + WMO on
# this env var; -c release is required because WMO is a release-mode flag).
P2P_CORE_EMBEDDED=1 swift build --target STUNWireCore -c release
P2P_CORE_EMBEDDED=1 swift build --target ICELiteCore -c release
P2P_CORE_EMBEDDED=1 swift build --target SCTPWireCore -c release
P2P_CORE_EMBEDDED=1 swift build --target DataChannelCore -c release
```

## Architecture

This is a pure Swift WebRTC data channel implementation with no C/C++ dependencies. The protocol stack is:

```
UDP → STUN / ICE Lite → DTLS 1.2 → SCTP → Data Channels
```

### Module Hierarchy

Each protocol layer is split into an Embedded-clean `*WireCore`/`*Core` value-type
core (no Foundation), and a Foundation adapter that keeps the `Data`-based API and
adds Mutex / swift-crypto. The four cores dual-build (host + Embedded); see the
Embedded build commands above.

```
WebRTC (top-level API)
├── STUNCore        - Data-based STUN API (adapter over STUNWireCore + Crypto)
│   └── STUNWireCore    - Embedded-clean STUN wire codec (RFC 5389)
├── ICELite         - ICE Lite Foundation adapter (wire decode + crypto + Mutex)
│   └── ICELiteCore     - Embedded-clean ICE Lite state machine (RFC 8445)
├── SCTPCore        - Data-based SCTP API (adapter over SCTPWireCore + Crypto)
│   └── SCTPWireCore    - Embedded-clean SCTP wire codec (RFC 4960)
├── DataChannel     - Data-based DCEP API (adapter over DataChannelCore)
│   └── DataChannelCore - Embedded-clean DCEP wire codec (RFC 8831 / 8832)
└── DTLS (swift-tls Tier-1 `TLS` facade — `DTLSClient`/`DTLSServer`)
```

### DTLS wiring (swift-tls Tier-1 facade)

WebRTC drives DTLS through swift-tls's Tier-1 `TLS` facade value types
(`DTLSClient` / `DTLSServer`). The former swift-tls `DTLSCore` / `DTLSRecord`
products were demoted to `package` visibility in the facade redesign and are no
longer importable here (swift-tls now exports only `TLS`, `TLSWire`, `DTLSWire`).
On the `embedded` branch swift-tls is referenced via local path (`../swift-tls`),
so this configuration is NOT for release.

- **DTLSEndpoint** (`Sources/WebRTC/DTLSEndpoint.swift`) - Internal enum wrapping
  `DTLSClient` / `DTLSServer` behind one sans-IO surface: `receive` / `send` /
  `handleTimeout` / `startHandshake`, plus `isEstablished` and
  `remoteCertificateDER`. The server is configured with
  `requireClientCertificate: true` (mutual DTLS).

### Security / certificate model

WebRTC OWNS its DTLS-SRTP certificate layer locally, because the `TLS` facade
takes a `TLSIdentity` (raw key + DER chain) rather than generating certificates:

- **WebRTCCertificate** (`Sources/WebRTC/WebRTCCertificate.swift`) - Self-signed
  ECDSA P-256 v3 leaf (`digitalSignature`, not a CA, 1-year validity) serialized to
  DER, plus its `P256.Signing.PrivateKey`. `generateSelfSigned(commonName:)` builds
  one (uses swift-certificates / swift-asn1). `tlsIdentity` exposes the
  `TLS.TLSIdentity` the facade requires.
- **CertificateFingerprint** (same file) - SHA-256 fingerprint with `.sdpFormat`
  (`sha-256 AB:CD:...`), `.multihash` / `.multibaseEncoded` (libp2p `/certhash`),
  `fromDER` (hashes), and `fromDigest` (wraps an existing digest, no re-hash).
- **Fail-closed DTLS-SRTP auth** - The peer's leaf certificate is surfaced via
  `WebRTCConnection.remoteCertificateDER` (delegates to `DTLSEndpoint`).
  `onHandshakeComplete()` computes the peer fingerprint from that DER and, when an
  expected fingerprint is configured, rejects the handshake on mismatch OR when the
  peer certificate is unavailable — it never silently accepts an unverified peer.
  The verified fingerprint is then exposed via `remoteFingerprint`.

### Key Classes

- **WebRTCEndpoint** (`Sources/WebRTC/WebRTCEndpoint.swift`) - Entry point. Creates connections and listeners. Owns the DTLS certificate.

- **WebRTCConnection** (`Sources/WebRTC/WebRTCConnection.swift`) - Integrates the full protocol stack. Demultiplexes STUN/DTLS by first byte, handles ICE, DTLS handshake, SCTP association, and data channel management.

- **ICELiteAgent** (`Sources/ICELite/ICELiteAgent.swift`) - Responds to ICE connectivity checks. Server-side only (no active candidate gathering). The underlying `ICELiteStateMachine` (in `ICELiteCore`) caps its `validatedPeers` set at `maxValidatedPeers` (1000) and evicts the oldest entry FIFO so a roaming peer cannot grow it without bound.

- **SCTPAssociation** (`Sources/SCTPCore/SCTPAssociation.swift`) - Manages SCTP state machine, TSN tracking, and stream sequence numbers. TSN and 16-bit SSN ordering use RFC 1982 serial-number arithmetic (so wraparound is handled), and the out-of-order / reassembly buffers are count- and byte-capped.

- **DataChannelManager** (`Sources/DataChannel/DataChannel.swift`) - Handles DCEP (Data Channel Establishment Protocol) open/ack messages.

### Design Principles

- **Transport-agnostic**: Callers provide a `SendHandler` closure for outgoing data and call `receive(_:)` for incoming. No UDP socket binding inside the library.

- **Sendable + Mutex**: All public types are `Sendable`. Thread safety uses `Synchronization.Mutex<T>` (not actors for high-frequency internal state).

- **AsyncStream for incoming channels**: `WebRTCConnection.incomingChannels` provides an async stream. The class must call `continuation.finish()` on close to prevent hangs.

### Protocol Demultiplexing

`WebRTCConnection.receive(_:)` demultiplexes by first byte (RFC 5764 §5.1.2):
- `20-63`: DTLS record
- `0-3` (and `isSTUN` check): STUN message
