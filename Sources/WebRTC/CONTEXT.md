# WebRTC — CONTEXT
Scope/role: the top-level WebRTC data-channel API (`Sources/WebRTC`) that integrates STUN/ICE-Lite, DTLS (via the swift-tls Tier-1 facade), SCTP, and DataChannel; the public entry point consumers import.
Last reviewed: 2026-06-25

Invariants and design intent that the code does not state structurally. Read this
before changing the DTLS-SRTP authentication path, the certificate/fingerprint
ownership, or the SCTP/ICE buffering caps. The protocol stack is `UDP → STUN /
ICE Lite → DTLS 1.2 → SCTP → Data Channels`; the lower layers split into an
Embedded-clean `*WireCore`/`*Core` value type plus a Foundation adapter, while
this top-level module is host-only (Foundation + swift-crypto + X.509).

## Contracts (the load-bearing rules)

- **WebRTC owns its DTLS-SRTP certificate layer locally.** The swift-tls Tier-1
  facade takes a `TLSIdentity` (raw key + DER chain) rather than generating
  certificates, so `WebRTCCertificate` (`Sources/WebRTC/WebRTCCertificate.swift`)
  generates the self-signed ECDSA P-256 leaf and `CertificateFingerprint` computes
  the SHA-256 fingerprint. Do not push certificate generation down into swift-tls;
  the fingerprint is WebRTC's unit of peer identity and must stay here.
- **DTLS is driven through the Tier-1 facade, never the legacy products.**
  `DTLSEndpoint` (`Sources/WebRTC/DTLSEndpoint.swift`) is an internal enum wrapping
  `DTLSClient` / `DTLSServer` behind one sans-IO surface (`startHandshake` /
  `receive` / `send` / `handleTimeout`, plus `isEstablished` and
  `remoteCertificateDER`). The former swift-tls `DTLSCore` / `DTLSRecord` products
  were demoted to `package` visibility and are not importable here. Route all DTLS
  through `DTLSEndpoint`; do not reintroduce a direct record-layer dependency.
- **The server is configured with `requireClientCertificate: true`.**
  `DTLSEndpoint.make` honors `requireClientCertificate` only on the server role;
  the WebRTC server demands mutual DTLS authentication. Do not relax this.
- **`WebRTCConnection` thread safety is `Mutex`-based, not actor-based.** Internal
  state lives behind `connState.withLock`. Keep mutations inside the lock; do not
  hold the lock across an `await`.
- **`incomingChannels` is an `AsyncStream` that MUST be finished on close/fail.**
  `finishIncomingChannels()` calls the continuation's `finish()`; the fail-closed
  handshake paths call it before throwing. A path that fails the connection without
  finishing the stream leaves `for await` consumers hung.

## Invariants (must hold; tests guard them)

- **DTLS-SRTP fingerprint authentication is fail-closed.**
  `WebRTCConnection.onHandshakeComplete()` (`Sources/WebRTC/WebRTCConnection.swift`)
  computes the peer fingerprint from `DTLSEndpoint.remoteCertificateDER` and, when
  an `expectedFingerprint` is configured, accepts ONLY on an exact match. It
  rejects (throws `WebRTCError.dtlsHandshakeFailed`, drives the state machine to
  failed, and finishes `incomingChannels`) on mismatch OR when the peer presented
  no certificate. Never add a path that silently accepts an unverified peer. When
  no expected fingerprint is set (identity bound by an upper layer), the handshake
  proceeds and the verified fingerprint is surfaced via `remoteFingerprint`.
- **The verified remote certificate is surfaced, not the negotiated one.**
  `remoteCertificateDER` / `remoteFingerprint` reflect what the peer actually
  presented during the handshake; both are `nil` until the handshake completes.
- **`CertificateFingerprint.fromDigest` never re-hashes.** `fromDER` hashes the DER;
  `fromDigest` wraps an existing SHA-256 digest (e.g. extracted from a `/certhash`
  multihash) verbatim. Do not collapse the two — a hash-of-hash breaks peer
  matching.
- **`WebRTCCertificate.init` is fail-closed on garbage DER.** It parses the DER as
  an `X509.Certificate` before accepting it; unparseable bytes throw.
- **ICE-Lite `validatedPeers` is capped FIFO.** `ICELiteStateMachine`
  (`Sources/ICELiteCore/ICELiteStateMachine.swift`) caps the set at
  `maxValidatedPeers` (1000); admitting a new key past the cap evicts the oldest
  entry (`validatedPeerOrder` is kept in lockstep). The cap bounds memory against a
  spoofed-source-address flood; it does NOT relax authentication. Do not remove the
  cap or let the order array drift from the set.
- **SCTP ordering uses RFC 1982 serial-number arithmetic.** The 32-bit TSN
  (`TSNTracker`) and the 16-bit Stream Sequence Number (`FragmentReassembler`) are
  compared with serial-number arithmetic so wraparound is handled correctly. Do not
  replace these comparisons with plain `<` / `>`.
- **SCTP reassembly/reorder buffers are count- and byte-capped.**
  `FragmentReassembler` (`Sources/SCTPWireCore/FragmentReassembler.swift`) enforces
  `maxPendingFragments` (concurrent groups), `maxBufferedMessagesPerStream`, and a
  total `maxBufferedBytes` ceiling (16 MiB default). Overflow is surfaced as an
  error, not silently dropped. Keep all three caps; they resist memory-exhaustion
  DoS.
- **SCTP hardening holds end to end:** zero-length-chunk DoS is rejected (the chunk
  parser always advances), COOKIE-ECHO replay is rejected, the negotiated inbound
  stream count is enforced, retransmissions are bounded (the association aborts at
  the maximum), and spoofed / reflected-tag ABORTs are discarded (RFC 4960 §8.5).
- **Protocol demultiplexing follows RFC 5764 §5.1.2.** `WebRTCConnection.receive(_:)`
  routes by first byte: `20–63` → DTLS record, `0–3` (plus the `isSTUN` check) →
  STUN. STUN decoding is safe for sliced `Data` (a non-zero `startIndex` does not
  trap or misread).

## Embedded constraints (do not regress)

- **This top-level `WebRTC` module is host-only.** It depends on Foundation,
  swift-crypto, X.509, and swift-asn1 (certificate generation). Only the four
  cores dual-build for Embedded Swift.
- **The Embedded-clean layers are `STUNWireCore`, `ICELiteCore`, `SCTPWireCore`,
  `DataChannelCore`** — value types, no Foundation. Build with
  `P2P_CORE_EMBEDDED=1 swift build --target <Core> -c release`. Do not introduce
  Foundation / `any` / `Mutex` into a `*WireCore` / `ICELiteCore` target; keep
  Foundation and crypto in the `*Core` / adapter layers above them.

## Dependencies & seams

- **swift-tls is referenced by local path on this branch** (`.package(path:
  "../swift-tls")`) so the Tier-1 `TLS` facade (`DTLSClient` / `DTLSServer`) is
  available. This configuration is NOT releasable — it must become a versioned
  dependency before tagging.
- **`SendHandler` is the only egress seam.** The library is transport-agnostic:
  callers inject a send closure and feed inbound bytes via `receive(_:)`. No UDP
  socket is bound inside the library.

## Wire protocol notes

- **SCTP (RFC 4960):** TSN is 32-bit, SSN is 16-bit; both use RFC 1982 serial
  arithmetic. CRC-32C is the packet checksum (validation treats the checksum field
  as zero in place to avoid a copy). DCEP open/ack rides RFC 8831 / 8832.
- **STUN (RFC 5389):** demultiplexed by first byte per RFC 5764 §5.1.2; optional
  MESSAGE-INTEGRITY and FINGERPRINT attributes are handled in the `STUNCore`
  adapter, not the wire core.

## Build

- Host: `swift build` (Swift tools 6.2, platform floor v26). Tests:
  `timeout 60 swift test` (per-module filters in `CLAUDE.md`).
- Embedded cores: `P2P_CORE_EMBEDDED=1 swift build --target STUNWireCore -c release`
  (likewise `ICELiteCore` / `SCTPWireCore` / `DataChannelCore`).
