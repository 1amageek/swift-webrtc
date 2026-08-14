# WebRTC — CONTEXT
Scope/role: the `WebRTC` library target and transport API (`Sources/WebRTC`) that
integrates STUN/ICE-Lite, DTLS (via the swift-tls Tier-1 facade), SCTP/data
channels, and authenticated RTP/RTCP. Codec framing, packetization, capture,
and presentation remain externally composed.
Last reviewed: 2026-08-05

Invariants and design intent that the code does not state structurally. Read this
before changing the DTLS certificate authentication path, the certificate/fingerprint
ownership, or the SCTP/ICE buffering caps. The protocol stack is `UDP → STUN /
ICE Lite → DTLS 1.2 → SRTP/SRTCP or SCTP → Media/Data Channels`. Internal
protocol boundaries remain domain-oriented source components inside this one
target; pure value engines and caller-locked adapters still preserve their
separate responsibilities. The module's sources are Embedded-seamed
(`FacadeLock` / `AsyncTimer` / logger / certificate gating), and the full
`WebRTC` target is part of the Embedded readiness gate.

## Target DTLS boundary (implemented)

- The stable dependency path is
  `swift-webrtc -> swift-tls/DTLS -> swift-ssl`.
- `swift-webrtc` owns SDP/security generations, ICE/STUN, DTLS role and
  fingerprint binding, timer delivery, SRTP/SRTCP, SCTP/DataChannel, and
  RTP/RTCP. It never owns a general DTLS record or cryptographic implementation.
- `swift-tls` owns the public sans-I/O DTLS session contract, typed effects,
  lifecycle, and capability suspension/resumption. `swift-ssl` owns the
  canonical DTLS wire, transcript, key schedule, record, replay, flight, cookie,
  exporter, authentication, and handshake mechanisms.
- WebRTC DTLS 1.2 is a narrow interoperability profile. Its mechanism belongs in
  `swift-ssl` and its public session profile belongs in `swift-tls`; it must not
  become an implicit general TLS 1.2 fallback.
- The current `DTLSEndpoint` consumes the `swift-tls` facade, whose active
  mechanism targets depend on `swift-ssl`; no duplicate DTLS mechanism remains
  in this target.

See the workspace
[`SECURE_TRANSPORT_ARCHITECTURE.md`](../../../../SECURE_TRANSPORT_ARCHITECTURE.md).

## Contracts (the load-bearing rules)

- **WebRTC owns its DTLS certificate layer locally.** The swift-tls Tier-1
  facade takes a `TLSIdentity` (raw key + DER chain) rather than generating
  certificates, so `WebRTCCertificate` (`Sources/WebRTC/WebRTCCertificate.swift`)
  builds a Pure Swift self-signed ECDSA P-256 leaf when a
  `WebRTCCertificateClock` is available and validates externally provisioned
  DER + raw key material on every target.
  `CertificateFingerprint` computes the SHA-256 fingerprint. Do not push
  certificate ownership down into swift-tls; the fingerprint is WebRTC's unit
  of peer identity and must stay here.
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
- **`WebRTCConnection` thread safety is lock-based, not actor-based.** Internal
  state lives behind `connState.withLock` via the common
  `Synchronization.Mutex`-backed `FacadeLock` on Native, WASM, and Embedded. Keep mutations inside the
  lock; do not hold the lock across an `await`.
- **Retransmission Tasks have one tokenized owner registry.** DTLS flight and
  SCTP T3 Tasks reserve an identity under `TimerTaskRegistry`, create the Task
  outside that mutex, and attach its handle only if the identity is still
  current. Immediate completion or concurrent close removes the placeholder and
  makes attachment fail; an older Task cannot clear its successor. Terminal
  teardown removes both handles under the registry mutex and cancels them after
  releasing it. Task closures retain independent pumps, never the public facade.
- **All deadlines use the injected `WebRTCTimer`.** The same driver reaches DTLS
  flight backoff and SCTP retransmission. Repeated DTLS state with the same
  generation preserves the current deadline; a timeout publishes the next
  generation before retransmitted datagrams leave the flight transaction.
  Cancellation is typed. Close rejects new egress admission; one datagram
  admitted before a concurrent close may finish, while the replaced egress
  epoch suppresses every later datagram in that batch.
- **`claimDataChannelEvents()` is the sole ordered DataChannel event surface.**
  OPEN, application DATA, and CLOSE are committed under the same connection
  transaction, admitted to one bounded queue, and delivered only after the
  connection lock is released. Exactly one claim succeeds and the returned
  `WebRTCDataChannelEventConsuming` owner permits only one suspended `next()`;
  a second claim or overlapping read is a typed failure. Copying the protocol
  existential retains that same owner and cannot create a second iterator.
  The connection staging ring and the consumer ring share one admission budget
  of 1,024 events and 16 MiB of payload by default. Moving an event between
  those rings transfers its existing reservation; it must not reserve twice or
  materialize a second payload owner. Popping a ring slot clears the retained
  owner immediately.
  Terminal finish preserves buffered order so the owner may drain events before
  observing close/failure. An owner that abandons that drain must call
  `discardRemainingEvents()`; it releases every remaining reservation and
  resumes a parked read with the terminal result. The first terminal cause
  committed by the connection is the authoritative result observed by both the
  connection and its consumer, even when close and transport failure race. Do
  not add independent
  channel/message/close callbacks:
  separate surfaces can overtake one another under synchronous transport
  re-entry and lose OPEN-adjacent DATA. Failure to consume the bounded queue is
  terminal and typed; payloads are never silently dropped.
- **Every DataChannel lifecycle has a monotonic local generation.** SCTP stream
  identifiers may be reused only after reset, so DATA and CLOSE events carry
  `(streamID, generation)`. Generation exhaustion fails explicitly and never
  wraps; delayed events from an older lifecycle must not target a reused ID.
- **Protected media uses the DTLS exporter, never DTLS application data.**
  `DTLSEndpoint` negotiates the required `use_srtp` profile and exports RFC 5705
  `EXTRACTOR-dtls_srtp` material. `WebRTCConnection` maps client/server key
  directions into one SRTP context; RTP and RTCP handlers are downstream
  of authentication, replay protection, decryption, and wire validation.
- **Codec implementations do not become WebRTC dependencies.** `WebRTCMedia`
  depends on `WebRTC` for RTP contracts, while `WebRTC` has no dependency on
  `WebRTCMedia`. Its H.264 sender's typed sink may call `sendRTP`, but the
  transport API must also accept other negotiated RTP codecs without an H.264
  dependency.
- **Protected media transfers one owner through the facade.** `receive` consumes
  the UDP array, the SRTP component authenticates/decrypts it in place, and the RTP/RTCP
  packet consumes that same storage into its handler. Reserved outbound RTP and
  SRTCP likewise retain their owner through in-place protection and the
  consuming transport callback. Storage-identity tests guard all four paths.
  This guarantee ends at the WebRTC/TLS dependency boundary: the swift-tls
  facade establishes one owned datagram before its mutex transaction, then
  passes that owner into the engine without a second packet-sized copy.
- **Media close is an admission boundary, not a quiescence barrier.** Handler
  lookup and terminal detachment share `mediaHandlerState`; callbacks run after
  that mutex is released. Terminal detachment also disables future handler
  installation, which returns `.failure(.closed)` without retaining the
  callback. A callback admitted before the detach may finish after `close()`
  returns. This permits callback-reentrant close without waiting on itself.

## Invariants (must hold; tests guard them)

- **DTLS certificate fingerprint authentication is fail-closed.**
  `WebRTCConnection.onHandshakeComplete()` (`Sources/WebRTC/WebRTCConnection.swift`)
  computes the peer fingerprint from `DTLSEndpoint.remoteCertificateDER` and, when
  an `expectedFingerprint` is configured, accepts ONLY on an exact match. It
  rejects (throws `WebRTCError.dtlsHandshakeFailed`, drives the state machine to
  failed, and finishes the claimed DataChannel event stream) on mismatch OR when the peer presented
  no certificate. Never add a path that silently accepts a mismatch. When no
  expected fingerprint is set, the existing data-channel handshake proceeds so
  an upper layer can bind identity, but protected media MUST remain unavailable
  until that explicit binding occurs.
- **Presented certificate bytes and verified identity are distinct.**
  `remoteCertificateDER` snapshots what the peer presented when the handshake
  completes, so terminal lease failure is never collapsed into an absent
  certificate after close.
  `remoteFingerprint` is populated only after it matches a configured expected
  fingerprint; it remains `nil` when identity binding is deferred upward.
- **`CertificateFingerprint.fromDigest` never re-hashes.** `fromDER` hashes the DER;
  `fromDigest` wraps an existing SHA-256 digest (e.g. extracted from a `/certhash`
  multihash) verbatim. Do not collapse the two — a hash-of-hash breaks peer
  matching.
- **`WebRTCCertificate.init` is fail-closed on malformed credentials.** Darwin
  parses the DER as an `X509.Certificate`; portable targets parse the required
  SubjectPublicKeyInfo and prove that the raw private scalar matches it. Every
  target computes the fingerprint via `DefaultSHA256`; no identity is fabricated.
- **ICE-Lite `validatedPeers` is capped FIFO.** `ICELiteStateMachine`
  (`Sources/WebRTC/Connectivity/ICE/ICELiteStateMachine.swift`) caps the set at
  `maxValidatedPeers` (1000); admitting a new key past the cap evicts the oldest
  entry (`validatedPeerOrder` is kept in lockstep). The cap bounds memory against a
  spoofed-source-address flood; it does NOT relax authentication. Do not remove the
  cap or let the order array drift from the set.
- **SCTP ordering uses RFC 1982 serial-number arithmetic.** The 32-bit TSN
  (`TSNTracker`) and the 16-bit Stream Sequence Number (`FragmentReassembler`) are
  compared with serial-number arithmetic so wraparound is handled correctly. Do not
  replace these comparisons with plain `<` / `>`.
- **SCTP reassembly/reorder buffers are count- and byte-capped.**
  `FragmentReassembler` (`Sources/WebRTC/DataChannel/SCTP/FragmentReassembler.swift`) enforces
  `maxPendingFragments` (concurrent groups), `maxBufferedMessagesPerStream`, and a
  total `maxBufferedBytes` ceiling (16 MiB default). Overflow is surfaced as an
  error, not silently dropped. Keep all three caps; they resist memory-exhaustion
  DoS.
- **SCTP hardening holds end to end:** zero-length-chunk DoS is rejected (the chunk
  parser always advances), COOKIE-ECHO replay is rejected, the negotiated inbound
  stream count is enforced, retransmissions are bounded (the association aborts at
  the maximum), and spoofed / reflected-tag ABORTs are discarded (RFC 4960 §8.5).
- **SCTP and DataChannel state commit before external I/O.** Packet processing,
  reciprocal reset state, DCEP state, and event-queue admission are one transaction.
  The canonical event queue drains before response datagrams are emitted, and both
  operations occur outside the connection mutex. This preserves OPEN/DATA/CLOSE
  order even when `SendHandler` synchronously re-enters `receive(_:)`.
- **Protocol demultiplexing follows RFC 7983.** `WebRTCConnection.receive(_:)`
  routes by first byte: `20–63` → DTLS record, `0–3` (plus the `isSTUN` check) →
  STUN, and `128–191` → the protected-media boundary. RFC 5761 then separates
  RTP from RTCP. Neither kind reaches the internal RTP/RTCP parser or an
  external handler until the SRTP component authenticates, checks replay state,
  and decrypts it.
  STUN decoding is safe for sliced `Data` (a non-zero `startIndex` does not trap
  or misread).
- **DTLS establishment is not media readiness.** Media configuration requires a
  signaling-bound expected fingerprint. The local swift-tls integration must
  also negotiate the configured extension 14 (`use_srtp`) profile and export
  directional RFC 5705 material before `isMediaReady` becomes true. Never route
  RTP/RTCP through DTLS application data.

## Embedded constraints (do not regress)

- **The full `WebRTC` facade must Embedded-compile.** The facade files
  (`WebRTCConnection` / `WebRTCEndpoint` / `WebRTCListener` / `WebRTCCertificate`)
  route their host-only deps through build-gated seams: common `FacadeLock`
  (`Synchronization.Mutex` on every supported platform), `WebRTCDefaultTimer` (the `AsyncTimer` seam — host
  `ContinuousAsyncTimer`, `WASIAsyncTimer`, or `POSIXAsyncTimer`; drives both
  DTLS flight and SCTP T3-rtx scheduling), `WebRTCLogger`
  (host swift-log / Embedded no-op),
  and the common `SSLCrypto.SHA256` certificate fingerprint path. Do not introduce target-specific state isolation /
  `Task.sleep` / `ContinuousClock` / `Logging.Logger` into the facade.
- **Pure Swift identity generation is shared by every target.**
  `WebRTCCertificate.generateSelfSigned` builds a v3 ECDSA P-256 leaf with the
  `SSLASN1` writer and `SSLCrypto` provider. The same `[UInt8]` certificate and
  raw scalar representation is used on Native, WASI, and Embedded. Its wall
  clock is an injectable `WebRTCCertificateClock`, so Embedded deployments can
  use an RTC without importing a platform clock into the facade. If no clock is
  available, generation fails with `.clockUnavailable`. Deployments that
  provision identity material externally can use
  `init(derEncoded:rawPrivateKey:)`; the initializer validates the certificate
  envelope, imports both keys, and fails closed on a mismatch. The fail-closed
  DTLS fingerprint verification is preserved on every build.
- **The adapter components are dual-built, not host-only.** STUN, ICE, SCTP,
  and DataChannel hold Embedded-clean value engines behind `FacadeLock` and
  route crypto/random/clock work through seams. Host-only `Data` conveniences
  are gated out under Embedded; the `[UInt8]` surface remains available.
- **Foundation-free protocol code remains isolated by domain directory.**
  `Connectivity/{ICE,STUN}`, `DataChannel/SCTP`, and `Transport/{RTP,SRTP}`
  live inside the `WebRTC` target; H.264 framing and packetization live in the
  separate `WebRTCMedia` target. Do not introduce Foundation, existential
  erasure, or target-specific synchronization into borrowed wire paths, and do
  not bypass the crypto/random/clock seams used by the stateful adapters.

## Dependencies & seams

- The Tier-1 `TLS` facade (`DTLSClient` / `DTLSServer`) is consumed from
  `swift-tls`. The release manifest resolves published versions of
  `swift-networking`, `swift-ssl`, and `swift-tls`.
- Certificate generation and validation use `swift-ssl`'s Pure Swift
  cryptography, ASN.1, and X.509 modules. The WebRTC manifest has no Darwin-only certificate trait or
  platform-specific crypto dependency; the package declares no traits and does
  not need trait flags to select the identity contract.
- The internal SRTP component owns RFC 3711 key derivation, in-place
  transforms, indices, and replay windows. The surrounding `WebRTC`
  orchestration owns negotiation, exporter direction mapping, demultiplexing,
  plaintext wire parsing, and handler delivery.
- **`SendHandler` is the only egress seam.** The library is transport-agnostic:
  callers inject a send closure and feed inbound bytes via `receive(_:)`. No UDP
  socket is bound inside the library.

## Wire protocol notes

- **SCTP (RFC 4960):** TSN is 32-bit, SSN is 16-bit; both use RFC 1982 serial
  arithmetic. CRC-32C is the packet checksum (validation treats the checksum field
  as zero in place to avoid a copy). DCEP open/ack rides RFC 8831 / 8832.
- **STUN (RFC 5389):** demultiplexed by first byte per RFC 5764 §5.1.2; optional
  MESSAGE-INTEGRITY and FINGERPRINT attributes are handled in the stateful STUN
  adapter, not the pure wire parser.

## Outbound H.264 composition

```text
encoded access-unit owner
  -> WebRTCMedia ByteStream borrowed NAL ranges
  -> WebRTCMedia RTP/Payload RFC 6184 layouts
  -> WebRTCMedia RTP one-owner plaintext packet with SRTP tail capacity
  -> WebRTCMedia sender typed sink
  -> WebRTCConnection.sendRTP
  -> WebRTC SRTP in-place protection
  -> SendHandler
```

The profile's `rtpProtectionTrailerByteCount` is the source of truth for the
sender reserve. Sequence/timestamp state belongs to the `WebRTCMedia` sender,
not the `WebRTC` transport. Packet pacing, UDP backpressure, and send ordering
belong to the adapter surrounding its synchronous sink.

## Build

- Native tests use `TOOLCHAINS=org.swift.64202607231a xcodebuild test` with the
  Xcode scheme and an explicit execution timeout.
- Normal and Embedded WASM use the exact 2026-07-23 Swift 6.4 toolchain and
  matching SDK identifiers shown in `CLAUDE.md`. Both run the Tests-contained
  `WebRTCPlatformIntegrationProbe` with `--build-system swiftbuild`; both
  select the same `swift-ssl` cryptographic backend.
- The pinned Embedded compiler requires `-debug-info-format none` for this
  executable-only async probe because its DWARF emitter asserts on conflicting
  frame locations. Release optimization remains enabled for library targets.
- The probe completes mutual in-memory DTLS, negotiates `use_srtp`, derives the
  exporter keys, performs an authenticated SRTP H.264 byte round trip, verifies
  typed transport rejection, and observes timer heartbeat/cancellation. It is
  not real UDP, browser interoperability, target-parallel Mutex validation, or
  a production event-loop timer claim.
- The platform default timer is supplied by `swift-networking`: continuous time
  on Native, WASI time on WASI, and POSIX time where the Embedded platform
  provides POSIX. A board integration with a different runtime should inject an
  event-loop-integrated `WebRTCTimer`.
