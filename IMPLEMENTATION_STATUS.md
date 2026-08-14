# Implementation Status

Last updated: 2026-08-14.

This file tracks observable implementation behavior. Declarations, successful
type checking, or DTLS certificate authentication alone do not satisfy media
milestones.

## Library layout

The package publishes two products backed by two Swift library targets:

```text
WebRTCMedia
    H.264 framing / RFC 6184 / sender / receiver
        -> WebRTC
            STUN / ICE / DTLS / SCTP / DataChannel / RTP / RTCP / SRTP
```

Protocol components remain separated by source directory and focused test
target. They are not independently importable implementation modules. The
target consolidation itself is not behavioral completion evidence; all
milestone claims still require the tests and runtime probes named below.

The consolidation also removes access modifiers that existed only for
cross-target implementation calls. The internal subsystem directories now
contain 21 top-level public types instead of 121. Those 21 close the signatures
of the facade DTOs, typed failures, and read-only RTP/RTCP layouts. STUN codecs,
ICE state machines, SCTP engines, RTP classifiers/parsers, and SRTP contexts
are internal. Package visibility is limited to the RTP operations consumed by
`WebRTCMedia`.

An external-package fixture verifies both products together and
`WebRTCMedia` as the only declared product dependency. Negative compile probes
verify that `DataChannelManager`, `RFC3550RTPPacketParser`, and the removed
`RTPWireCore` module are not externally reachable.

## Milestones

| Milestone | Status | Completion evidence | Remaining gate |
|---|---|---|---|
| M0 — Swift 6.4 and common state isolation | Implemented and verified on the published dependency graph; target-parallel runtime validation remains | Native facade, ordered DataChannel events, SRTP, sender/receiver state, and the tokenized DTLS/SCTP Task registry use `Synchronization.Mutex` on every supported platform. Native and both portable runtime probes pass with the exact snapshot and tagged dependencies | Linux runtime, real target-parallel Mutex stress, and production event-loop timer integration |
| M1 — RTP/RTCP wire path | Implemented across the published probe graph | The internal WebRTC RTP/RTCP component parses RTP by borrowed `Span`, validates compound/reduced RTCP, enforces bounded metadata, classifies RTP/RTCP mux, and directly appends headers; Native wire tests pass 30/30, the payload-size regression gate passes, and both portable probes parse sender output | Real UDP integration |
| M2 — Protected media transport boundary | Implemented across the published in-memory probe graph | RFC 7983/RFC 5761 media datagrams enter the internal WebRTC SRTP component before parsing or delivery; unauthenticated, replayed, and malformed packets are dropped. Native integration verifies the protected boundary and owner identity; normal/Embedded probes complete mutual DTLS and authenticated SRTP H.264 reconstruction | Real UDP plus browser/native interoperability |
| M3 — DTLS-SRTP negotiation and exporter | Implemented and integrated with published dependencies | `swift-tls` negotiates `use_srtp`, requires the configured profile, exports RFC 5705 keying material, maps client/server directions, and advances repeated record epochs with bounded retained-flight keys; the versioned Native and portable probe graphs complete the negotiated media path | External browser/native interoperability |
| M4 — SRTP/SRTCP | Implemented for AES_CM_128_HMAC_SHA1_80 across the current probe graph | RFC 3711 KDF/AES-CM/HMAC-SHA1-80, ROC, per-SSRC replay windows, SRTCP index, nonce-burn failure handling, size limits, concurrency tests, and an independent libSRTP packet fixture; Native tests pass 32/32 and both portable probes execute SRTP | Explicit session rekey orchestration, an independent full SRTCP fixture, and real network loss/reorder validation |
| M5 — H.264 send/receive path | Implemented in memory; network feedback pending | The `WebRTCMedia` target contains internal components for borrowed parsing, range-only packetization, one-owner RTP assembly, bounded sequence/timestamp policy, and typed partial delivery. The receiver reparses owner/layout identity, bounds reorder and active-unit memory/time, conservatively quarantines loss, retains range-only packet plans, bulk-materializes one exact owner outside `Mutex`, and delivers units incrementally. Focused Native results are 6/6, 24/24, 3/3, 9/9, and receiver 36/36; Native/normal WASM/Embedded WASM probes execute a real sender-to-receiver byte round trip | NACK/PLI, pacing, measured recovery, real UDP, and decoder/browser interoperability |
| M6 — Jetson to Mac integration | Not started | No Jetson camera/encoder adapter, socket transport, or real stream is present in this package | Hardware encoder ownership, UDP/signaling integration, complete WebRTC/browser interop, Pose correlation, and copy/allocation/latency measurements |
| M7 — Lume integration | Not started | No OpenVision, ActionRecognition, Interaction, or Lume dependency is present | Keep product policy outside this transport package; verify the complete camera-to-Lume path in its integration repository |

## Shared-state review matrix

| Logical state | Native storage/isolation | WASM storage/isolation | Embedded storage/isolation | Read/mutation entry | Shutdown/release |
|---|---|---|---|---|---|
| WebRTC connection state | `SharedMutex<ConnState>` | same storage and isolation | same storage and isolation | connection transactions use `withLock` | terminal teardown releases protocol owners after committing terminal state |
| WebRTC egress leases and terminal phases | fields in `SharedMutex<ConnState>` | same storage and isolation | same storage and isolation | admission, epoch validation, in-flight count, terminal token, and teardown phases mutate in one connection transaction; crypto/transport run after unlock | close replaces the epoch and waits for in-flight leases; one already-admitted datagram may finish, while later batch datagrams are suppressed |
| Media handler registry | `SharedMutex<MediaHandlers>` | same storage and isolation | same storage and isolation | handler install, lookup, permanent detach, and registration rejection use `withLock`; callbacks run after unlock | terminal teardown disables installation and releases both handlers; one already-admitted callback may finish after close |
| DTLS/SCTP deadline Task ownership | `TimerTaskRegistry` over `Mutex<State>` plus `DTLSTimerPublication` over `Mutex<UInt64>` | same storage and isolation | same storage and isolation | Task handles reserve/attach/clear by identity; timer creation, cancellation, sleep, and protocol I/O remain outside locks | removes both Task handles under lock and cancels them after unlock |
| DTLS engine transaction | `DTLSFlightCoordinator` over `Mutex<Void>` | same storage and isolation | same storage and isolation | serializes synchronous DTLS flight mutation; timeout reconciliation is returned as a value | no Task or facade ownership; terminal endpoint close is separately gated by drained egress leases and terminal phases |
| Endpoint registry | `Mutex<EndpointState>` | `Mutex<EndpointState>` | `Mutex<EndpointState>` | `withLock` | closes retained connections |
| Listener registry/stream | `Mutex<ListenerState>` | `Mutex<ListenerState>` | `Mutex<ListenerState>` | `withLock` | finishes continuation and closes connections |
| ICE agent | `Mutex<AgentState>` | `Mutex<AgentState>` | `Mutex<AgentState>` | `withLock` | closes state machine |
| SCTP association | `Mutex<SCTPAssociationStorage>` owning one engine | same storage and isolation | same storage and isolation | `withLock` through the storage owner | owner release after connection shutdown |
| Data channel manager | `Mutex<ManagerState>` | `Mutex<ManagerState>` | `Mutex<ManagerState>` | `withLock` | explicit `shutdown()` |
| Ordered DataChannel event staging/consumer/budget | `Mutex<ChannelState>` + `Mutex<ConsumerState>` + shared `Mutex<BudgetState>` | same storage and isolation | same storage and isolation | reserve count/bytes once; move the payload owner through bounded rings; `next()` permits one suspended read | close/failure drains both rings, releases every reservation, and resumes the parked read exactly once with the authoritative terminal cause |
| WebRTC RTP/RTCP wire component | no shared state | no shared state | no shared state | borrowed pure parser | owner retained by caller |
| WebRTCMedia byte-stream framing component | no shared state | no shared state | no shared state | borrowed parser + caller-owned range scratch | owner retained by caller |
| WebRTCMedia RFC 6184 / RTP assembly components | no shared state | no shared state | no shared state | borrowed planning/parsing; one final packet allocation | owner transferred to caller |
| H264 sender sequence/timestamp | `Mutex<State>` | `Mutex<State>` | `Mutex<State>` | bounded reservation through `withLock`; assembly/sink outside lock | session lifetime |
| H264 receiver reorder/assembly | `Mutex<State>` | `Mutex<State>` | `Mutex<State>` | owner/range planning through `withLock`; exact materialization/sink outside lock | packet owners released on completion, typed failure, or sink rejection |
| SRTP/SRTCP indices and replay windows | `Mutex<SRTPState>` | `Mutex<SRTPState>` | `Mutex<SRTPState>` | reserve/commit/cancel through `withLock`; crypto outside lock | context lifetime; connection releases context on shutdown |

For every row above, I/O, external callbacks, event delivery, and suspension
remain outside the mutex critical section. H.264 packet assembly also occurs
outside its state mutex. SCTP deliberately validates, assembles, and atomically
commits one bounded packet batch while holding its association mutex.

## Verified toolchain matrix

These rows record the latest successful behavioral runs against the public URL
dependency graph: `swift-networking` 0.1.0, `swift-ssl` 0.3.0, and `swift-tls`
2.0.1. Directory structure or successful type checking is not a substitute.

| Target | Toolchain / SDK | Versioned release graph result |
|---|---|---|
| macOS Native | Xcode 27.0 (`27A5209h`), toolchain `org.swift.64202607231a`, compiler `ef761e567dc94ee` | 520 logical tests across 13 targets pass with 0 failures and 0 skips. The same behavior is covered by split Address Sanitizer runs with no sanitizer finding. Three opt-in Release benchmark runs also pass |
| WASM | Swift 6.4 development snapshot 2026-07-23 + SDK `swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm` | Release compile/link succeeds and the runtime executable passes external identities, mutual DTLS, `use_srtp`, exporter directions, typed transport rejection, timer heartbeat/cancellation, and authenticated H.264 byte reconstruction. It uses in-memory datagram exchange, not UDP |
| Embedded WASM | Swift 6.4 development snapshot 2026-07-23 + SDK `swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded` | Release compile/link succeeds and the runtime executable passes the same in-memory graph. It proves target runtime behavior but not target-parallel Mutex semantics; production integration should inject an event-loop-integrated timer |

## Performance and ownership audit

```text
H.264 borrowed owner
    -> one required bulk materialization into final RTP owner
        -> in-place SRTP -> consuming transport

protected UDP owner
    -> in-place SRTP/SRTCP -> same owner at RTP/RTCP handler
```

- Reserved outbound RTP and SRTCP retain their base address through the
  transport admission callback.
- Inbound protected RTP and RTCP retain their base address through
  authentication, decryption, parsing, and handler delivery.
- H.264 final payload materialization uses one scoped contiguous append. The
  three-run Release median measures 4 KiB at 73.22 ns versus 10,169.94 ns
  scalar and 64 KiB at 773.93 ns versus 164,028.64 ns scalar.
- RTP header-extension materialization uses the same scoped bulk-copy boundary.
- The three-run Release RTP parser median measures 12-byte, 1,200-byte, and
  65,535-byte packets at 12.798 ns, 12.790 ns, and 12.783 ns respectively; the
  normalized payload slope remains effectively flat at -0.000408.
- The swift-tls Tier-1 facade makes one required owner copy when a borrowed
  `Span` crosses the mutex transaction, then passes that owner into the engine
  without a second packet-sized materialization. Native hash/HMAC updates retain
  direct Span borrowing. The pinned WASM snapshot requires one owner copy at
  each Pure Swift hash/HMAC update because its generic unsafe-buffer witness
  cannot execute reliably; the closed statically-dispatched WASI backend records
  that platform constraint and passes SHA-1/SHA-256/SHA-384 KATs on normal and
  Embedded WASM.
- SCTP retransmission currently re-encodes its plaintext packet. An encoded
  packet cache requires a separate retained-memory and loss benchmark before
  changing that ownership model.

## Completed SCTP protocol behavior

No known callable SCTP or DataChannel branch remains marked as an incomplete
implementation. The former release-visible gaps now have concrete behavior:

| Contract | Implemented behavior | Native behavioral evidence |
|---|---|---|
| RFC 3758 FORWARD-TSN receive | Negotiates the INIT/INIT-ACK parameter, advances the cumulative TSN point, discards incomplete fragments, releases ordered messages stranded behind skipped SSNs, completes deferred resets, and SACKs stale FORWARD-TSN chunks | Focused receive/reset/reorder tests |
| RFC 3758 sender partial reliability | Supports per-message maximum-retransmission and timed policies, atomically abandons all fragments, emits/retransmits bounded FORWARD-TSN chunks, preserves F5 congestion responses, and never credits abandoned bytes to `cwnd` | 10 sender tests covering loss, expiry, fragmentation, negotiation, ordering, retry limits, transactional rollback, and congestion accounting |
| RFC 6525 send during reset | Accepts messages into a bounded immutable-owner queue without assigning TSN/SSN, then releases them FIFO after the terminal reset result; success resets SSN, denial preserves SSN, expiry consumes no sequence space, and shutdown drains accepted owners | 5 reset-queued send tests |
| WebRTC DataChannel policy | DCEP reliable/rexmit/timed channel types round-trip into immutable channel descriptors and the selected SCTP send policy | 25 DCEP/DataChannel manager tests |

RFC 9260 unknown-parameter action bits are implemented on both INIT and
INIT-ACK. Reportable parameter TLVs are preserved, INIT reports are encoded as
type-8 Unrecognized Parameter values, INIT-ACK reports are bundled after
COOKIE-ECHO as cause-8 ERROR chunks when they fit the active path budget, and
all four action-bit combinations have direct tests.

## Media readiness rule

`DTLS established` is not the same as `media ready`. The connection installs a
media protector and permits protected-media send/receive only after all of the
following are true:

1. the peer certificate fingerprint supplied by signaling is verified;
2. DTLS negotiated a supported `use_srtp` profile;
3. exporter key material was split into verified local and remote directions;
4. SRTP/SRTCP contexts are active with replay protection;

An inbound packet is delivered only after a fifth per-packet condition:
SRTP/SRTCP authentication and replay checks succeed, followed by successful
plaintext decoding in the internal WebRTC RTP/RTCP wire component.

## H.264 media readiness rule

The H.264 sender path is usable only when its caller supplies all platform and
session responsibilities that deliberately remain outside these products:

1. an encoded access-unit owner that remains alive and immutable for the call;
2. its actual framing format (`Annex B` or the correct AVCC length width);
3. a monotonic capture timestamp in nanoseconds;
4. signaling-selected payload type, SSRC, packetization mode, and datagram limit;
5. the negotiated profile's RTP trailer size;
6. a typed sink that accepts ownership or reports failure.

Successful in-memory sender-to-receiver reconstruction proves packetization and
reassembly, not playback. Loss feedback, pacing, UDP transport, codec output,
and Lume behavior remain separate acceptance gates.

## Release integration

The release manifest uses only public URL dependencies and follows this
dependency direction:

```text
swift-networking + swift-ssl
    -> swift-tls
        -> swift-webrtc
```

No local `.package(path:)` reference remains in the release manifest. The
complete verification matrix above was rerun from the published graph. Release
publication must still verify that the tag commit equals `origin/main`.
