# SRTP and SRTCP Context

Scope: RFC 3711 `AES_CM_128_HMAC_SHA1_80` key derivation and stateful,
in-place SRTP/SRTCP packet protection inside `Sources/WebRTC/Transport/SRTP`.
This component does not own DTLS exporter labeling, `use_srtp` negotiation, UDP
demultiplexing, RTP codecs, jitter buffers, congestion control, or media
presentation.

Last reviewed: 2026-07-31.

## Boundary and data flow

```text
DTLS exporter
  -> directional master key (16) + master salt (14)
  -> platform composition resolves concrete AES-CM + HMAC-SHA1 operations
  -> RFC 3711 labels 0...5, kdr=0
  -> SRTP component authenticate / replay / in-place transform
  -> authenticated plaintext
  -> RTP/RTCP wire component
```

The RTP/RTCP wire component remains a pure plaintext parser. Network RTP or
RTCP must never reach it or a media sink before the SRTP component
authenticates the packet. The
facade is responsible for selecting local exporter material for outbound keys
and remote exporter material for inbound keys.

## Public contract

- `SRTPPacketProtecting` is the public protocol.
- `AESCM128HMACSHA1SRTPContext` is the concrete implementation.
- `SRTPCryptoContext` is an immutable, non-generic function table assembled by
  the platform composition layer. It supplies a type-erased keyed
  `SRTPAES128CounterModeContext` and segmented incremental HMAC-SHA1.
- Backend selection and associated-type dispatch occur once outside the SRTP
  component's
  packet path. This is the normal-WASM ownership boundary as well as the
  dependency-inversion seam.
- `SRTPMasterKeyMaterial` accepts exactly 16 key bytes and 14 salt bytes.
- All callable failures are typed `SRTPError`; malformed packets,
  authentication failure, replay, old packets, index exhaustion, policy
  rejection, and provider failure never become success values.
- A caller passes one owned `[UInt8]` as `inout`. On a thrown transform error,
  the caller discards the packet because a provider may have partially mutated
  the requested range before returning its typed failure.

## Zero-copy and ownership

- RTP and RTCP packet bodies are never converted to `Array`, `Data`, `String`,
  `Bytes`, or another packet-sized owner by the SRTP component.
- AES-CM mutates the caller's owner in place and only inside the requested
  payload range.
- RTP leaves the complete header, CSRC list, and header extension clear. The
  encrypted range starts at the payload and includes RTP padding.
- SRTCP leaves the first eight bytes clear and encrypts bytes `8..<end`.
- Authentication uses incremental HMAC updates. SRTP supplies the encrypted
  packet followed by the four-byte network-order ROC without concatenating
  them into a packet-sized buffer.
- The HMAC operation borrows the caller's complete `[UInt8]` owner together
  with an authenticated range. Passing that copy-on-write value through the
  synchronous operation does not materialize packet bytes, and the operation
  contract forbids retaining the owner or a view after return.
- The current HMAC seam returns one fixed 20-byte digest allocation. The SRTP
  component truncates it to the leftmost 10 bytes. Appending the protocol trailer may
  grow the caller's owner when it has no tail capacity; callers should reserve
  10 bytes for SRTP or 14 bytes for SRTCP before protection.
- WebRTC exposes those profile-specific sizes through
  `WebRTCMediaProtectionProfile.rtpProtectionTrailerByteCount` and
  `rtcpProtectionTrailerByteCount`. H.264 sender adapters use the RTP value when
  reserving their one-owner packet capacity.
- Performance acceptance must measure packet payload copies and fixed-size
  allocations through the selected provider. The enforced budget is zero
  packet-sized payload copies. Counter words, index words, HMAC state, and the
  20-byte digest remain fixed-size working storage whose allocation count has
  not yet been established as a release claim. A provider that materializes an
  input `Span` internally does not satisfy the packet-copy budget, even though
  the SRTP component itself does not copy it.
- The WebRTC composition adapter resolves the concrete `P2PCrypto.Default*`
  implementation on every target and consumes each packet range by a scoped
  `Span` borrow. Provider suites own the incremental-HMAC
  equivalence checks; the SRTP component additionally verifies that a
  caller-reserved trailer capacity preserves the packet owner's storage address through
  protection.

## State, concurrency, and lifetime

Native, WASM, and Embedded use exactly one
`Synchronization.Mutex<SRTPState>` contract inside the `WebRTC` target. There
is no `hasFeature(Embedded)` or capability branch around storage, `Sendable`,
read, mutation, or release.

`SRTPCryptoContext` and each `SRTPAES128CounterModeContext` are immutable final
owners. Their closures retain concrete keyed crypto owners until the SRTP
context is released. Packet, key, counter, and suffix values are synchronously
borrowed for an operation and are never stored by the injected closure.

| Logical state | Native storage/isolation | WASM storage/isolation | Embedded storage/isolation | Mutation entry point | Release |
|---|---|---|---|---|---|
| Outbound RTP index/pending reservations | `Mutex<SRTPState>` | same | same | `protectRTP` | context lifetime |
| Inbound RTP replay/pending reservations | `Mutex<SRTPState>` | same | same | `unprotectRTP` | context lifetime |
| Outbound SRTCP index/pending reservations | `Mutex<SRTPState>` | same | same | `protectRTCP` | context lifetime |
| Inbound SRTCP replay/pending reservations | `Mutex<SRTPState>` | same | same | `unprotectRTCP` | context lifetime |

The lock contains only bounded dictionary/set/window calculations and commits.
AES and HMAC execute outside it. A reservation prevents two concurrent calls
from using or accepting the same `<SSRC,index>` while crypto is in progress.
Authentication failure cancels the inbound reservation without advancing the
replay window. An authenticated packet commits replay state before decryption,
so plaintext is never exposed before authentication and concurrent duplicates
cannot both succeed. An authenticated SRTCP packet also commits replay state
before an `E=0` policy rejection, so rejected authenticated traffic cannot be
replayed indefinitely as fresh input.

Outbound validation completes before an index reservation. Once AES-CM starts,
any provider or authentication-contract failure burns the reserved RTP or
SRTCP index, even when the provider reports failure after partially mutating
the caller's buffer. No later call can reuse that `<key,SSRC,index>` IV.
Validation failures occur before reservation; any index consumed after that
boundary remains a safe gap. Correctness and nonce uniqueness take priority
over gap-free numbering.

## RFC 3711 profile rules

- Session key labels are SRTP encryption/authentication/salt `0/1/2` and SRTCP
  encryption/authentication/salt `3/4/5`.
- One fixed AES-CM IV protects at most `2^16` blocks (1,048,576 encrypted
  bytes). For `E=1`, a larger encrypted portion is rejected before replay or
  outbound index state changes; `E=0` has no AES-CM encrypted portion.
- The key derivation rate is zero. Session key sizes are 16-byte AES, 20-byte
  HMAC-SHA1, and 14-byte salt.
- SRTP authenticates encrypted RTP bytes followed by network-order ROC and
  truncates HMAC-SHA1 to 80 bits.
- Each SSRC has an independent 48-bit RTP index and 64-packet replay window.
- A plaintext RTP retransmission with an already reserved or committed index is
  rejected. The caller must reuse the already protected datagram.
- SRTCP keeps the first eight RTCP bytes clear, encrypts the remainder, appends
  `E=1 || 31-bit index`, and authenticates the packet plus index.
- SRTCP uses an independent per-SSRC 64-packet replay window. This profile
  requires `E=1`; an authenticated `E=0` packet is a typed policy failure.
- RTP index wrap after `2^48` and SRTCP index wrap after `2^31` are typed
  exhaustion failures. Neither index is silently reused with the same key.

## Verification gates

- RFC 3711 Appendix B.2 AES-CM and Appendix B.3 KDF known-answer fixtures,
  plus cisco/libsrtp commit `2fc078db25bae61ed0a52dc4fdb7dcce6a6ed037`
  `srtp_validate` as an independent full SRTP packet reference fixture.
- RTP round trip, header/range sentinel, padding, tamper, wrong key, truncated
  tag, ROC wrap, replay, too-old, multi-SSRC, exhaustion, and concurrency.
- SRTCP round trip, first-eight-byte sentinel, E/index encoding, tamper, failed
  authentication state invariance, replay, E policy, and exhaustion.
- Native host build and targeted `xcodebuild` tests.
- Normal WASM and Embedded WASM compile, link, and execute the portable
  DTLS-SRTP H.264 round-trip probe under the pinned Swift 6.4 toolchain and
  matching SDK (verified 2026-07-31). Target-local replay and concurrency
  semantics remain unverified until the full SRTP behavior suite executes on
  each platform; the integration probe alone is not a synchronization-semantics
  claim.

## Normative references

- RFC 3711: SRTP, SRTCP, AES-CM, HMAC-SHA1, KDF, indices, and replay.
- RFC 3550: plaintext RTP and RTCP structure (owned by the WebRTC RTP/RTCP
  component).
