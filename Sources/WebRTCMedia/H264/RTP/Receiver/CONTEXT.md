# H.264 RTP Receiver Context

## Scope

The `WebRTCMedia/H264/RTP/Receiver` component owns the stateful, bounded
conversion from one negotiated
plaintext H.264 RTP stream into decoder-bound access units. It owns sequence
reordering, gap deadlines, loss quarantine, RFC 6184 Single NAL/STAP-A/FU-A
reconstruction, and synchronous consuming delivery.

It does not own UDP, ICE, DTLS, SRTP authentication, RTCP feedback, codec
decoding, rendering, or signaling. The caller must authenticate and decrypt an
SRTP packet before passing its owner and `RTPPacketLayout` here.

```text
authenticated plaintext RTP owner
    -> owner/layout reparse
    -> bounded sequence reorder
    -> loss quarantine
    -> range-only access-unit plan
    -> exact allocation + bulk copy outside Mutex
    -> consuming decoder sink
```

## Ownership and copy budget

- `receive` consumes one `[UInt8]` packet owner.
- Reordering and assembly retain that owner plus checked byte ranges; media
  payload is not copied while an access unit is incomplete.
- A completed access unit performs one direct copy of every media byte into one
  exact-size contiguous `[UInt8]` owner. Prefix bytes and reconstructed FU-A
  headers are initialized in that owner.
- No intermediate `Data`, payload array, fragment array, or growing output media
  buffer is permitted on this path.
- Materialization and the consuming sink run outside `Mutex<State>`.
- Sink success accepts ownership. Sink failure rejects the current owner, drops
  queued packet owners explicitly, and reports those effects.

The unsafe materialization boundary documents owner retention, ranges,
initialization, alignment, and pointer lifetime in
`H264RTPAccessUnitPlan.materialized(format:)`. Differential fixtures cover
Single NAL, STAP-A, FU-A, Annex B, and AVCC output.

## Loss and boundary policy

- RTP marker is an early access-unit boundary signal, not the only boundary.
  A timestamp transition also completes a valid non-fragmented unit.
- A packet after a marker with the same timestamp is a typed stream violation.
- A declared gap discards any active unit and always quarantines the first
  timestamp observed after the gap. This accounts for a missing packet that may
  have been the first packet of that timestamp.
- A stateful reassembly error quarantines the failed packet's timestamp.
- Sequence distance is interpreted in the forward half-space `0..<32768`.
  Distance `32768` is deterministically late/ambiguous. An SSRC restart requires
  a newly negotiated receiver session; it is not inferred from unauthenticated
  sequence jumps.
- Under reorder pressure, recovery starts from the earliest retained forward
  packet. Any far-future packet evicted to preserve the configured byte bound is
  reported by count and byte count.

## Bounds

Configuration independently bounds:

- one RTP packet;
- decoder-bound access-unit bytes;
- retained input packet bytes for an active access unit;
- packets and NAL metadata per access unit;
- access-unit assembly duration;
- reorder packet count, retained bytes, and gap duration.

Completed units are delivered one at a time, so there is no internal ready-unit
queue whose count can cause a valid burst to be discarded.

## Failure contract

- Owner/layout, RTP, payload type, SSRC, and RFC 6184 validation failures are
  typed `H264RTPReceiverError` values.
- Failures after state progress return `receiverAfterProgress` with all observed
  effects.
- Sink failure returns the typed sink error and the delivery, reconstruction,
  discard, and buffering effects.
- No malformed, incomplete, timed-out, or quarantined unit is returned as a
  successful access unit.

## Shared-state matrix

| Target | Storage | Isolation | Read/mutation entry | Release |
|---|---|---|---|---|
| Native | `State` | `Mutex<State>` | `receive` / `advanceTime` | owner release or sink transfer |
| WASM | `State` | `Mutex<State>` | same | same |
| Embedded WASM | `State` | `Mutex<State>` | same | same |

There is no `hasFeature(Embedded)` synchronization branch. Target differences
belong to the linked platform implementation of `Synchronization.Mutex`.
