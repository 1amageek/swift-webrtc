# H.264 RTP Payload — CONTEXT

Last reviewed: 2026-07-30.

Scope: Foundation-free RFC 6184 payload validation, packetization planning, and
direct encoding for Single NAL unit packets, STAP-A, and FU-A. Packetization
modes 0 and 1 are supported. Mode 2 is an explicit typed unsupported result.

This component does not own RTP headers, sequence numbers, timestamps, SSRCs,
SRTP, RTCP feedback, jitter buffering, fragment reassembly, codecs, I/O, or
Jetson/Apple adapters.

## Ownership and zero-copy contract

- The caller owns access-unit and inbound-payload bytes.
- Packetization accepts borrowed bytes plus borrowed NAL-unit range metadata.
- Packetization emits scalar/range layouts synchronously and creates no payload
  container or array of fragment bytes.
- `traversePackets` lets the callback return `.stop` and reports `.stopped`
  without visiting later layouts. `forEachPacket` is the compatibility traversal
  that always returns `.proceed` internally.
- Inbound parsing returns scalar/range layouts and never retains a `Span`, raw
  pointer, or owner reference.
- STAP-A iteration re-scans validated length fields and emits ranges through a
  synchronous callback instead of allocating a range array.
- Packetization validates the complete access unit and packetization
  feasibility before the first callback. A typed failure emits no layouts;
  intentional short-circuiting is an explicit outcome rather than a failure.
- Encoding appends source bytes directly into one caller-owned final buffer
  through one scoped contiguous buffer operation. This network-boundary
  materialization is the only payload copy in this component; byte-at-a-time
  payload appends are a performance regression.
- Encoding validates the supplied layout before reserving or mutating its
  destination. A typed validation failure leaves the destination unchanged.
- `Data`, `Bytes(Span)`, `Array(slice)`, and payload concatenation are forbidden
  on parser and packetization paths.

```text
caller-owned access unit
    -> range-only packet layouts
        -> caller-owned final RTP packet buffer

caller-owned inbound RTP payload
    -> range-only Single NAL / STAP-A / FU-A layout
```

## Input format

NAL ranges must refer to naked H.264 NAL units including their one-byte NAL
header. The `H264/ByteStream` component can remove Annex B start codes or AVCC
length prefixes before this component is called. Supplying a range
that begins at a start code fails as a reserved NAL type rather than being
silently normalized.

## RFC 6184 rules

- Mode 0 emits and accepts Single NAL unit packets only.
- Mode 1 emits and accepts Single NAL unit packets, STAP-A, and FU-A only.
- Mode 2, STAP-B, MTAP16/24, and FU-B are not silently mapped to mode 1.
- STAP-A preserves NAL order, uses 16-bit network-order lengths, sets NRI to
  the maximum contained NRI, and never nests aggregation or fragmentation units.
- FU-A excludes the original NAL header from fragment bytes and transports its
  F/NRI/type fields through the FU indicator and header.
- Outbound FU-A fragments are non-empty and cover every source byte after the
  original NAL header exactly once. Inbound empty FU payloads remain valid as
  permitted by RFC 6184; reassembly limits belong to a higher layer.
- Inbound parsing describes one RTP payload only. It does not join FU-A
  fragments or reconstruct a decoded/access-unit owner.

## Performance budget

| Path | Budget |
|---|---|
| Packetization planning | zero payload copies; zero payload-sized allocations |
| Short-circuit traversal | zero payload copies; stops before later layout callbacks |
| Single/FU-A parse | zero copies; zero heap allocations |
| STAP-A parse/iteration | zero copies; zero metadata arrays |
| Payload encode | one scoped contiguous append into caller owner; source bytes copied once |

Timing alone does not prove these budgets. Completion requires source audit plus
Native tests and normal/Embedded WASM compilation with the pinned Swift 6.4
toolchain and matching SDK.

The current focused Native suite passes 24/24. The dedicated performance gate
compares 4 KiB and 64 KiB contiguous materialization against a scalar reference.
The sender-integrated normal and Embedded WASM probes both exercise the
contiguous traversal path successfully.

## Normative reference

- RFC 6184: H.264 packetization modes, Single NAL units, STAP-A, and FU-A.
