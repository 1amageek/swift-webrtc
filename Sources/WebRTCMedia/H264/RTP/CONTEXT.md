# H.264 RTP Assembly — CONTEXT

Last reviewed: 2026-07-30.

Scope: stateless composition of `WebRTC` RTP headers and the
`WebRTCMedia/H264/RTP/Payload` component's RFC 6184 layouts into one
caller-owned plaintext RTP packet.

This component does not parse Annex B/AVCC, own codec buffers, assign sequence
numbers or timestamps, maintain an RTP session, perform SRTP, send network
datagrams, or know about Jetson/Apple capture APIs. Those responsibilities
remain in adapters and session owners.

## Ownership and copy contract

```text
borrowed access-unit bytes + borrowed NAL ranges
    -> range-only RFC 6184 layout
        -> one caller-owned RTP packet allocation
            -> downstream SRTP mutates payload and appends its trailer in place
```

- RTP header bytes are generated directly in final packet storage.
- H.264 source bytes are copied exactly once into that storage because the
  network datagram must own a contiguous payload.
- `protectionTrailerByteCount` reserves space in the same owner for downstream
  SRTP authentication data; it is included in the maximum datagram check.
- The RTP marker bit is derived from
  `H264RTPPacketizationLayout.isLastPacketOfAccessUnit`.
- A packet larger than the configured datagram limit is a typed failure before
  payload materialization.
- `maximumDatagramByteCount` covers the complete protected RTP datagram: RTP
  header, H.264 payload, and reserved SRTP trailer. It excludes UDP/IP headers.
- The assembler owns no session state. The `H264/RTP/Sender` component is the
  higher layer that
  reserves sequence numbers, maps capture time to the 90 kHz clock, and sends
  packet owners through a typed sink.

## Platform contract

The component is Foundation-free and uses the same implementation inside the
`WebRTCMedia` target on Native, normal WASM, and Embedded WASM. It owns no
mutable shared state and therefore requires no synchronization primitive.

## Normative references

- RFC 3550: RTP header fields, sequence numbers, timestamps, and marker bit.
- RFC 6184: H.264 RTP payload and access-unit marker semantics.
