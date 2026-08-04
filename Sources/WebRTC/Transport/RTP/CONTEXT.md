# RTP and RTCP Wire Context

Scope: Foundation-free RTP and RTCP wire parsing plus bounded RTP header
encoding inside `Sources/WebRTC/Transport/RTP`. This component does not own
media sessions, SRTP keys, codec payload
formats, jitter buffering, feedback policy, or congestion control.

Last reviewed: 2026-07-30.

## Ownership and zero-copy contract

- Parsers borrow `Span<UInt8>` and return scalar fields plus `Range<Int>` values.
- A layout never stores a `Span`, pointer, or owner reference.
- The caller retains the original datagram while extracting views from ranges.
- The parse path must not use `ByteReader(Span)`, `Bytes.slice`, `Array(slice)`,
  `Data`, or another payload materialization. Those APIs copy bytes.
- RTCP decoding may allocate one bounded array for packet-layout metadata.
- `encodedHeader` produces only the small RTP header. `appendHeader` can instead
  write directly into caller-owned packet storage; the `WebRTCMedia` H.264 RTP
  assembler uses that API to avoid an intermediate header owner.
- Raw RFC 3550 extension bytes are copied once into the owned header through a
  scoped contiguous buffer append. Byte-at-a-time extension appends are
  forbidden because the public bound permits up to 262,140 extension bytes.

The current `WebRTCMedia` H.264 outbound owner has this shape:

```text
single owned allocation
├── RTP header headroom
├── encoded media payload
└── SRTP authentication tailroom
```

## Security boundary

The RTP/RTCP parser reads plaintext only after an SRTP or SRTCP context
authenticates and decrypts the network datagram. Never route bytes selected only
by the RFC 7983 or RFC 5761 classifiers directly to a media sink.

```text
UDP -> RFC 7983 -> RFC 5761 -> SRTP/SRTCP authenticate -> RTP/RTCP parser -> sink
```

## RTCP framing

- `.compound` enforces RFC 3550: at least two individual packets, initial SR or
  RR, structurally valid report lengths, and an SDES CNAME for the initial
  report source.
- `.reducedSize` accepts one or more packet types without requiring an initial
  report or CNAME. Negotiating reduced-size RTCP is a session responsibility.
- Both modes validate version, exact length coverage, padding, known minimum
  structures, and the configured packet-count limit.
- Unknown later RTCP packet types remain represented by layouts. They are not a
  wire failure merely because this version does not interpret them.

## Performance gates

| Path | Budget |
|---|---|
| RTP parse | zero byte copies, zero heap allocations |
| RTP payload access | borrowed range view, zero copies |
| RTCP parse | zero byte copies, at most one bounded metadata allocation |
| RTP `encodedHeader` | one header-sized allocation; no payload copy |
| RTP `appendHeader` | direct write into caller storage; one bulk copy for caller-owned extension bytes |

Parsing 12-byte, 1,200-byte, and 65,535-byte RTP packets must remain independent
of payload length. Any future API that scans or copies payload bytes belongs in a
payload-format component and requires a separate benchmark.
`RTPWireCorePerformanceTests` remains a focused test target for this gate. It
imports the consolidated `WebRTC` module, so the compilation graph includes the
full transport target; the timed operation itself must remain limited to the
RTP parser path.

The latency benchmark is an asymptotic regression gate only. Passing its
normalized-slope assertions does not prove zero heap allocations or zero byte
copies. Those budgets are accepted only after a source audit confirms all of the
following:

- parser results contain only scalar metadata and ranges into the caller-owned
  datagram;
- no parser path materializes payload bytes through `ByteReader(Span)`,
  `Bytes.slice`, `Array(slice)`, `Data`, or an equivalent owned container;
- no `Span`, pointer, or borrowed view escapes the parser call or is stored in a
  layout;
- `encodedHeader` allocates only its header owner; `appendHeader` writes directly
  into final caller storage without scanning the media payload;
- RTCP metadata allocation remains limited by `RTCPParseLimits` and does not
  allocate in proportion to an individual packet body.

When an allocation-counting tool is available for the target, its measurement
supplements this audit. Timing alone must never be reported as evidence that the
allocation or copy budget is satisfied.

## Normative references

- RFC 3550: RTP and RTCP wire format.
- RFC 5506: reduced-size RTCP.
- RFC 5761: RTP/RTCP multiplexing and payload-type restrictions.
- RFC 7983: outer WebRTC datagram demultiplexing.
