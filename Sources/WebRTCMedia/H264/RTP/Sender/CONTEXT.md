# H.264 RTP Sender Context

Last reviewed: 2026-07-30.

The `WebRTCMedia/H264/RTP/Sender` component owns RTP sender policy for one H.264
stream: sequence numbers, SSRC fields, the 90 kHz video clock, and bounded
packet assembly. It does not own capture, encoding, signaling, SRTP keys,
sockets, pacing, or retransmission.

```text
borrowed H.264 access unit + NAL ranges + monotonic capture time
    -> RFC 6184 planning
    -> atomic sequence/timestamp reservation under Mutex
    -> one-owner plaintext RTP packets
    -> typed synchronous sink
        -> WebRTCConnection.sendRTP
```

## Ownership and failure

- The encoded access unit remains borrowed; it is never copied as a whole.
- Each final RTP packet is allocated once with SRTP trailer capacity reserved.
- Packetization runs a validation/count pass and an emission pass. The second
  linear scan avoids retaining a packet-layout array while allowing one exact
  sequence-number reservation before any sink call.
- The count pass uses short-circuit traversal and stops after observing the
  first packet beyond `maximumPacketsPerAccessUnit`. The emission pass likewise
  stops immediately after an assembly or sink failure. Complete input
  validation still precedes every callback; short-circuiting bounds later
  packet-layout callbacks and materialization rather than skipping validation.
- The sink receives a `consuming [UInt8]`; a successful call accepts that packet
  owner without leaving a second framework owner behind.
- A sink failure stops later emission and reports the number already accepted.
- A sender-side error discovered after earlier sink acceptance is reported as
  `senderAfterPartialDelivery` with the accepted packet count. It is never
  collapsed into an all-or-nothing failure.
- Once a sequence-number block is reserved it is never reused, including after
  assembly or sink failure. A visible gap is safer than nonce reuse.
- Concurrent or sink-reentrant emission on the same session is rejected with a
  typed `sendInProgress` failure. This preserves packet order and keeps one
  active owner-transfer path per sender session.
- Each access unit is limited by `maximumPacketsPerAccessUnit` (2,048 by
  default). The public maximum is 32,766, below RTP's half-sequence-space
  boundary, so a failed reserved block cannot make later sequence ordering
  ambiguous.
- Capture timestamps must be monotonic. The first sample anchors the configured
  initial RTP timestamp; elapsed nanoseconds map to the 90 kHz clock modulo
  `UInt32` as required by RTP.
- `maximumDatagramByteCount` includes the RTP header, H.264 payload, and
  protection trailer but excludes UDP/IP headers. Obtain the trailer size from
  the negotiated WebRTC media protection profile rather than hard-coding it in
  an adapter.

## Concurrency and platforms

The short, memory-only sender state uses the same `Synchronization.Mutex<State>`
implementation on Native, WASM, and Embedded. Packet construction and sink calls
run outside the critical section. The caller owns any I/O ordering, pacing, and
backpressure policy around the synchronous sink.

## Performance budget

| Path | Budget |
|---|---|
| Access-unit framing/payload input | borrowed; zero whole-access-unit copies |
| Packetization metadata | no per-access-unit layout array |
| Final RTP materialization | one owner per network packet; source payload copied once |
| Shared state | one bounded reservation critical section per access unit |
| Sink | consuming transfer outside the mutex; no framework-retained packet owner |

The Native ownership fixture verifies that a consuming sink can append the
reserved SRTP trailer without changing the packet storage address. This proves
that fixture and path; allocation/copy acceptance still requires measurement on
each production adapter and target.

The current focused Native sender suite passes 9/9. The exact 2026-07-23 normal
and Embedded WASM runtime probes both call `sendAccessUnit` and validate its RTP
output. Those sequential probes do not establish concurrent Mutex semantics or
network delivery.

## Integration boundary

The `WebRTCMedia` target depends on `WebRTC` for RTP wire contracts, but the
sender component does not own a `WebRTCConnection`. A caller maps the typed sink
result to `WebRTCConnection.sendRTP`; another consumer may install a different
transport boundary. A successful report means the sink accepted each packet
owner. It does not prove network delivery, receiver reassembly, decoder output,
or presentation.

## Remaining sender-adjacent work

- pacing and asynchronous backpressure policy;
- retransmission cache and RTCP NACK handling;
- PLI/keyframe request policy;
- measured loss recovery and bounded jitter policy;
- real encoder, UDP, browser, and Lume integration measurements.
