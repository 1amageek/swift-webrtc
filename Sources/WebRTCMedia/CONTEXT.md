# WebRTCMedia Context

## Responsibility

`WebRTCMedia` is the optional public H.264 library target for swift-webrtc.
Consumers import this module for H.264 framing, RFC 6184, sender, and receiver
APIs. The target depends on `WebRTC` for RTP wire contracts; `WebRTC` does not
depend on `WebRTCMedia`.

It owns:

- Annex B and AVCC NAL-unit range extraction;
- RFC 6184 payload planning, parsing, and encoding;
- one-owner plaintext RTP packet assembly;
- bounded sender sequence and timestamp policy;
- bounded receiver reorder, loss quarantine, and access-unit assembly.

It does not own cameras, hardware encoders, decoders, sockets, signaling,
SRTP keys, or product policy.

## Internal source boundaries

There is one `WebRTCMedia` Swift target. Domain-oriented source directories and
focused test targets preserve the implementation boundaries:

```text
Sources/WebRTCMedia/H264/
├── ByteStream/
└── RTP/
    ├── Payload/
    ├── Sender/
    └── Receiver/
```

The execution path is:

```text
camera / encoded H.264 owner
    -> WebRTCMedia borrowed bytes and range metadata
        -> one-owner plaintext RTP packet
            -> WebRTC RTP/SRTP
                -> consuming transport boundary
```

Directory separation does not create additional importable modules and is not
implementation-completion evidence. Focused tests, Native builds, and
normal/Embedded WASM runtime probes remain required.

## Ownership and performance

- Encoded access-unit bytes remain owned by the caller while synchronous
  borrowed `Span` operations execute.
- Packetization stores scalar and range metadata, not copied media payloads.
- The sender creates one final plaintext RTP owner per packet and transfers it
  through a consuming sink.
- The receiver consumes authenticated plaintext packet owners, retains bounded
  owner/range plans, and materializes one exact decoder-bound access-unit owner
  outside its state mutex.
- Crossing from the `WebRTCMedia` target into `WebRTC` does not require a
  facade copy. The same RTP packet owner reaches in-place SRTP protection.

## Failure and platform contract

- Failures remain typed across the `WebRTCMedia` to `WebRTC` boundary.
- Unsupported framing, packetization, resource limits, and sink rejection are
  never converted to success values.
- Native, WASM, and Embedded compile the same implementation sources.
- Shared sender and receiver state uses the same `Synchronization.Mutex`
  contract on every platform.
