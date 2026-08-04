# H.264 ByteStream Context

Last reviewed: 2026-07-30.

The `WebRTCMedia/H264/ByteStream` component owns only H.264 byte-stream
framing. It converts a borrowed
Annex B or AVCC access unit into NAL-unit ranges. It does not decode video,
validate codec semantics, packetize RTP, own timestamps, or perform I/O.

## Ownership and performance

```text
encoded access-unit owner
    -> borrowed Span<UInt8>
        -> H264ByteStreamParser
            -> caller-reused [Range<Int>]
```

- Encoded media bytes are never copied or retained.
- Only small range metadata is appended.
- `appendNALUnitRanges` supports scratch-array reuse across frames.
- Failure restores the destination elements to their pre-call value.
- The input owner must remain alive and must not be mutated for as long as a
  consumer uses the returned ranges.

## Framing contract

- Annex B recognizes three-byte and longer zero-prefixed start codes, excludes
  delimiters and trailing zero bytes from emitted NAL ranges, and rejects
  nonzero bytes before the first delimiter.
- AVCC accepts one- through four-byte big-endian length fields. The caller must
  supply the width negotiated by its codec/container boundary.
- Empty access units, empty NAL units, missing/truncated framing, and declared
  lengths outside the owner are typed `H264ByteStreamError` failures.
- This component does not validate H.264 NAL types; that belongs to the
  `H264/RTP/Payload` component when the ranges enter RFC 6184 packetization.

## Performance budget

| Path | Budget |
|---|---|
| Annex B / AVCC scan | zero media copies; one linear scan |
| Reused destination | no required metadata allocation when capacity is sufficient |
| Convenience result | range-metadata allocation only; never a media allocation |

## Platform contract

The component is Foundation-free and uses the same implementation inside the
`WebRTCMedia` target on Native, WASM, and Embedded Swift 6.4 builds.
