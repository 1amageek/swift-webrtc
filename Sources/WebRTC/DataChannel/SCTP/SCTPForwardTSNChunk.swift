/// One ordered stream advanced by an RFC 3758 FORWARD-TSN chunk.
struct SCTPForwardTSNSkippedStream: Sendable, Equatable {
    let streamIdentifier: UInt16
    let streamSequenceNumber: UInt16
}

/// RFC 3758 FORWARD-TSN chunk.
struct SCTPForwardTSNChunk: Sendable, Equatable {
    let newCumulativeTSN: UInt32
    let skippedStreams: [SCTPForwardTSNSkippedStream]

    init(
        newCumulativeTSN: UInt32,
        skippedStreams: [SCTPForwardTSNSkippedStream] = []
    ) {
        self.newCumulativeTSN = newCumulativeTSN
        self.skippedStreams = skippedStreams
    }

    func toChunk() throws(SCTPWireError) -> SCTPChunk {
        let (streamByteCount, streamOverflow) = skippedStreams.count
            .multipliedReportingOverflow(by: 4)
        let (valueByteCount, valueOverflow) = streamByteCount
            .addingReportingOverflow(4)
        guard !streamOverflow,
              !valueOverflow,
              valueByteCount <= Int(UInt16.max) - 4 else {
            throw .chunkValueTooLarge(
                actual: streamOverflow || valueOverflow ? Int.max : valueByteCount,
                maximum: Int(UInt16.max) - 4
            )
        }

        var seenStreamIdentifiers: Set<UInt16> = []
        var value: [UInt8] = []
        value.reserveCapacity(valueByteCount)
        sctpAppendUInt32(&value, newCumulativeTSN)
        for skipped in skippedStreams {
            guard seenStreamIdentifiers.insert(skipped.streamIdentifier).inserted else {
                throw .decode(.invalidFormat(
                    "FORWARD-TSN contains a duplicate stream identifier"
                ))
            }
            sctpAppendUInt16(&value, skipped.streamIdentifier)
            sctpAppendUInt16(&value, skipped.streamSequenceNumber)
        }
        return try SCTPChunk(
            chunkType: SCTPChunkType.forwardTSN.rawValue,
            value: value
        )
    }

    static func decode(from chunk: SCTPChunk) throws(SCTPWireError) -> Self {
        guard chunk.chunkType == SCTPChunkType.forwardTSN.rawValue else {
            throw .decode(.invalidFormat("Expected a FORWARD-TSN chunk"))
        }
        guard chunk.flags == 0 else {
            throw .decode(.invalidFormat("FORWARD-TSN reserved flags are non-zero"))
        }
        guard chunk.value.count >= 4 else {
            throw .decode(.insufficientData(expected: 4, actual: chunk.value.count))
        }
        guard (chunk.value.count - 4) % 4 == 0 else {
            throw .decode(.invalidFormat(
                "FORWARD-TSN skipped-stream list is not four-byte aligned"
            ))
        }

        var skippedStreams: [SCTPForwardTSNSkippedStream] = []
        skippedStreams.reserveCapacity((chunk.value.count - 4) / 4)
        var seenStreamIdentifiers: Set<UInt16> = []
        var offset = 4
        while offset < chunk.value.count {
            let streamIdentifier = sctpReadUInt16(chunk.value, offset: offset)
            guard seenStreamIdentifiers.insert(streamIdentifier).inserted else {
                throw .decode(.invalidFormat(
                    "FORWARD-TSN contains a duplicate stream identifier"
                ))
            }
            skippedStreams.append(SCTPForwardTSNSkippedStream(
                streamIdentifier: streamIdentifier,
                streamSequenceNumber: sctpReadUInt16(
                    chunk.value,
                    offset: offset + 2
                )
            ))
            offset += 4
        }

        return Self(
            newCumulativeTSN: sctpReadUInt32(chunk.value, offset: 0),
            skippedStreams: skippedStreams
        )
    }
}

