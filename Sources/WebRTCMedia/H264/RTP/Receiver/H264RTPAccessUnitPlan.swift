
/// Internal range-only reconstruction plan.
///
/// The plan retains each RTP packet owner exactly once and records only byte
/// ranges until an access unit boundary is known. Materialization therefore
/// allocates the decoder-bound owner at its exact size and copies every media
/// byte directly from its packet owner exactly once.
struct H264RTPAccessUnitPlan: Sendable {
    let packetOwners: [[UInt8]]
    let nalUnits: [H264RTPNALUnitPlan]
    let outputByteCount: Int
    let rtpTimestamp: UInt32
    let synchronizationSource: UInt32
    let firstSequenceNumber: UInt16
    let lastSequenceNumber: UInt16
    let packetCount: Int
    let containsInstantaneousDecoderRefresh: Bool

    func materialized(
        format: H264RTPAccessUnitFormat
    ) -> H264RTPAccessUnit {
        let prefixByteCount = format.prefixByteCount
        var ranges: [Range<Int>] = []
        ranges.reserveCapacity(nalUnits.count)

        var cursor = 0
        for nalUnit in nalUnits {
            cursor += prefixByteCount
            let start = cursor
            cursor += nalUnit.byteCount
            ranges.append(start..<cursor)
        }

        // Unsafe boundary invariants:
        // - Array owns and deallocates the destination exactly once.
        // - `outputByteCount` is the checked sum of every prefix and NAL byte.
        // - Every source range was validated against its immutable packet owner.
        // - UInt8 has stride/alignment 1 and every destination byte is initialized
        //   exactly once before `initializedCount` is published.
        // - Source and destination pointers remain inside nested scoped closures
        //   and never cross a Sendable or lifetime boundary.
        let bytes = [UInt8](
            unsafeUninitializedCapacity: outputByteCount
        ) { destination, initializedCount in
            guard outputByteCount > 0,
                  let destinationBase = destination.baseAddress else {
                initializedCount = 0
                return
            }

            var outputOffset = 0
            for nalUnit in nalUnits {
                format.initializePrefix(
                    at: destinationBase.advanced(by: outputOffset),
                    nalUnitByteCount: nalUnit.byteCount
                )
                outputOffset += prefixByteCount

                if let reconstructedHeader = nalUnit.reconstructedHeader {
                    destinationBase.advanced(by: outputOffset).initialize(
                        to: reconstructedHeader
                    )
                    outputOffset += 1
                }

                for chunk in nalUnit.chunks {
                    let owner = packetOwners[chunk.ownerIndex]
                    owner.withUnsafeBufferPointer { source in
                        guard let sourceBase = source.baseAddress else { return }
                        destinationBase.advanced(by: outputOffset).initialize(
                            from: sourceBase.advanced(by: chunk.range.lowerBound),
                            count: chunk.range.count
                        )
                    }
                    outputOffset += chunk.range.count
                }
            }

            precondition(outputOffset == outputByteCount)
            initializedCount = outputByteCount
        }

        return H264RTPAccessUnit(
            bytes: bytes,
            nalUnitRanges: ranges,
            rtpTimestamp: rtpTimestamp,
            synchronizationSource: synchronizationSource,
            firstSequenceNumber: firstSequenceNumber,
            lastSequenceNumber: lastSequenceNumber,
            packetCount: packetCount,
            containsInstantaneousDecoderRefresh:
                containsInstantaneousDecoderRefresh
        )
    }
}

struct H264RTPNALUnitPlan: Sendable {
    let header: H264NALUnitHeader
    let reconstructedHeader: UInt8?
    var chunks: [H264RTPPayloadChunk]
    var byteCount: Int
}

struct H264RTPPayloadChunk: Sendable {
    let ownerIndex: Int
    let range: Range<Int>
}

extension H264RTPAccessUnitFormat {
    var prefixByteCount: Int {
        switch self {
        case .annexB(let startCodeByteCount):
            return startCodeByteCount
        case .avcc(let lengthFieldByteCount):
            return lengthFieldByteCount
        }
    }

    func initializePrefix(
        at destination: UnsafeMutablePointer<UInt8>,
        nalUnitByteCount: Int
    ) {
        switch self {
        case .annexB(let startCodeByteCount):
            for index in 0..<(startCodeByteCount - 1) {
                destination.advanced(by: index).initialize(to: 0)
            }
            destination.advanced(by: startCodeByteCount - 1).initialize(to: 1)

        case .avcc(let lengthFieldByteCount):
            for index in 0..<lengthFieldByteCount {
                let shift = (lengthFieldByteCount - index - 1) * 8
                destination.advanced(by: index).initialize(
                    to: UInt8(truncatingIfNeeded: nalUnitByteCount >> shift)
                )
            }
        }
    }
}
