
struct EncryptedRTPHeader: Sendable, Equatable {
    let sequenceNumber: UInt16
    let synchronizationSource: UInt32
    let payloadOffset: Int
}

func encryptedRTPHeader(in packet: Span<UInt8>) throws(SRTPError) -> EncryptedRTPHeader {
    let fixedHeaderByteCount = 12
    guard packet.count >= fixedHeaderByteCount else {
        throw .malformedRTP(.insufficientBytes(
            field: .rtpFixedHeader,
            required: fixedHeaderByteCount,
            available: packet.count
        ))
    }

    let firstByte = packet[0]
    let version = firstByte >> 6
    guard version == 2 else {
        throw .malformedRTP(.invalidVersion(actual: version))
    }

    let contributingSourceCount = Int(firstByte & 0x0F)
    let contributingSourcesEnd = fixedHeaderByteCount + contributingSourceCount * 4
    guard packet.count >= contributingSourcesEnd else {
        throw .malformedRTP(.insufficientBytes(
            field: .rtpContributingSources,
            required: contributingSourcesEnd,
            available: packet.count
        ))
    }

    var payloadOffset = contributingSourcesEnd
    if firstByte & 0x10 != 0 {
        let extensionHeaderEnd = payloadOffset + 4
        guard packet.count >= extensionHeaderEnd else {
            throw .malformedRTP(.insufficientBytes(
                field: .rtpHeaderExtensionHeader,
                required: extensionHeaderEnd,
                available: packet.count
            ))
        }
        let declaredWords = readUInt16(packet, at: payloadOffset + 2)
        let extensionByteCount = Int(declaredWords) * 4
        let extensionEnd = extensionHeaderEnd + extensionByteCount
        guard packet.count >= extensionEnd else {
            throw .malformedRTP(.invalidHeaderExtensionLength(
                declaredWords: declaredWords,
                availableBytes: packet.count - extensionHeaderEnd
            ))
        }
        payloadOffset = extensionEnd
    }

    return EncryptedRTPHeader(
        sequenceNumber: readUInt16(packet, at: 2),
        synchronizationSource: readUInt32(packet, at: 8),
        payloadOffset: payloadOffset
    )
}

func srtpInitialCounter(
    salt: [UInt8],
    synchronizationSource: UInt32,
    packetIndex: UInt64
) -> [UInt8] {
    var counter = [UInt8](repeating: 0, count: 16)
    for index in 0..<salt.count {
        counter[index] = salt[index]
    }

    counter[4] ^= UInt8(truncatingIfNeeded: synchronizationSource >> 24)
    counter[5] ^= UInt8(truncatingIfNeeded: synchronizationSource >> 16)
    counter[6] ^= UInt8(truncatingIfNeeded: synchronizationSource >> 8)
    counter[7] ^= UInt8(truncatingIfNeeded: synchronizationSource)

    counter[8] ^= UInt8(truncatingIfNeeded: packetIndex >> 40)
    counter[9] ^= UInt8(truncatingIfNeeded: packetIndex >> 32)
    counter[10] ^= UInt8(truncatingIfNeeded: packetIndex >> 24)
    counter[11] ^= UInt8(truncatingIfNeeded: packetIndex >> 16)
    counter[12] ^= UInt8(truncatingIfNeeded: packetIndex >> 8)
    counter[13] ^= UInt8(truncatingIfNeeded: packetIndex)
    return counter
}

func networkOrderBytes(_ value: UInt32) -> [UInt8] {
    [
        UInt8(truncatingIfNeeded: value >> 24),
        UInt8(truncatingIfNeeded: value >> 16),
        UInt8(truncatingIfNeeded: value >> 8),
        UInt8(truncatingIfNeeded: value),
    ]
}

func readUInt16(_ bytes: Span<UInt8>, at offset: Int) -> UInt16 {
    UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
}

func readUInt32(_ bytes: Span<UInt8>, at offset: Int) -> UInt32 {
    UInt32(bytes[offset]) << 24
        | UInt32(bytes[offset + 1]) << 16
        | UInt32(bytes[offset + 2]) << 8
        | UInt32(bytes[offset + 3])
}

func constantTimeTagMatches(
    expectedDigest: [UInt8],
    receivedTag: Span<UInt8>,
    tagByteCount: Int
) -> Bool {
    guard expectedDigest.count >= tagByteCount,
          receivedTag.count == tagByteCount else {
        return false
    }
    var difference: UInt8 = 0
    for index in 0..<tagByteCount {
        difference |= expectedDigest[index] ^ receivedTag[index]
    }
    return difference == 0
}
