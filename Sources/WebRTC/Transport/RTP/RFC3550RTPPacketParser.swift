/// A bounds-checked, zero-copy RTP packet parser conforming to RFC 3550.
package struct RFC3550RTPPacketParser: RTPPacketParsing, Sendable {
    private static let fixedHeaderByteCount = 12

    package init() {}

    package func layout(in packet: Span<UInt8>) throws(RTPWireError) -> RTPPacketLayout {
        guard packet.count >= Self.fixedHeaderByteCount else {
            throw .insufficientBytes(
                field: .rtpFixedHeader,
                required: Self.fixedHeaderByteCount,
                available: packet.count
            )
        }

        let firstByte = packet[0]
        let version = firstByte >> 6
        guard version == 2 else {
            throw .invalidVersion(actual: version)
        }

        let hasPadding = firstByte & 0x20 != 0
        let hasExtension = firstByte & 0x10 != 0
        let contributingSourceCount = firstByte & 0x0F
        let contributingSourcesByteCount = Int(contributingSourceCount) * 4
        let contributingSourcesEnd = Self.fixedHeaderByteCount + contributingSourcesByteCount

        guard packet.count >= contributingSourcesEnd else {
            throw .insufficientBytes(
                field: .rtpContributingSources,
                required: contributingSourcesEnd,
                available: packet.count
            )
        }

        let secondByte = packet[1]
        let fixedHeader = RTPFixedHeader(
            hasPadding: hasPadding,
            hasExtension: hasExtension,
            contributingSourceCount: contributingSourceCount,
            marker: secondByte & 0x80 != 0,
            payloadType: secondByte & 0x7F,
            sequenceNumber: readRTPUInt16(packet, at: 2),
            timestamp: readRTPUInt32(packet, at: 4),
            synchronizationSource: readRTPUInt32(packet, at: 8)
        )

        var payloadStart = contributingSourcesEnd
        var headerExtension: RTPHeaderExtensionLayout?
        if hasExtension {
            let extensionHeaderEnd = payloadStart + 4
            guard packet.count >= extensionHeaderEnd else {
                throw .insufficientBytes(
                    field: .rtpHeaderExtensionHeader,
                    required: extensionHeaderEnd,
                    available: packet.count
                )
            }

            let profileIdentifier = readRTPUInt16(packet, at: payloadStart)
            let declaredWords = readRTPUInt16(packet, at: payloadStart + 2)
            let extensionByteCount = Int(declaredWords) * 4
            let extensionDataEnd = extensionHeaderEnd + extensionByteCount
            guard packet.count >= extensionDataEnd else {
                throw .invalidHeaderExtensionLength(
                    declaredWords: declaredWords,
                    availableBytes: packet.count - extensionHeaderEnd
                )
            }

            headerExtension = RTPHeaderExtensionLayout(
                profileIdentifier: profileIdentifier,
                dataRange: extensionHeaderEnd..<extensionDataEnd
            )
            payloadStart = extensionDataEnd
        }

        var payloadEnd = packet.count
        var paddingRange: Range<Int>?
        if hasPadding {
            let availableBytes = packet.count - payloadStart
            guard availableBytes > 0 else {
                throw .insufficientBytes(field: .rtpPadding, required: 1, available: 0)
            }

            let paddingCount = packet[packet.count - 1]
            guard paddingCount > 0, Int(paddingCount) < availableBytes else {
                throw .invalidRTPPadding(count: paddingCount, availableBytes: availableBytes)
            }

            payloadEnd = packet.count - Int(paddingCount)
            paddingRange = payloadEnd..<packet.count
        }

        return RTPPacketLayout(
            packetLength: packet.count,
            fixedHeader: fixedHeader,
            contributingSourcesRange: Self.fixedHeaderByteCount..<contributingSourcesEnd,
            headerExtension: headerExtension,
            payloadRange: payloadStart..<payloadEnd,
            paddingRange: paddingRange
        )
    }
}

private func readRTPUInt16(_ bytes: Span<UInt8>, at offset: Int) -> UInt16 {
    UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
}

private func readRTPUInt32(_ bytes: Span<UInt8>, at offset: Int) -> UInt32 {
    UInt32(bytes[offset]) << 24
        | UInt32(bytes[offset + 1]) << 16
        | UInt32(bytes[offset + 2]) << 8
        | UInt32(bytes[offset + 3])
}
