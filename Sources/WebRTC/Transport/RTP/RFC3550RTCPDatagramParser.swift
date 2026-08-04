/// A bounded, zero-copy RTCP datagram parser for compound and reduced-size framing.
struct RFC3550RTCPDatagramParser: RTCPDatagramParsing, Sendable {
    private static let commonHeaderByteCount = 4
    private static let senderReportType: UInt8 = 200
    private static let receiverReportType: UInt8 = 201
    private static let sourceDescriptionType: UInt8 = 202

    init() {}

    func layout(
        in datagram: Span<UInt8>,
        framing: RTCPFraming,
        limits: RTCPParseLimits = RTCPParseLimits()
    ) throws(RTPWireError) -> RTCPDatagramLayout {
        guard limits.maximumPacketCount > 0 else {
            throw .packetLimitExceeded(limit: limits.maximumPacketCount)
        }
        guard datagram.count >= Self.commonHeaderByteCount else {
            throw .insufficientBytes(
                field: .rtcpCommonHeader,
                required: Self.commonHeaderByteCount,
                available: datagram.count
            )
        }

        var packetLayouts = [RTCPPacketLayout]()
        packetLayouts.reserveCapacity(min(limits.maximumPacketCount, datagram.count / 4))
        var compoundReportSource: UInt32?
        var compoundContainsRequiredCNAME = false
        var offset = 0

        while offset < datagram.count {
            let availableBytes = datagram.count - offset
            guard availableBytes >= Self.commonHeaderByteCount else {
                throw .trailingRTCPBytes(count: availableBytes)
            }
            guard packetLayouts.count < limits.maximumPacketCount else {
                throw .packetLimitExceeded(limit: limits.maximumPacketCount)
            }

            let firstByte = datagram[offset]
            let version = firstByte >> 6
            guard version == 2 else {
                throw .invalidVersion(actual: version)
            }

            let declaredWords = rtcpReadUInt16(datagram, at: offset + 2)
            let declaredBytes = (Int(declaredWords) + 1) * 4
            guard declaredBytes <= availableBytes else {
                throw .invalidRTCPPacketLength(
                    packetIndex: packetLayouts.count,
                    declaredBytes: declaredBytes,
                    availableBytes: availableBytes
                )
            }

            let packetEnd = offset + declaredBytes
            let hasPadding = firstByte & 0x20 != 0
            var bodyEnd = packetEnd
            var paddingRange: Range<Int>?
            if hasPadding {
                guard packetEnd == datagram.count else {
                    throw .rtcpPaddingBeforeLast(packetIndex: packetLayouts.count)
                }
                let paddingCount = datagram[packetEnd - 1]
                guard paddingCount > 0,
                      paddingCount.isMultiple(of: 4),
                      Int(paddingCount) <= declaredBytes - Self.commonHeaderByteCount else {
                    throw .invalidRTCPPadding(
                        packetIndex: packetLayouts.count,
                        count: paddingCount
                    )
                }
                bodyEnd = packetEnd - Int(paddingCount)
                paddingRange = bodyEnd..<packetEnd
            }

            let commonHeader = RTCPCommonHeader(
                hasPadding: hasPadding,
                countOrFormat: firstByte & 0x1F,
                packetType: datagram[offset + 1],
                lengthIn32BitWordsMinusOne: declaredWords
            )
            let packetLayout = RTCPPacketLayout(
                commonHeader: commonHeader,
                packetRange: offset..<packetEnd,
                bodyRange: (offset + Self.commonHeaderByteCount)..<bodyEnd,
                paddingRange: paddingRange
            )
            let containsRequiredCNAME = try validateKnownPacket(
                packetLayout,
                packetIndex: packetLayouts.count,
                requiredCNAMEForSource: compoundReportSource,
                in: datagram
            )
            compoundContainsRequiredCNAME = compoundContainsRequiredCNAME
                || containsRequiredCNAME
            if framing == .compound,
               packetLayouts.isEmpty,
               packetLayout.commonHeader.packetType == Self.senderReportType
                    || packetLayout.commonHeader.packetType == Self.receiverReportType {
                compoundReportSource = rtcpReadUInt32(
                    datagram,
                    at: packetLayout.bodyRange.lowerBound
                )
            }
            packetLayouts.append(packetLayout)
            offset = packetEnd
        }

        if framing == .compound {
            try validateCompound(
                packetLayouts,
                containsRequiredCNAME: compoundContainsRequiredCNAME
            )
        }

        return RTCPDatagramLayout(
            framing: framing,
            packetLayouts: packetLayouts,
            byteCount: datagram.count
        )
    }

    private func validateKnownPacket(
        _ layout: RTCPPacketLayout,
        packetIndex: Int,
        requiredCNAMEForSource: UInt32?,
        in datagram: Span<UInt8>
    ) throws(RTPWireError) -> Bool {
        let count = Int(layout.commonHeader.countOrFormat)
        let bodyByteCount = layout.bodyRange.count

        switch layout.commonHeader.packetType {
        case Self.senderReportType:
            let required = 24 + count * 24
            guard bodyByteCount >= required else {
                throw .insufficientBytes(
                    field: .rtcpSenderReport,
                    required: required,
                    available: bodyByteCount
                )
            }
            return false
        case Self.receiverReportType:
            let required = 4 + count * 24
            guard bodyByteCount >= required else {
                throw .insufficientBytes(
                    field: .rtcpReceiverReport,
                    required: required,
                    available: bodyByteCount
                )
            }
            return false
        case Self.sourceDescriptionType:
            return try validateSourceDescription(
                layout,
                packetIndex: packetIndex,
                requiredCNAMEForSource: requiredCNAMEForSource,
                in: datagram
            )
        case 203:
            let required = count * 4
            guard bodyByteCount >= required else {
                throw .insufficientBytes(
                    field: .rtcpPacket,
                    required: required,
                    available: bodyByteCount
                )
            }
            return false
        case 204, 205, 206:
            guard bodyByteCount >= 8 else {
                throw .insufficientBytes(field: .rtcpPacket, required: 8, available: bodyByteCount)
            }
            return false
        case 207:
            guard bodyByteCount >= 4 else {
                throw .insufficientBytes(field: .rtcpPacket, required: 4, available: bodyByteCount)
            }
            return false
        default:
            // Unknown RTCP packet types remain represented by their layout so
            // newer extensions can be ignored or handled by a higher layer.
            return false
        }
    }

    private func validateCompound(
        _ packetLayouts: [RTCPPacketLayout],
        containsRequiredCNAME: Bool
    ) throws(RTPWireError) {
        guard packetLayouts.count >= 2 else {
            throw .compoundRequiresMultiplePackets(actual: packetLayouts.count)
        }

        let first = packetLayouts[0]
        guard first.commonHeader.packetType == Self.senderReportType
                || first.commonHeader.packetType == Self.receiverReportType else {
            throw .compoundMustStartWithReport(actual: first.commonHeader.packetType)
        }

        guard containsRequiredCNAME else {
            throw .compoundMissingSourceDescriptionCNAME
        }
    }

    private func validateSourceDescription(
        _ layout: RTCPPacketLayout,
        packetIndex: Int,
        requiredCNAMEForSource: UInt32?,
        in datagram: Span<UInt8>
    ) throws(RTPWireError) -> Bool {
        var cursor = layout.bodyRange.lowerBound
        let end = layout.bodyRange.upperBound
        var foundRequiredCNAME = false

        for _ in 0..<layout.commonHeader.countOrFormat {
            guard cursor + 4 <= end else {
                throw .malformedSourceDescription(packetIndex: packetIndex)
            }
            let source = rtcpReadUInt32(datagram, at: cursor)
            cursor += 4

            var foundEnd = false
            while cursor < end {
                let itemType = datagram[cursor]
                cursor += 1
                if itemType == 0 {
                    foundEnd = true
                    while (cursor - layout.packetRange.lowerBound) % 4 != 0 {
                        guard cursor < end, datagram[cursor] == 0 else {
                            throw .malformedSourceDescription(packetIndex: packetIndex)
                        }
                        cursor += 1
                    }
                    break
                }

                guard cursor < end else {
                    throw .malformedSourceDescription(packetIndex: packetIndex)
                }
                let itemLength = Int(datagram[cursor])
                cursor += 1
                guard itemLength <= end - cursor else {
                    throw .malformedSourceDescription(packetIndex: packetIndex)
                }
                if itemType == 1,
                   let requiredCNAMEForSource,
                   requiredCNAMEForSource == source {
                    foundRequiredCNAME = true
                }
                cursor += itemLength
            }

            guard foundEnd else {
                throw .malformedSourceDescription(packetIndex: packetIndex)
            }
        }

        guard cursor == end else {
            throw .malformedSourceDescription(packetIndex: packetIndex)
        }
        return foundRequiredCNAME
    }
}

private func rtcpReadUInt16(_ bytes: Span<UInt8>, at offset: Int) -> UInt16 {
    UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
}

private func rtcpReadUInt32(_ bytes: Span<UInt8>, at offset: Int) -> UInt32 {
    UInt32(bytes[offset]) << 24
        | UInt32(bytes[offset + 1]) << 16
        | UInt32(bytes[offset + 2]) << 8
        | UInt32(bytes[offset + 3])
}
