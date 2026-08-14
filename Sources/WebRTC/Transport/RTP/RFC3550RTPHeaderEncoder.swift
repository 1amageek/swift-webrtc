import NetworkingCore

/// Encodes RFC 3550 RTP headers without joining or copying the media payload.
package struct RFC3550RTPHeaderEncoder: RTPHeaderEncoding, RTPHeaderAppending, Sendable {
    package init() {}

    package func encodedHeader(
        _ header: RTPOutboundHeader,
        extensionProfile: UInt16?,
        extensionData: Span<UInt8>
    ) throws(RTPWireError) -> OwnedBytes {
        let count = try headerByteCount(
            header,
            extensionProfile: extensionProfile,
            extensionData: extensionData
        )
        var bytes = ContiguousArray<UInt8>()
        bytes.reserveCapacity(count)
        appendValidatedHeader(
            header,
            extensionProfile: extensionProfile,
            extensionData: extensionData,
            to: &bytes
        )
        return OwnedBytes(consuming: bytes)
    }

    package func appendHeader(
        _ header: RTPOutboundHeader,
        extensionProfile: UInt16?,
        extensionData: Span<UInt8>,
        to destination: inout [UInt8]
    ) throws(RTPWireError) {
        let headerByteCount = try headerByteCount(
            header,
            extensionProfile: extensionProfile,
            extensionData: extensionData
        )
        let (requiredCapacity, capacityOverflow) = destination.count.addingReportingOverflow(
            headerByteCount
        )
        guard !capacityOverflow else {
            throw .integerOverflow
        }
        destination.reserveCapacity(requiredCapacity)

        appendValidatedHeader(
            header,
            extensionProfile: extensionProfile,
            extensionData: extensionData,
            to: &destination
        )
    }

    private func appendValidatedHeader<Destination: RangeReplaceableCollection>(
        _ header: RTPOutboundHeader,
        extensionProfile: UInt16?,
        extensionData: Span<UInt8>,
        to destination: inout Destination
    ) where Destination.Element == UInt8 {
        let hasExtension = extensionProfile != nil
        let firstByte = UInt8(2 << 6)
            | (hasExtension ? 0x10 : 0)
            | UInt8(header.contributingSources.count)
        destination.append(firstByte)
        destination.append((header.marker ? 0x80 : 0) | header.payloadType)
        appendUInt16(header.sequenceNumber, to: &destination)
        appendUInt32(header.timestamp, to: &destination)
        appendUInt32(header.synchronizationSource, to: &destination)

        for source in header.contributingSources {
            appendUInt32(source, to: &destination)
        }

        if let extensionProfile {
            appendUInt16(extensionProfile, to: &destination)
            appendUInt16(UInt16(extensionData.count / 4), to: &destination)
            // Header extensions are bounded but may still be large. Keep the
            // borrowed pointer scoped and perform the required owner copy as
            // one contiguous append rather than one checked append per byte.
            extensionData.withUnsafeBufferPointer { bytes in
                destination.append(contentsOf: bytes)
            }
        }
    }

    package func headerByteCount(
        _ header: RTPOutboundHeader,
        extensionProfile: UInt16?,
        extensionData: Span<UInt8>
    ) throws(RTPWireError) -> Int {
        guard header.payloadType <= 127 else {
            throw .invalidPayloadType(actual: header.payloadType)
        }
        guard header.contributingSources.count <= 15 else {
            throw .tooManyContributingSources(actual: header.contributingSources.count)
        }

        if extensionProfile == nil, !extensionData.isEmpty {
            throw .unexpectedHeaderExtensionData(byteCount: extensionData.count)
        }
        guard extensionData.count.isMultiple(of: 4) else {
            throw .invalidHeaderExtensionAlignment(byteCount: extensionData.count)
        }
        let extensionWordCount = extensionData.count / 4
        guard extensionWordCount <= Int(UInt16.max) else {
            throw .headerExtensionTooLarge(byteCount: extensionData.count)
        }

        let hasExtension = extensionProfile != nil
        let extensionByteCount = hasExtension ? 4 + extensionData.count : 0
        return 12 + header.contributingSources.count * 4 + extensionByteCount
    }
}

private func appendUInt16<Destination: RangeReplaceableCollection>(
    _ value: UInt16,
    to bytes: inout Destination
) where Destination.Element == UInt8 {
    bytes.append(UInt8(value >> 8))
    bytes.append(UInt8(truncatingIfNeeded: value))
}

private func appendUInt32<Destination: RangeReplaceableCollection>(
    _ value: UInt32,
    to bytes: inout Destination
) where Destination.Element == UInt8 {
    bytes.append(UInt8(value >> 24))
    bytes.append(UInt8(truncatingIfNeeded: value >> 16))
    bytes.append(UInt8(truncatingIfNeeded: value >> 8))
    bytes.append(UInt8(truncatingIfNeeded: value))
}
