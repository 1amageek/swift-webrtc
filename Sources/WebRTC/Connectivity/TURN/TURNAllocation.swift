public struct TURNAllocation: Sendable, Equatable {
    public let relayedAddress: TURNAddress
    public let mappedAddress: TURNAddress?
    public let lifetimeSeconds: UInt32

    let authentication: TURNAuthenticationContext

    init(
        relayedAddress: TURNAddress,
        mappedAddress: TURNAddress?,
        lifetimeSeconds: UInt32,
        authentication: TURNAuthenticationContext
    ) {
        self.relayedAddress = relayedAddress
        self.mappedAddress = mappedAddress
        self.lifetimeSeconds = lifetimeSeconds
        self.authentication = authentication
    }

    public func makePermissionTransaction(
        for peerAddresses: [TURNAddress]
    ) throws(TURNError) -> TURNPermissionTransaction {
        try TURNPermissionTransaction(
            peerAddresses: peerAddresses,
            authentication: authentication
        )
    }

    public func makeRefreshTransaction(
        lifetimeSeconds: UInt32
    ) -> TURNRefreshTransaction {
        TURNRefreshTransaction(
            lifetimeSeconds: lifetimeSeconds,
            authentication: authentication
        )
    }

    public func encapsulate(
        _ payload: consuming [UInt8],
        to peerAddress: TURNAddress
    ) throws(TURNError) -> TURNOutboundDatagram {
        let transactionID = TransactionID(
            byteValues: SecureRandom.bytes(count: 12)
        )
        let peerAttribute = peerAddress.xorAttribute(
            type: .xorPeerAddress,
            transactionID: transactionID
        )
        let encodedPeerAttribute = STUNMessage.encodeAttributes([peerAttribute])
        let paddingByteCount = (4 - payload.count % 4) % 4
        let attributeByteCount = encodedPeerAttribute.count
            + stunAttributeHeaderSize
            + payload.count
            + paddingByteCount
        guard attributeByteCount <= Int(UInt16.max) else {
            throw .payloadTooLarge(payload.count)
        }

        var prefix: [UInt8] = []
        prefix.reserveCapacity(
            stunHeaderSize + encodedPeerAttribute.count + stunAttributeHeaderSize
        )
        let messageType = STUNMessageType(method: .send, class: .indication)
        prefix.append(UInt8(truncatingIfNeeded: messageType.rawValue >> 8))
        prefix.append(UInt8(truncatingIfNeeded: messageType.rawValue))
        prefix.append(UInt8(truncatingIfNeeded: attributeByteCount >> 8))
        prefix.append(UInt8(truncatingIfNeeded: attributeByteCount))
        prefix.append(UInt8(truncatingIfNeeded: stunMagicCookie >> 24))
        prefix.append(UInt8(truncatingIfNeeded: stunMagicCookie >> 16))
        prefix.append(UInt8(truncatingIfNeeded: stunMagicCookie >> 8))
        prefix.append(UInt8(truncatingIfNeeded: stunMagicCookie))
        prefix.append(contentsOf: transactionID.byteValues)
        prefix.append(contentsOf: encodedPeerAttribute)
        prefix.append(UInt8(truncatingIfNeeded: STUNAttributeType.data.rawValue >> 8))
        prefix.append(UInt8(truncatingIfNeeded: STUNAttributeType.data.rawValue))
        prefix.append(UInt8(truncatingIfNeeded: payload.count >> 8))
        prefix.append(UInt8(truncatingIfNeeded: payload.count))
        return TURNOutboundDatagram(
            prefixBytes: prefix,
            payload: payload,
            paddingByteCount: paddingByteCount
        )
    }

    public func decapsulate(
        _ input: consuming [UInt8]
    ) throws(TURNError) -> TURNPeerDatagram {
        var bytes = input
        guard bytes.count >= stunHeaderSize else { throw .malformedMessage }
        let declaredLength = Int(UInt16(bytes[2]) << 8 | UInt16(bytes[3]))
        guard declaredLength.isMultiple(of: 4),
              bytes.count == stunHeaderSize + declaredLength,
              UInt32(bytes[4]) << 24
                | UInt32(bytes[5]) << 16
                | UInt32(bytes[6]) << 8
                | UInt32(bytes[7]) == stunMagicCookie else {
            throw .malformedMessage
        }
        let rawMessageType = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
        let expectedMessageType = STUNMessageType(
            method: .data,
            class: .indication
        )
        guard rawMessageType == expectedMessageType.rawValue else {
            throw .unexpectedMessageType(rawMessageType)
        }
        let transactionID = TransactionID(
            byteValues: Array(bytes[8..<stunHeaderSize])
        )

        var peerAddress: TURNAddress?
        var payloadRange: Range<Int>?
        var offset = stunHeaderSize
        while offset < bytes.count {
            guard offset + stunAttributeHeaderSize <= bytes.count else {
                throw .malformedMessage
            }
            let type = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
            let length = Int(UInt16(bytes[offset + 2]) << 8 | UInt16(bytes[offset + 3]))
            let valueStart = offset + stunAttributeHeaderSize
            let valueEnd = valueStart + length
            guard valueEnd <= bytes.count else { throw .malformedMessage }
            if type == STUNAttributeType.xorPeerAddress.rawValue {
                guard peerAddress == nil else {
                    throw .duplicateAttribute(type)
                }
                let attribute = STUNAttribute(
                    type: type,
                    value: Array(bytes[valueStart..<valueEnd])
                )
                peerAddress = try TURNAddress.parse(
                    attribute,
                    expectedType: .xorPeerAddress,
                    transactionID: transactionID
                )
            } else if type == STUNAttributeType.data.rawValue {
                guard payloadRange == nil else {
                    throw .duplicateAttribute(type)
                }
                payloadRange = valueStart..<valueEnd
            }
            let paddedLength = (length + 3) & ~3
            guard valueStart + paddedLength <= bytes.count else {
                throw .malformedMessage
            }
            offset = valueStart + paddedLength
        }
        guard let peerAddress else { throw .missingPeerAddress }
        guard let payloadRange else { throw .missingData }

        // `bytes` owns the sole host-boundary materialization. The DATA value
        // always starts after the STUN header, so a forward overlapping copy is
        // safe and reuses that allocation. No pointer escapes and no second
        // full-payload owner is created.
        let payloadCount = payloadRange.count
        if payloadRange.lowerBound != 0 {
            for index in 0..<payloadCount {
                bytes[index] = bytes[payloadRange.lowerBound + index]
            }
        }
        bytes.removeLast(bytes.count - payloadCount)
        return TURNPeerDatagram(
            peerAddress: peerAddress,
            payload: bytes
        )
    }
}
