/// An Outgoing SSN Reset Request Parameter (RFC 6525 §4.1).
struct SCTPOutgoingSSNResetRequest: Sendable, Equatable {
    static let parameterType: UInt16 = 13

    let requestSequenceNumber: UInt32
    let responseSequenceNumber: UInt32
    let senderLastAssignedTSN: UInt32
    /// An empty list means all outgoing streams.
    let streamIDs: [UInt16]

    init(
        requestSequenceNumber: UInt32,
        responseSequenceNumber: UInt32,
        senderLastAssignedTSN: UInt32,
        streamIDs: [UInt16]
    ) {
        self.requestSequenceNumber = requestSequenceNumber
        self.responseSequenceNumber = responseSequenceNumber
        self.senderLastAssignedTSN = senderLastAssignedTSN
        self.streamIDs = streamIDs
    }

    func encodeParameterBytes() throws(SCTPWireError) -> [UInt8] {
        let (streamBytes, overflow) = streamIDs.count.multipliedReportingOverflow(by: 2)
        let (length, lengthOverflow) = 16.addingReportingOverflow(streamBytes)
        guard !overflow, !lengthOverflow, length <= Int(UInt16.max) else {
            throw .decode(.invalidFormat("Outgoing SSN reset stream list exceeds the parameter length field"))
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(length)
        sctpAppendUInt16(&bytes, Self.parameterType)
        sctpAppendUInt16(&bytes, UInt16(length))
        sctpAppendUInt32(&bytes, requestSequenceNumber)
        sctpAppendUInt32(&bytes, responseSequenceNumber)
        sctpAppendUInt32(&bytes, senderLastAssignedTSN)
        for streamID in streamIDs {
            sctpAppendUInt16(&bytes, streamID)
        }
        return bytes
    }

    static func decodeParameter(
        from bytes: [UInt8],
        offset: Int,
        length: Int
    ) throws(SCTPWireError) -> Self {
        guard length >= 16, (length - 16) % 2 == 0 else {
            throw .decode(.invalidFormat("Invalid Outgoing SSN Reset Request length"))
        }
        guard offset >= 0, offset <= bytes.count, length <= bytes.count - offset else {
            throw .decode(.insufficientData(expected: offset + length, actual: bytes.count))
        }

        var streamIDs: [UInt16] = []
        streamIDs.reserveCapacity((length - 16) / 2)
        var streamOffset = offset + 16
        while streamOffset < offset + length {
            streamIDs.append(sctpReadUInt16(bytes, offset: streamOffset))
            streamOffset += 2
        }

        return Self(
            requestSequenceNumber: sctpReadUInt32(bytes, offset: offset + 4),
            responseSequenceNumber: sctpReadUInt32(bytes, offset: offset + 8),
            senderLastAssignedTSN: sctpReadUInt32(bytes, offset: offset + 12),
            streamIDs: streamIDs
        )
    }
}
