/// An Incoming SSN Reset Request Parameter (RFC 6525 §4.2).
struct SCTPIncomingSSNResetRequest: Sendable, Equatable {
    static let parameterType: UInt16 = 14

    let requestSequenceNumber: UInt32
    /// An empty list means all incoming streams.
    let streamIDs: [UInt16]

    init(requestSequenceNumber: UInt32, streamIDs: [UInt16]) {
        self.requestSequenceNumber = requestSequenceNumber
        self.streamIDs = streamIDs
    }

    func encodeParameterBytes() throws(SCTPWireError) -> [UInt8] {
        let (streamBytes, overflow) = streamIDs.count.multipliedReportingOverflow(by: 2)
        let (length, lengthOverflow) = 8.addingReportingOverflow(streamBytes)
        guard !overflow, !lengthOverflow, length <= Int(UInt16.max) else {
            throw .decode(.invalidFormat("Incoming SSN reset stream list exceeds the parameter length field"))
        }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(length)
        sctpAppendUInt16(&bytes, Self.parameterType)
        sctpAppendUInt16(&bytes, UInt16(length))
        sctpAppendUInt32(&bytes, requestSequenceNumber)
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
        guard length >= 8, (length - 8) % 2 == 0 else {
            throw .decode(.invalidFormat("Invalid Incoming SSN Reset Request length"))
        }
        guard offset >= 0, offset <= bytes.count, length <= bytes.count - offset else {
            throw .decode(.insufficientData(expected: offset + length, actual: bytes.count))
        }
        var streamIDs: [UInt16] = []
        streamIDs.reserveCapacity((length - 8) / 2)
        var streamOffset = offset + 8
        while streamOffset < offset + length {
            streamIDs.append(sctpReadUInt16(bytes, offset: streamOffset))
            streamOffset += 2
        }
        return Self(
            requestSequenceNumber: sctpReadUInt32(bytes, offset: offset + 4),
            streamIDs: streamIDs
        )
    }
}
