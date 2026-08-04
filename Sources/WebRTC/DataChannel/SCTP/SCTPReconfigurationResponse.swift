/// A Re-configuration Response Parameter (RFC 6525 §4.4).
struct SCTPReconfigurationResponse: Sendable, Equatable {
    static let parameterType: UInt16 = 16

    let responseSequenceNumber: UInt32
    let result: SCTPReconfigurationResult
    let senderNextTSN: UInt32?
    let receiverNextTSN: UInt32?

    init(
        responseSequenceNumber: UInt32,
        result: SCTPReconfigurationResult,
        senderNextTSN: UInt32? = nil,
        receiverNextTSN: UInt32? = nil
    ) {
        self.responseSequenceNumber = responseSequenceNumber
        self.result = result
        self.senderNextTSN = senderNextTSN
        self.receiverNextTSN = receiverNextTSN
    }

    func encodeParameterBytes() throws(SCTPWireError) -> [UInt8] {
        guard (senderNextTSN == nil) == (receiverNextTSN == nil) else {
            throw .decode(.invalidFormat("Both optional TSNs must be present in a reconfiguration response"))
        }
        let length: UInt16 = senderNextTSN == nil ? 12 : 20
        var bytes: [UInt8] = []
        bytes.reserveCapacity(Int(length))
        sctpAppendUInt16(&bytes, Self.parameterType)
        sctpAppendUInt16(&bytes, length)
        sctpAppendUInt32(&bytes, responseSequenceNumber)
        sctpAppendUInt32(&bytes, result.rawValue)
        if let senderNextTSN, let receiverNextTSN {
            sctpAppendUInt32(&bytes, senderNextTSN)
            sctpAppendUInt32(&bytes, receiverNextTSN)
        }
        return bytes
    }

    static func decodeParameter(
        from bytes: [UInt8],
        offset: Int,
        length: Int
    ) throws(SCTPWireError) -> Self {
        guard length == 12 || length == 20 else {
            throw .decode(.invalidFormat("Invalid Re-configuration Response length"))
        }
        guard offset >= 0, offset <= bytes.count, length <= bytes.count - offset else {
            throw .decode(.insufficientData(expected: offset + length, actual: bytes.count))
        }

        return Self(
            responseSequenceNumber: sctpReadUInt32(bytes, offset: offset + 4),
            result: SCTPReconfigurationResult(
                rawValue: sctpReadUInt32(bytes, offset: offset + 8)
            ),
            senderNextTSN: length == 20
                ? sctpReadUInt32(bytes, offset: offset + 12)
                : nil,
            receiverNextTSN: length == 20
                ? sctpReadUInt32(bytes, offset: offset + 16)
                : nil
        )
    }
}
