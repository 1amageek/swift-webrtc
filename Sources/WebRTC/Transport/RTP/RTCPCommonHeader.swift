/// Scalar values from the common four-byte RTCP header.
public struct RTCPCommonHeader: Sendable, Equatable {
    public let hasPadding: Bool
    public let countOrFormat: UInt8
    public let packetType: UInt8
    public let lengthIn32BitWordsMinusOne: UInt16

    init(
        hasPadding: Bool,
        countOrFormat: UInt8,
        packetType: UInt8,
        lengthIn32BitWordsMinusOne: UInt16
    ) {
        self.hasPadding = hasPadding
        self.countOrFormat = countOrFormat
        self.packetType = packetType
        self.lengthIn32BitWordsMinusOne = lengthIn32BitWordsMinusOne
    }
}
