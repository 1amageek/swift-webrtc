/// Scalar fields from one H.264 NAL unit header octet.
public struct H264NALUnitHeader: Sendable, Equatable {
    public let hasForbiddenBit: Bool
    public let referenceIndicator: UInt8
    public let unitType: UInt8

    public init(rawValue: UInt8) {
        self.hasForbiddenBit = rawValue & 0x80 != 0
        self.referenceIndicator = (rawValue >> 5) & 0x03
        self.unitType = rawValue & 0x1F
    }

    public var rawValue: UInt8 {
        (hasForbiddenBit ? 0x80 : 0)
            | ((referenceIndicator & 0x03) << 5)
            | (unitType & 0x1F)
    }
}
