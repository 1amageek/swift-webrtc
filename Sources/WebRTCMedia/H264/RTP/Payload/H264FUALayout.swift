/// Validated metadata for one inbound FU-A payload.
public struct H264FUALayout: Sendable, Equatable {
    public let indicator: H264NALUnitHeader
    public let originalNALUnitHeader: H264NALUnitHeader
    public let fragmentRange: Range<Int>
    public let isStart: Bool
    public let isEnd: Bool

    init(
        indicator: H264NALUnitHeader,
        originalNALUnitHeader: H264NALUnitHeader,
        fragmentRange: Range<Int>,
        isStart: Bool,
        isEnd: Bool
    ) {
        self.indicator = indicator
        self.originalNALUnitHeader = originalNALUnitHeader
        self.fragmentRange = fragmentRange
        self.isStart = isStart
        self.isEnd = isEnd
    }
}
