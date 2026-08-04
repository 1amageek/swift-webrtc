/// A validated NAL unit header and its range in a caller-owned byte buffer.
///
/// This value never retains the buffer. The caller must keep the exact owner
/// alive while extracting a borrowed view from ``range``.
public struct H264NALUnitLayout: Sendable, Equatable {
    public let header: H264NALUnitHeader
    public let range: Range<Int>

    init(header: H264NALUnitHeader, range: Range<Int>) {
        self.header = header
        self.range = range
    }
}
