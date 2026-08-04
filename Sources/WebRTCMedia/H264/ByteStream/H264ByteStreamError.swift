/// Typed failures produced while extracting H.264 NAL-unit ranges.
public enum H264ByteStreamError: Error, Equatable, Sendable {
    case emptyAccessUnit
    case missingAnnexBStartCode
    case nonzeroBytesBeforeFirstStartCode(offset: Int)
    case emptyNALUnit(index: Int)
    case invalidAVCCLengthFieldByteCount(actual: Int)
    case truncatedAVCCLengthField(offset: Int, expected: Int, actual: Int)
    case avccNALUnitOutOfBounds(
        index: Int,
        declaredByteCount: Int,
        availableByteCount: Int
    )
}
