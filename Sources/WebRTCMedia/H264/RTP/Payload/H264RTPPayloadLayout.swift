/// A zero-copy description of one validated inbound RFC 6184 payload.
///
/// All ranges refer to the caller-owned payload passed to the parser. This
/// value stores no `Span`, pointer, or owner reference.
public struct H264RTPPayloadLayout: Sendable, Equatable {
    public let structure: H264RTPPayloadStructure
    public let payloadByteCount: Int

    init(structure: H264RTPPayloadStructure, payloadByteCount: Int) {
        self.structure = structure
        self.payloadByteCount = payloadByteCount
    }
}
