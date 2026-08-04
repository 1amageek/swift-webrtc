import WebRTCMedia

private enum WebRTCMediaOnlyFixtureError: Error {
    case byteStreamContractUnavailable
}

private func payloadRange(of layout: RTPPacketLayout) -> Range<Int> {
    layout.payloadRange
}

private func isTypedWireFailure(_ failure: RTPWireError) -> Bool {
    switch failure {
    case .integerOverflow:
        true
    default:
        false
    }
}

@main
private enum WebRTCMediaOnlyProbe {
    static func main() throws {
        let accessUnit: [UInt8] = [0, 0, 0, 1, 0x65, 0x01]
        let ranges = try H264ByteStreamParser().nalUnitRanges(
            in: accessUnit.span,
            format: .annexB
        )
        guard ranges == [4..<6] else {
            throw WebRTCMediaOnlyFixtureError.byteStreamContractUnavailable
        }

        _ = payloadRange
        _ = isTypedWireFailure
        print("WebRTCMedia-only consumer probe passed")
    }
}
