import WebRTC
import WebRTCMedia

private enum ExternalConsumerFixtureError: Error {
    case dataChannelContractUnavailable
    case mediaContractUnavailable
}

@main
private enum ExternalConsumerProbe {
    static func main() throws {
        let channel = DataChannel(
            id: 2,
            generation: 7,
            label: "fixture",
            state: .open
        )
        guard channel.id == 2,
              channel.generation == 7,
              channel.state == .open else {
            throw ExternalConsumerFixtureError.dataChannelContractUnavailable
        }

        let accessUnit: [UInt8] = [0, 0, 0, 1, 0x65, 0x01]
        let ranges = try H264ByteStreamParser().nalUnitRanges(
            in: accessUnit.span,
            format: .annexB
        )
        guard ranges == [4..<6] else {
            throw ExternalConsumerFixtureError.mediaContractUnavailable
        }

        print("WebRTC external consumer facade probe passed")
    }
}
