import WebRTC

@main
private enum DataChannelManagerLeakProbe {
    static func main() {
        _ = DataChannelManager(isInitiator: true)
    }
}
