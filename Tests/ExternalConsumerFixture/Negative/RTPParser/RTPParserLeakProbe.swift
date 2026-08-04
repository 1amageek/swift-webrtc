import WebRTCMedia

@main
private enum RTPParserLeakProbe {
    static func main() {
        _ = RFC3550RTPPacketParser()
    }
}
