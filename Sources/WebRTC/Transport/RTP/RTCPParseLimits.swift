/// Resource limits applied before allocating RTCP packet-layout metadata.
struct RTCPParseLimits: Sendable, Equatable {
    let maximumPacketCount: Int

    init(maximumPacketCount: Int = 64) {
        self.maximumPacketCount = maximumPacketCount
    }
}
