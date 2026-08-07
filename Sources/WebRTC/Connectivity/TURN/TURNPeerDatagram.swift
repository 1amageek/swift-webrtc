public struct TURNPeerDatagram: Sendable, Equatable {
    public let peerAddress: TURNAddress
    public let payload: [UInt8]

    init(
        peerAddress: TURNAddress,
        payload: consuming [UInt8]
    ) {
        self.peerAddress = peerAddress
        self.payload = payload
    }
}
