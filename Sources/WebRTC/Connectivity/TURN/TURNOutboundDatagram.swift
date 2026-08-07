/// Scatter-form TURN Send Indication.
///
/// The host transport writes `prefixBytes`, `payload`, and zero padding into
/// its final UDP buffer. Keeping the owned WebRTC payload separate avoids an
/// intermediate full-payload allocation and copy on the media/data path.
public struct TURNOutboundDatagram: Sendable, Equatable {
    public let prefixBytes: [UInt8]
    public let payload: [UInt8]
    public let paddingByteCount: Int

    public var encodedByteCount: Int {
        prefixBytes.count + payload.count + paddingByteCount
    }

    init(
        prefixBytes: [UInt8],
        payload: consuming [UInt8],
        paddingByteCount: Int
    ) {
        self.prefixBytes = prefixBytes
        self.payload = payload
        self.paddingByteCount = paddingByteCount
    }

    func encodedBytesForTesting() -> [UInt8] {
        var bytes = prefixBytes
        bytes.reserveCapacity(encodedByteCount)
        bytes.append(contentsOf: payload)
        bytes.append(contentsOf: repeatElement(0, count: paddingByteCount))
        return bytes
    }
}
