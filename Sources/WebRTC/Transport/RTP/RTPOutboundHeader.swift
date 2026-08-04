/// Values used to construct an RTP header before payload and SRTP assembly.
package struct RTPOutboundHeader: Sendable, Equatable {
    package let marker: Bool
    package let payloadType: UInt8
    package let sequenceNumber: UInt16
    package let timestamp: UInt32
    package let synchronizationSource: UInt32
    package let contributingSources: [UInt32]

    package init(
        marker: Bool,
        payloadType: UInt8,
        sequenceNumber: UInt16,
        timestamp: UInt32,
        synchronizationSource: UInt32,
        contributingSources: [UInt32] = []
    ) {
        self.marker = marker
        self.payloadType = payloadType
        self.sequenceNumber = sequenceNumber
        self.timestamp = timestamp
        self.synchronizationSource = synchronizationSource
        self.contributingSources = contributingSources
    }
}
