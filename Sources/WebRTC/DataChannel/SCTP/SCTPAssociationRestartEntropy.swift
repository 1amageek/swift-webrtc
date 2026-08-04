/// Fresh handshake values used only when an unexpected INIT requires a new TCB.
///
/// The synchronized adapter obtains these values before entering the engine
/// transaction. The Sans-I/O engine never performs platform randomness or I/O.
struct SCTPAssociationRestartEntropy: Sendable, Equatable {
    /// Fresh nonzero Initiate Tag advertised in the restart INIT-ACK.
    let initiateTag: UInt32

    /// Fresh Initial TSN advertised in the restart INIT-ACK.
    let initialTSN: UInt32

    init(initiateTag: UInt32, initialTSN: UInt32) {
        self.initiateTag = initiateTag
        self.initialTSN = initialTSN
    }
}
