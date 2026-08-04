/// Message identity and persistence shared by every assigned DATA fragment.
struct SCTPAssignedMessage: Sendable, Equatable {
    let firstTSN: UInt32
    let lastTSN: UInt32
    let reliability: SCTPAssignedMessageReliability
}
