/// Role-erased ICE owner used by `WebRTCConnection`.
///
/// Every case preserves the same owner and synchronization contract on Native,
/// WASM, and Embedded. Platform differences remain below `FacadeLock`.
enum WebRTCICEAgent: Sendable {
    case prevalidated(ICELiteAgent)
    case lite(ICELiteAgent)
    case controlling(ICEControllingAgent)

    init(configuration: WebRTCICEConfiguration) {
        switch configuration.role {
        case .prevalidated:
            self = .prevalidated(ICELiteAgent(
                credentials: configuration.credentials
            ))
        case .lite:
            self = .lite(ICELiteAgent(credentials: configuration.credentials))
        case .controlling:
            self = .controlling(ICEControllingAgent(
                credentials: configuration.credentials
            ))
        }
    }

    var credentials: ICECredentials {
        switch self {
        case .prevalidated(let agent), .lite(let agent):
            return agent.credentials
        case .controlling(let agent):
            return agent.credentials
        }
    }

    var state: ICEState {
        switch self {
        case .prevalidated:
            return .completed
        case .lite(let agent):
            return agent.state
        case .controlling(let agent):
            return agent.state
        }
    }

    var failureReason: String? {
        switch self {
        case .prevalidated, .lite:
            return nil
        case .controlling(let agent):
            return agent.failureReason
        }
    }

    var requiresConnectivityCheckBeforeDTLS: Bool {
        if case .controlling = self { return true }
        return false
    }

    func setRemoteCredentials(ufrag: String, password: String) {
        switch self {
        case .prevalidated(let agent), .lite(let agent):
            agent.setRemoteCredentials(ufrag: ufrag, password: password)
        case .controlling(let agent):
            agent.setRemoteCredentials(ufrag: ufrag, password: password)
        }
    }

    func connectivityCheck() -> ICEControllingAgent.CheckResult? {
        guard case .controlling(let agent) = self else { return nil }
        return agent.connectivityCheck()
    }

    func processSTUNBytes(
        data: [UInt8],
        sourceAddress: [UInt8],
        sourcePort: UInt16
    ) -> [UInt8]? {
        switch self {
        case .prevalidated(let agent), .lite(let agent):
            return agent.processSTUNBytes(
                data: data,
                sourceAddress: sourceAddress,
                sourcePort: sourcePort
            )
        case .controlling(let agent):
            return agent.processSTUNBytes(
                data,
                sourceAddress: sourceAddress,
                sourcePort: sourcePort
            )
        }
    }

    func fail(_ reason: String) {
        if case .controlling(let agent) = self {
            agent.fail(reason)
        }
    }

    func complete() {
        switch self {
        case .prevalidated(let agent), .lite(let agent):
            agent.complete()
        case .controlling(let agent):
            agent.complete()
        }
    }

    func close() {
        switch self {
        case .prevalidated(let agent), .lite(let agent):
            agent.close()
        case .controlling(let agent):
            agent.close()
        }
    }
}
