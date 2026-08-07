/// Controlling ICE agent for one nominated UDP candidate pair.
///
/// The agent is sans-I/O: it owns the STUN transaction and validates responses,
/// while the connection owns retransmission scheduling and datagram delivery.

import Synchronization

final class ICEControllingAgent: Sendable {
    enum CheckResult: Sendable, Equatable {
        case send([UInt8])
        case connected
        case failed(String)
    }

    private struct AgentState: Sendable {
        var credentials: ICECredentials
        var state: ICEState = .new
        var transactionID: TransactionID?
        var encodedRequest: [UInt8]?
        var failureReason: String?
        let tiebreaker: UInt64
    }

    private let agentState: FacadeLock<AgentState>

    var credentials: ICECredentials {
        agentState.withLock { $0.credentials }
    }

    var state: ICEState {
        agentState.withLock { $0.state }
    }

    var failureReason: String? {
        agentState.withLock { $0.failureReason }
    }

    init(credentials: ICECredentials) {
        let random = SecureRandom.bytes(count: 8)
        var tiebreaker: UInt64 = 0
        for byte in random {
            tiebreaker = (tiebreaker << 8) | UInt64(byte)
        }
        self.agentState = FacadeLock(AgentState(
            credentials: credentials,
            tiebreaker: tiebreaker
        ))
    }

    func setRemoteCredentials(ufrag: String, password: String) {
        agentState.withLock { state in
            state.credentials.remoteUfrag = ufrag
            state.credentials.remotePassword = password
            state.transactionID = nil
            state.encodedRequest = nil
            state.failureReason = nil
            if state.state != .closed {
                state.state = .new
            }
        }
    }

    /// Returns the original encoded transaction for both the first check and
    /// retransmissions. Reusing the transaction ID is required by STUN.
    func connectivityCheck() -> CheckResult {
        agentState.withLock { state in
            switch state.state {
            case .connected, .completed:
                return .connected
            case .failed:
                return .failed(
                    state.failureReason ?? "ICE connectivity check failed"
                )
            case .closed:
                return .failed("ICE agent is closed")
            case .new, .checking:
                break
            }

            if let encodedRequest = state.encodedRequest {
                state.state = .checking
                return .send(encodedRequest)
            }
            guard let username = state.credentials.stunUsername,
                  let remotePassword = state.credentials.remotePassword else {
                state.state = .failed
                state.failureReason = "Controlling ICE requires remote credentials"
                return .failed("Controlling ICE requires remote credentials")
            }

            let transactionID = TransactionID(
                byteValues: SecureRandom.bytes(count: 12)
            )
            let request = STUNMessage(
                messageType: .bindingRequest,
                transactionID: transactionID,
                attributes: [
                    .username(username),
                    .priority(1_845_501_695),
                    .useCandidate(),
                    .iceControlling(tiebreaker: state.tiebreaker),
                ]
            ).encodeWithIntegrityBytes(key: Array(remotePassword.utf8))

            state.transactionID = transactionID
            state.encodedRequest = request
            state.state = .checking
            return .send(request)
        }
    }

    /// Processes either the response to this agent's nominated check or a
    /// reciprocal connectivity check from the controlled peer.
    ///
    /// Full ICE peers perform triggered checks even when this agent has already
    /// nominated the pair. Answering that request is required before such a peer
    /// will admit DTLS on the candidate pair.
    @discardableResult
    func processSTUNBytes(
        _ data: [UInt8],
        sourceAddress: [UInt8] = [],
        sourcePort: UInt16 = 0
    ) -> [UInt8]? {
        guard STUNMessage.isSTUN(data) else {
            return nil
        }
        let message: STUNMessage
        do {
            message = try STUNMessage.decode(from: data)
        } catch {
            return nil
        }

        if message.messageType == .bindingRequest {
            return processReciprocalCheck(
                message,
                encodedMessage: data,
                sourceAddress: sourceAddress,
                sourcePort: sourcePort
            )
        }

        agentState.withLock { state in
            guard state.state == .checking,
                  message.transactionID == state.transactionID else {
                return
            }

            switch message.messageType {
            case .bindingSuccessResponse:
                if message.attribute(ofType: .fingerprint) != nil,
                   !STUNFingerprint.verify(message: data) {
                    state.state = .failed
                    state.failureReason = "ICE response fingerprint verification failed"
                    return
                }
                guard let remotePassword = state.credentials.remotePassword else {
                    state.state = .failed
                    state.failureReason = "ICE response credentials are unavailable"
                    return
                }
                guard MessageIntegrity.verifyWithResultBytes(
                    message: data,
                    key: Array(remotePassword.utf8)
                ) == .valid else {
                    state.state = .failed
                    state.failureReason = "ICE response integrity verification failed"
                    return
                }
                guard let mappedAddress = message.attribute(ofType: .xorMappedAddress),
                      mappedAddress.parseXorMappedAddress(
                        transactionID: message.transactionID
                      ) != nil else {
                    state.state = .failed
                    state.failureReason = "ICE response has no valid XOR-MAPPED-ADDRESS"
                    return
                }
                state.state = .connected

            case .bindingErrorResponse:
                state.state = .failed
                state.failureReason = "ICE peer rejected the connectivity check"

            default:
                return
            }
        }
        return nil
    }

    func fail(_ reason: String) {
        agentState.withLock { state in
            guard state.state != .closed else { return }
            state.state = .failed
            state.failureReason = reason
        }
    }

    func complete() {
        agentState.withLock { state in
            if state.state == .connected {
                state.state = .completed
            }
        }
    }

    func close() {
        agentState.withLock { state in
            state.state = .closed
            state.transactionID = nil
            state.encodedRequest = nil
        }
    }

    private func processReciprocalCheck(
        _ message: STUNMessage,
        encodedMessage: [UInt8],
        sourceAddress: [UInt8],
        sourcePort: UInt16
    ) -> [UInt8]? {
        guard sourceAddress.count == 4 || sourceAddress.count == 16 else {
            return nil
        }

        let credentials = agentState.withLock { state -> ICECredentials? in
            state.state == .closed ? nil : state.credentials
        }
        guard let credentials else { return nil }
        let key = Array(credentials.localPassword.utf8)

        guard let usernameAttribute = message.attribute(ofType: .username) else {
            return errorResponse(
                transactionID: message.transactionID,
                code: .badRequest,
                reason: "Missing USERNAME",
                key: key
            )
        }
        guard let username = Self.utf8String(usernameAttribute.value),
              let remoteUfrag = credentials.remoteUfrag else {
            return errorResponse(
                transactionID: message.transactionID,
                code: .badRequest,
                reason: "Invalid USERNAME",
                key: key
            )
        }
        let expectedUsername = "\(credentials.localUfrag):\(remoteUfrag)"
        guard username == expectedUsername else {
            return errorResponse(
                transactionID: message.transactionID,
                code: .unauthorized,
                reason: "USERNAME mismatch",
                key: key
            )
        }

        if message.attribute(ofType: .fingerprint) != nil,
           !STUNFingerprint.verify(message: encodedMessage) {
            return errorResponse(
                transactionID: message.transactionID,
                code: .badRequest,
                reason: "FINGERPRINT verification failed",
                key: key
            )
        }
        guard MessageIntegrity.verifyWithResultBytes(
            message: encodedMessage,
            key: key
        ) == .valid else {
            return errorResponse(
                transactionID: message.transactionID,
                code: .unauthorized,
                reason: "Bad credentials",
                key: key
            )
        }

        if message.attribute(ofType: .iceControlling) != nil {
            return errorResponse(
                transactionID: message.transactionID,
                code: .roleConflict,
                reason: "Role conflict",
                key: key
            )
        }
        guard let controlled = message.attribute(ofType: .iceControlled),
              controlled.value.count == 8,
              let priority = message.attribute(ofType: .priority),
              priority.value.count == 4 else {
            return errorResponse(
                transactionID: message.transactionID,
                code: .badRequest,
                reason: "Missing ICE attributes",
                key: key
            )
        }

        return STUNMessage.bindingSuccessResponse(
            transactionID: message.transactionID,
            address: sourceAddress,
            port: sourcePort
        ).encodeWithIntegrityBytes(key: key)
    }

    private func errorResponse(
        transactionID: TransactionID,
        code: STUNErrorCode,
        reason: String,
        key: [UInt8]
    ) -> [UInt8] {
        STUNMessage.bindingErrorResponse(
            transactionID: transactionID,
            errorCode: code.rawValue,
            reason: reason
        ).encodeWithIntegrityBytes(key: key)
    }

    private static func utf8String(_ bytes: [UInt8]) -> String? {
        var decoder = Unicode.UTF8()
        var iterator = bytes.makeIterator()
        var scalars = String.UnicodeScalarView()
        decodeLoop: while true {
            switch decoder.decode(&iterator) {
            case .scalarValue(let scalar):
                scalars.append(scalar)
            case .emptyInput:
                break decodeLoop
            case .error:
                return nil
            }
        }
        return String(scalars)
    }
}
