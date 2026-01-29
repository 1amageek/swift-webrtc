/// ICE Lite Agent (RFC 8445 — Lite implementation)
///
/// ICE Lite is a minimal ICE implementation suitable for server-side deployments.
/// It only responds to connectivity checks (no active checking or candidate gathering).
/// ICE Lite always acts as the controlled agent.

import Foundation
import Synchronization
import STUNCore

/// ICE validation errors
public enum ICEValidationError: Error, Sendable {
    case missingUsername
    case invalidUsernameFormat
    case localUfragMismatch
    case missingMessageIntegrity
    case invalidMessageIntegrity
    case fingerprintVerificationFailed
    case roleConflict
}

/// ICE Lite agent for server-side connectivity checks
public final class ICELiteAgent: Sendable {
    private let agentState: Mutex<AgentState>

    private struct AgentState: Sendable {
        var state: ICEState = .new
        var credentials: ICECredentials
        var validatedPeers: Set<String> = [] // "ip:port" of validated peers
    }

    /// ICE credentials
    public var credentials: ICECredentials {
        agentState.withLock { $0.credentials }
    }

    /// Current ICE state
    public var state: ICEState {
        agentState.withLock { $0.state }
    }

    public init(credentials: ICECredentials = ICECredentials()) {
        self.agentState = Mutex(AgentState(credentials: credentials))
    }

    /// Set remote credentials (from SDP exchange)
    public func setRemoteCredentials(ufrag: String, password: String) {
        agentState.withLock { s in
            s.credentials.remoteUfrag = ufrag
            s.credentials.remotePassword = password
            if s.state == .new {
                s.state = .checking
            }
        }
    }

    /// Process an incoming STUN message (connectivity check)
    /// - Parameters:
    ///   - data: The raw STUN message bytes
    ///   - sourceAddress: Source IP (4 or 16 bytes)
    ///   - sourcePort: Source port
    /// - Returns: Response STUN message bytes, or nil if not a valid check
    public func processSTUN(
        data: Data,
        sourceAddress: Data,
        sourcePort: UInt16
    ) -> Data? {
        guard STUNMessage.isSTUN(data) else { return nil }

        let message: STUNMessage
        do {
            message = try STUNMessage.decode(from: data)
        } catch {
            return nil
        }

        guard message.messageType == .bindingRequest else {
            return nil
        }

        let (key, localUfrag) = agentState.withLock { s in
            (s.credentials.stunKey, s.credentials.localUfrag)
        }

        // P0.3: Validate USERNAME attribute
        do {
            try validateUsername(message: message, expectedLocalUfrag: localUfrag)
        } catch let error as ICEValidationError {
            return buildErrorResponse(
                transactionID: message.transactionID,
                error: error,
                key: key
            )
        } catch {
            return nil
        }

        // P0.4: Validate FINGERPRINT if present
        if message.attribute(ofType: .fingerprint) != nil {
            guard STUNFingerprint.verify(message: data) else {
                return buildErrorResponse(
                    transactionID: message.transactionID,
                    error: .fingerprintVerificationFailed,
                    key: key
                )
            }
        }

        // P0.5: Verify MESSAGE-INTEGRITY (required)
        let integrityResult = MessageIntegrity.verifyWithResult(message: data, key: key)
        switch integrityResult {
        case .missing:
            return buildErrorResponse(
                transactionID: message.transactionID,
                error: .missingMessageIntegrity,
                key: key
            )
        case .invalid:
            return buildErrorResponse(
                transactionID: message.transactionID,
                error: .invalidMessageIntegrity,
                key: key
            )
        case .valid:
            break // Continue processing
        }

        // P1.1: Role conflict detection
        // ICE Lite is always controlled. If we receive ICE-CONTROLLED, it's a conflict.
        if message.attribute(ofType: .iceControlled) != nil {
            return buildErrorResponse(
                transactionID: message.transactionID,
                error: .roleConflict,
                key: key
            )
        }

        // Mark peer as validated
        let peerKey = addressKey(address: sourceAddress, port: sourcePort)
        agentState.withLock { s in
            s.validatedPeers.insert(peerKey)
            if s.state == .checking || s.state == .new {
                s.state = .connected
            }
        }

        // Build success response
        let response = STUNMessage.bindingSuccessResponse(
            transactionID: message.transactionID,
            address: sourceAddress,
            port: sourcePort
        )

        return response.encodeWithIntegrity(key: key)
    }

    /// Whether a peer at the given address has been validated
    public func isPeerValidated(address: Data, port: UInt16) -> Bool {
        let key = addressKey(address: address, port: port)
        return agentState.withLock { $0.validatedPeers.contains(key) }
    }

    /// Complete ICE processing
    public func complete() {
        agentState.withLock { s in
            if s.state == .connected {
                s.state = .completed
            }
        }
    }

    /// Close the ICE agent
    public func close() {
        agentState.withLock { s in
            s.state = .closed
            s.validatedPeers.removeAll()
        }
    }

    // MARK: - Private validation helpers

    private func validateUsername(message: STUNMessage, expectedLocalUfrag: String) throws {
        // P0.3: USERNAME is required for connectivity checks
        guard let usernameAttr = message.attribute(ofType: .username) else {
            throw ICEValidationError.missingUsername
        }

        guard let username = String(data: usernameAttr.value, encoding: .utf8) else {
            throw ICEValidationError.invalidUsernameFormat
        }

        // RFC 8445: USERNAME format is "remoteUfrag:localUfrag"
        // From our perspective as the receiving server:
        // - The first part is the remote peer's ufrag (which we may have set via SDP)
        // - The second part must match our localUfrag
        let parts = username.split(separator: ":", maxSplits: 1)
        guard parts.count == 2 else {
            throw ICEValidationError.invalidUsernameFormat
        }

        let receivedLocalUfrag = String(parts[1])
        guard receivedLocalUfrag == expectedLocalUfrag else {
            throw ICEValidationError.localUfragMismatch
        }
    }

    private func buildErrorResponse(
        transactionID: TransactionID,
        error: ICEValidationError,
        key: Data
    ) -> Data {
        let (code, reason): (UInt16, String) = switch error {
        case .missingUsername:
            (STUNErrorCode.badRequest.rawValue, "Missing USERNAME")
        case .invalidUsernameFormat:
            (STUNErrorCode.badRequest.rawValue, "Invalid USERNAME format")
        case .localUfragMismatch:
            (STUNErrorCode.unauthorized.rawValue, "USERNAME mismatch")
        case .missingMessageIntegrity:
            (STUNErrorCode.unauthorized.rawValue, "Missing MESSAGE-INTEGRITY")
        case .invalidMessageIntegrity:
            (STUNErrorCode.unauthorized.rawValue, "Bad credentials")
        case .fingerprintVerificationFailed:
            (STUNErrorCode.badRequest.rawValue, "FINGERPRINT verification failed")
        case .roleConflict:
            (STUNErrorCode.roleConflict.rawValue, "Role conflict")
        }

        let errorResp = STUNMessage.bindingErrorResponse(
            transactionID: transactionID,
            errorCode: code,
            reason: reason
        )

        return errorResp.encodeWithIntegrity(key: key)
    }

    private func addressKey(address: Data, port: UInt16) -> String {
        let hex = address.map { String(format: "%02x", $0) }.joined()
        return "\(hex):\(port)"
    }
}
