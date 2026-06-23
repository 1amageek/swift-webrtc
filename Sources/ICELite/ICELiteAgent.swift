/// ICE Lite Agent (RFC 8445 — Lite implementation) — Foundation adapter.
///
/// ICE Lite is a minimal ICE implementation suitable for server-side deployments.
/// It only responds to connectivity checks (no active checking or candidate
/// gathering) and always acts as the controlled agent.
///
/// The connectivity-check decision logic and state machine live in the
/// Embedded-clean `ICELiteCore`. This adapter holds that value behind a `Mutex`
/// (the proven caller-locked pattern), performs the wire decode and the crypto
/// checks (FINGERPRINT / MESSAGE-INTEGRITY) the core asks for, and builds the
/// `Data` STUN responses. The decision is fail-closed: the core returns
/// `.reject` on any validation failure and this adapter answers with a STUN
/// error response, never a success.

import Foundation
import Synchronization
import STUNCore
// Re-export the Embedded-clean core so existing call sites keep using
// `ICELite.ICEState` / `ICELite.ICEValidationError` (incl. enum-case usage in
// default arguments) unchanged, matching the SCTPWireCompat `@_exported` pattern.
@_exported import ICELiteCore

/// ICE Lite agent for server-side connectivity checks.
public final class ICELiteAgent: Sendable {
    private let agentState: Mutex<AgentState>

    private struct AgentState: Sendable {
        /// The pure state machine (state + ufrags + validated peers).
        var core: ICELiteStateMachine
        /// Full credentials, including the password/key the core does not hold.
        var credentials: ICECredentials
    }

    /// ICE credentials
    public var credentials: ICECredentials {
        agentState.withLock { $0.credentials }
    }

    /// Current ICE state
    public var state: ICEState {
        agentState.withLock { $0.core.state }
    }

    public init(credentials: ICECredentials = ICECredentials()) {
        let core = ICELiteStateMachine(
            localUfrag: credentials.localUfrag,
            remoteUfrag: credentials.remoteUfrag
        )
        self.agentState = Mutex(AgentState(core: core, credentials: credentials))
    }

    /// Set remote credentials (from SDP exchange)
    public func setRemoteCredentials(ufrag: String, password: String) {
        agentState.withLock { s in
            s.credentials.remoteUfrag = ufrag
            s.credentials.remotePassword = password
            s.core.setRemoteUfrag(ufrag)
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

        let key = agentState.withLock { $0.credentials.stunKey }

        // Extract the facts the core decides on. USERNAME is decoded here (wire);
        // FINGERPRINT and MESSAGE-INTEGRITY are verified here (crypto) and the
        // *results* are handed to the core.
        let usernameAttr = message.attribute(ofType: .username)
        let hasUsername = usernameAttr != nil
        let username: String? = usernameAttr.flatMap { String(data: $0.value, encoding: .utf8) }

        let hasFingerprint = message.attribute(ofType: .fingerprint) != nil
        let fingerprintValid = hasFingerprint ? STUNFingerprint.verify(message: data) : false

        let integrity = MessageIntegrity.verifyWithResult(message: data, key: key)

        let hasIceControlled = message.attribute(ofType: .iceControlled) != nil

        let input = ICECheckInput(
            messageType: message.messageType,
            username: username,
            hasUsername: hasUsername,
            hasFingerprint: hasFingerprint,
            fingerprintValid: fingerprintValid,
            integrity: integrity,
            hasIceControlled: hasIceControlled
        )

        let peerKey = addressKey(address: sourceAddress, port: sourcePort)

        // Ask the core for the verdict and, on accept, mark the peer validated —
        // both under the same lock so the decision and the state update are atomic.
        let verdict: ICECheckVerdict = agentState.withLock { s in
            let v = s.core.verdict(for: input)
            if case .accept = v {
                s.core.markValidated(peerKey: peerKey)
            }
            return v
        }

        switch verdict {
        case .ignore:
            return nil
        case .reject(let error):
            return buildErrorResponse(
                transactionID: message.transactionID,
                error: error,
                key: key
            )
        case .accept:
            let response = STUNMessage.bindingSuccessResponse(
                transactionID: message.transactionID,
                address: sourceAddress,
                port: sourcePort
            )
            return response.encodeWithIntegrity(key: key)
        }
    }

    /// Whether a peer at the given address has been validated
    public func isPeerValidated(address: Data, port: UInt16) -> Bool {
        let key = addressKey(address: address, port: port)
        return agentState.withLock { $0.core.isValidated(peerKey: key) }
    }

    /// Complete ICE processing
    public func complete() {
        agentState.withLock { $0.core.complete() }
    }

    /// Close the ICE agent
    public func close() {
        agentState.withLock { $0.core.close() }
    }

    // MARK: - Private helpers

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
        case .remoteUfragMismatch:
            (STUNErrorCode.unauthorized.rawValue, "Remote ufrag mismatch")
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
