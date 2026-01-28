/// ICE Lite Agent (RFC 8445 — Lite implementation)
///
/// ICE Lite is a minimal ICE implementation suitable for server-side deployments.
/// It only responds to connectivity checks (no active checking or candidate gathering).

import Foundation
import Synchronization
import STUNCore

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

        // Verify MESSAGE-INTEGRITY
        let key = agentState.withLock { $0.credentials.stunKey }
        guard MessageIntegrity.verify(message: data, key: key) else {
            let errorResp = STUNMessage.bindingErrorResponse(
                transactionID: message.transactionID,
                errorCode: STUNErrorCode.unauthorized.rawValue,
                reason: "Bad credentials"
            )
            return errorResp.encode()
        }

        // Mark peer as validated
        let peerKey = addressKey(address: sourceAddress, port: sourcePort)
        let isNewPeer = agentState.withLock { s -> Bool in
            let isNew = !s.validatedPeers.contains(peerKey)
            s.validatedPeers.insert(peerKey)
            if s.state == .checking || s.state == .new {
                s.state = .connected
            }
            return isNew
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

    private func addressKey(address: Data, port: UInt16) -> String {
        let hex = address.map { String(format: "%02x", $0) }.joined()
        return "\(hex):\(port)"
    }
}
