/// Embedded-clean ICE Lite state machine (RFC 8445 — Lite implementation).
///
/// ICE Lite is a minimal, server-side ICE implementation: it only responds to
/// connectivity checks (no active checking or candidate gathering) and always
/// acts as the controlled agent.
///
/// This core is a pure value type holding the ICE state, the decision-relevant
/// credential fields, and the validated-peer set. It owns ALL connectivity-check
/// decisions and state transitions; it performs no crypto and no wire codec. The
/// `ICELite` adapter decodes the STUN message, runs the crypto checks
/// (FINGERPRINT / MESSAGE-INTEGRITY) it is told to, then feeds the resulting
/// facts here for the decision. The verdict is fail-closed: any validation
/// failure yields `.reject(error)`, never `.accept`.
///
/// Following the proven caller-locked pattern, the adapter (`ICELiteAgent`) holds
/// this value behind a `Mutex` and mutates it under the lock. ICE Lite is not
/// time-bound, so no clock is injected.


/// The verdict the core returns for an inbound connectivity check.
enum ICECheckVerdict: Sendable, Equatable {
    /// The check passed; build a binding success response and the peer is
    /// validated.
    case accept
    /// The check failed; build a binding error response for `error`.
    case reject(ICEValidationError)
    /// Not a connectivity check we handle; produce no response.
    case ignore
}

/// The facts the adapter extracts from a decoded STUN message before asking the
/// core for a verdict. Crypto results (`fingerprint`, `integrity`) are computed
/// adapter-side and passed in; the core decides what they mean.
struct ICECheckInput: Sendable, Equatable {
    /// The message type (only `.bindingRequest` is processed as a check).
    let messageType: STUNMessageType
    /// The decoded USERNAME attribute value as a UTF-8 string, if present and
    /// decodable; `nil` if the attribute is absent or not valid UTF-8.
    let username: String?
    /// Whether a USERNAME attribute was present at all (distinguishes "absent"
    /// from "present but not UTF-8").
    let hasUsername: Bool
    /// Whether a FINGERPRINT attribute was present.
    let hasFingerprint: Bool
    /// If a FINGERPRINT was present, whether it verified (adapter-computed).
    let fingerprintValid: Bool
    /// The MESSAGE-INTEGRITY verification result (adapter-computed via the seam).
    let integrity: IntegrityResult
    /// Whether an ICE-CONTROLLED attribute was present (a role conflict for a
    /// Lite agent, which is always controlled).
    let hasIceControlled: Bool

    init(
        messageType: STUNMessageType,
        username: String?,
        hasUsername: Bool,
        hasFingerprint: Bool,
        fingerprintValid: Bool,
        integrity: IntegrityResult,
        hasIceControlled: Bool
    ) {
        self.messageType = messageType
        self.username = username
        self.hasUsername = hasUsername
        self.hasFingerprint = hasFingerprint
        self.fingerprintValid = fingerprintValid
        self.integrity = integrity
        self.hasIceControlled = hasIceControlled
    }
}

/// Pure ICE Lite state machine value type.
struct ICELiteStateMachine: Sendable, Equatable {
    /// Current ICE state.
    private(set) var state: ICEState

    /// Local username fragment (used to validate the USERNAME's local half).
    let localUfrag: String

    /// Remote username fragment, once known from signaling. When set, the
    /// USERNAME's remote half is asserted too.
    private(set) var remoteUfrag: String?

    /// Validated peer keys ("address:port"), supplied by the adapter.
    private(set) var validatedPeers: Set<String>

    /// Insertion order of `validatedPeers`, oldest first, used for FIFO eviction
    /// once the cap is reached. Kept in lockstep with `validatedPeers`.
    private var validatedPeerOrder: [String]

    /// Hard cap on the validated-peer set. A single roaming peer reaching us from
    /// many source addresses would otherwise grow `validatedPeers` without bound;
    /// the cap bounds memory by evicting the oldest entry (FIFO). It does NOT relax
    /// the connectivity check — a peer is only ever inserted after `verdict(for:)`
    /// returns `.accept`.
    static let maxValidatedPeers: Int = 1000

    init(
        localUfrag: String,
        remoteUfrag: String? = nil,
        state: ICEState = .new
    ) {
        self.localUfrag = localUfrag
        self.remoteUfrag = remoteUfrag
        self.state = state
        self.validatedPeers = []
        self.validatedPeerOrder = []
    }

    // MARK: - State transitions (caller-locked; adapter holds the Mutex)

    /// Records the remote credentials' ufrag. Moves `.new` to `.checking`,
    /// matching the historical agent behavior.
    mutating func setRemoteUfrag(_ ufrag: String) {
        remoteUfrag = ufrag
        if state == .new {
            state = .checking
        }
    }

    /// Completes ICE: `.connected` becomes `.completed`.
    mutating func complete() {
        if state == .connected {
            state = .completed
        }
    }

    /// Closes the agent: state becomes `.closed` and the validated-peer set is
    /// cleared.
    mutating func close() {
        state = .closed
        validatedPeers.removeAll()
        validatedPeerOrder.removeAll()
    }

    // MARK: - Connectivity check decision (pure, fail-closed)

    /// Decides the verdict for an inbound connectivity check from the
    /// adapter-supplied facts. On `.accept`, the caller should mark `peerKey`
    /// validated via ``markValidated(peerKey:)`` and build a success response.
    ///
    /// The check order mirrors the historical agent exactly:
    /// 1. only `.bindingRequest` is a check (else `.ignore`);
    /// 2. USERNAME present, UTF-8, well-formed, local half matches, and (when the
    ///    remote ufrag is known) the remote half matches;
    /// 3. FINGERPRINT, if present, must verify;
    /// 4. MESSAGE-INTEGRITY must be present and valid;
    /// 5. ICE-CONTROLLED present is a role conflict (Lite is always controlled).
    func verdict(for input: ICECheckInput) -> ICECheckVerdict {
        guard input.messageType == .bindingRequest else {
            return .ignore
        }

        // USERNAME validation.
        guard input.hasUsername else {
            return .reject(.missingUsername)
        }
        guard let username = input.username else {
            return .reject(.invalidUsernameFormat)
        }
        // RFC 8445 Section 7.2.2: the sender constructs USERNAME as
        // "<receiverUfrag>:<senderUfrag>". From this receiving agent's
        // perspective, the local fragment is therefore first.
        let parts = username.split(separator: ":", maxSplits: 1)
        guard parts.count == 2 else {
            return .reject(.invalidUsernameFormat)
        }
        let receivedLocalUfrag = String(parts[0])
        guard receivedLocalUfrag == localUfrag else {
            return .reject(.localUfragMismatch)
        }
        if let remoteUfrag {
            let receivedRemoteUfrag = String(parts[1])
            guard receivedRemoteUfrag == remoteUfrag else {
                return .reject(.remoteUfragMismatch)
            }
        }

        // FINGERPRINT (only if present).
        if input.hasFingerprint {
            guard input.fingerprintValid else {
                return .reject(.fingerprintVerificationFailed)
            }
        }

        // MESSAGE-INTEGRITY (required).
        switch input.integrity {
        case .missing:
            return .reject(.missingMessageIntegrity)
        case .invalid:
            return .reject(.invalidMessageIntegrity)
        case .valid:
            break
        }

        // Role conflict: a Lite agent is always controlled.
        if input.hasIceControlled {
            return .reject(.roleConflict)
        }

        return .accept
    }

    /// Marks `peerKey` validated and advances `.new`/`.checking` to `.connected`.
    /// Call this only after ``verdict(for:)`` returns `.accept`.
    ///
    /// The validated-peer set is bounded by ``maxValidatedPeers``: re-validating a
    /// key already present is a no-op for membership but refreshes its recency, and
    /// admitting a new key past the cap evicts the oldest entry (FIFO). The cap is
    /// purely a memory bound — the caller has already passed the STUN check.
    mutating func markValidated(peerKey: String) {
        if validatedPeers.contains(peerKey) {
            // Refresh recency so a steadily-active peer is not evicted ahead of
            // peers that have gone silent.
            if let idx = validatedPeerOrder.firstIndex(of: peerKey) {
                validatedPeerOrder.remove(at: idx)
            }
            validatedPeerOrder.append(peerKey)
        } else {
            if validatedPeers.count >= Self.maxValidatedPeers, !validatedPeerOrder.isEmpty {
                let evicted = validatedPeerOrder.removeFirst()
                validatedPeers.remove(evicted)
            }
            validatedPeers.insert(peerKey)
            validatedPeerOrder.append(peerKey)
        }
        if state == .checking || state == .new {
            state = .connected
        }
    }

    /// Whether `peerKey` has been validated.
    func isValidated(peerKey: String) -> Bool {
        validatedPeers.contains(peerKey)
    }
}
