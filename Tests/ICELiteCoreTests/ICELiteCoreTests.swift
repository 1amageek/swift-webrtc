/// Tests for the Embedded-clean ICE Lite state machine core.

import Testing
@testable import ICELiteCore

@Suite("ICE Lite Validated-Peer Cap Tests")
struct ICELiteValidatedPeerCapTests {

    /// The validated-peer set is bounded by `maxValidatedPeers`. A roaming peer
    /// reaching us from many source addresses must not grow the set without
    /// bound; the oldest entry is evicted (FIFO) once the cap is hit.
    @Test("validatedPeers never exceeds the cap")
    func validatedPeersBounded() {
        var sm = ICELiteStateMachine(localUfrag: "ufrag")
        let cap = ICELiteStateMachine.maxValidatedPeers

        for i in 0..<(cap + 500) {
            sm.markValidated(peerKey: "10.0.0.1:\(i)")
            #expect(sm.validatedPeers.count <= cap)
        }
        #expect(sm.validatedPeers.count == cap)
    }

    /// FIFO eviction: the earliest-inserted keys are the ones dropped once the
    /// cap is exceeded, while the most recent `cap` keys remain validated.
    @Test("Oldest validated peers are evicted first")
    func oldestEvictedFirst() {
        var sm = ICELiteStateMachine(localUfrag: "ufrag")
        let cap = ICELiteStateMachine.maxValidatedPeers

        for i in 0..<cap {
            sm.markValidated(peerKey: "peer:\(i)")
        }
        // Insert one more — the first key (peer:0) must be evicted.
        sm.markValidated(peerKey: "peer:\(cap)")

        #expect(!sm.isValidated(peerKey: "peer:0"))
        #expect(sm.isValidated(peerKey: "peer:1"))
        #expect(sm.isValidated(peerKey: "peer:\(cap)"))
        #expect(sm.validatedPeers.count == cap)
    }

    /// Re-validating an already-present key is a membership no-op but refreshes
    /// its recency, so a steadily-active peer is not evicted ahead of peers that
    /// have gone silent.
    @Test("Re-validating refreshes recency without growing the set")
    func revalidateRefreshesRecency() {
        var sm = ICELiteStateMachine(localUfrag: "ufrag")
        let cap = ICELiteStateMachine.maxValidatedPeers

        for i in 0..<cap {
            sm.markValidated(peerKey: "peer:\(i)")
        }
        #expect(sm.validatedPeers.count == cap)

        // Touch peer:0 so it becomes most-recent; membership count is unchanged.
        sm.markValidated(peerKey: "peer:0")
        #expect(sm.validatedPeers.count == cap)

        // Admitting a new key now evicts peer:1 (the new oldest), NOT peer:0.
        sm.markValidated(peerKey: "peer:\(cap)")
        #expect(sm.isValidated(peerKey: "peer:0"))
        #expect(!sm.isValidated(peerKey: "peer:1"))
        #expect(sm.validatedPeers.count == cap)
    }

    /// The cap is a memory bound only — it never relaxes the connectivity check.
    /// `markValidated` is the post-`.accept` hook, so a validated key is always
    /// reported as validated until evicted.
    @Test("A freshly validated peer is reported validated")
    func freshlyValidatedPeerIsValidated() {
        var sm = ICELiteStateMachine(localUfrag: "ufrag")
        sm.markValidated(peerKey: "1.2.3.4:5000")
        #expect(sm.isValidated(peerKey: "1.2.3.4:5000"))
        #expect(sm.state == .connected)
    }

    /// close() clears both the set and its insertion-order bookkeeping.
    @Test("close clears validated peers")
    func closeClearsValidatedPeers() {
        var sm = ICELiteStateMachine(localUfrag: "ufrag")
        sm.markValidated(peerKey: "1.2.3.4:5000")
        sm.close()
        #expect(sm.validatedPeers.isEmpty)
        #expect(!sm.isValidated(peerKey: "1.2.3.4:5000"))
        #expect(sm.state == .closed)
    }
}
