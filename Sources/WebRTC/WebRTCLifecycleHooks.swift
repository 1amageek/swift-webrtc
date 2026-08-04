/// Package-scoped lifecycle checkpoints for deterministic integration tests.
///
/// Checkpoints run outside every WebRTC mutex and do not receive protocol
/// owners. Production construction leaves both closures `nil`, so no packet or
/// event payload is copied across this boundary.
package struct WebRTCLifecycleHooks: Sendable {
    package let beforeHandshakeCommit: (@Sendable () -> Void)?
    package let beforeSCTPTransaction: (@Sendable () -> Void)?
    package let beforeDataChannelEventHandoff: (@Sendable () -> Void)?

    package init(
        beforeHandshakeCommit: (@Sendable () -> Void)? = nil,
        beforeSCTPTransaction: (@Sendable () -> Void)? = nil,
        beforeDataChannelEventHandoff: (@Sendable () -> Void)? = nil
    ) {
        self.beforeHandshakeCommit = beforeHandshakeCommit
        self.beforeSCTPTransaction = beforeSCTPTransaction
        self.beforeDataChannelEventHandoff = beforeDataChannelEventHandoff
    }
}
