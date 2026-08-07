/// WebRTC Connection
///
/// Integrates the full WebRTC Direct protocol stack:
/// UDP → STUN/ICE Lite → DTLS 1.2 → SCTP → Data Channels
///
/// Transport-agnostic: uses a send closure for outgoing data and
/// a `receive(_:remoteAddress:)` method for incoming data.
///
/// DTLS is driven over the swift-tls Tier-1 `DTLSClient`/`DTLSServer` facade via
/// the local ``DTLSEndpoint`` wrapper.

import TLS
import P2PCrypto
import Synchronization
#if canImport(Logging)
import Logging
#endif
// REQUIRED under Embedded for `Task` / `async` (probe P10); the
// host build picks these up from the implicit stdlib import, but the Embedded
// build needs the explicit `_Concurrency` import to bring them into scope.
import _Concurrency
#if canImport(Foundation)
import Foundation
#endif

/// A WebRTC Direct connection over UDP
///
/// ## Concurrency
///
/// All public methods are thread-safe. Datagrams passed to
/// `receive(_:remoteAddress:)` may be called concurrently. SCTP reorders DATA
/// by TSN/SSN, and the canonical data-channel event queue serializes the
/// resulting application effects. No internal lock is held while invoking the
/// external `SendHandler`, so synchronous loopback transports cannot deadlock.
public final class WebRTCConnection: Sendable {
    /// Largest data-channel message that fits in one SCTP packet under the
    /// default conservative path budget.
    public static var defaultMaximumUnfragmentedDataChannelMessageByteCount: Int {
        SCTPAssociationLimits.defaultMaximumDataPayloadByteCount
    }

    /// Synchronously transfers one owned datagram into a bounded transport.
    ///
    /// Success means the transport accepted ownership for transmission; it does
    /// not mean the peer received the datagram. Failure means the transport did
    /// not retain the owner. The consuming contract prevents an extra packet
    /// owner from being kept alive across the WebRTC/transport boundary.
    public typealias SendHandler = @Sendable (
        consuming [UInt8]
    ) -> Result<Void, WebRTCDatagramSendFailure>

    /// Callback for one authenticated and decrypted RTP packet.
    ///
    /// Delivery is admitted under the media-handler lock and invoked after that
    /// lock is released. A callback admitted before concurrent `close()` may
    /// finish after `close()` returns; close detaches the handlers and
    /// permanently rejects later handler installation.
    public typealias RTPHandler = @Sendable (WebRTCRTPPacket) -> Void

    /// Callback for one authenticated and decrypted RTCP datagram.
    ///
    /// Delivery has the same close boundary as ``RTPHandler``.
    public typealias RTCPHandler = @Sendable (WebRTCRTCPPacket) -> Void

    // MARK: - Public properties

    /// Current connection state
    public var state: WebRTCConnectionState {
        connState.withLock { $0.state }
    }

    /// The first typed error that made this connection terminal.
    ///
    /// Background failures, including SCTP retransmission transport rejection,
    /// cannot be returned from a synchronous caller. They remain observable here
    /// without reducing the cause to the state's diagnostic string.
    public var terminalFailure: WebRTCError? {
        connState.withLock { $0.terminalFailure }
    }

    /// Local certificate fingerprint
    public let localFingerprint: CertificateFingerprint

    /// Remote certificate fingerprint, verified after the DTLS handshake.
    ///
    /// The swift-tls Tier-1 DTLS facade surfaces the peer certificate via
    /// `remoteCertificateDER`; ``onHandshakeComplete()`` computes this fingerprint
    /// from it and only stores it after matching `expectedFingerprint`. It remains
    /// `nil` when no expected fingerprint was configured, even if the peer
    /// presented a certificate. The fail-closed verifier rejects the handshake
    /// when an expected fingerprint is configured and the peer fingerprint
    /// mismatches or cannot be obtained.
    public var remoteFingerprint: CertificateFingerprint? {
        connState.withLock { $0.verifiedRemoteFingerprint }
    }

    /// Remote peer's DER-encoded leaf certificate (available after the DTLS
    /// handshake completes).
    ///
    /// The handshake commit snapshots the certificate into connection state.
    /// `nil` therefore means the handshake has not committed or no certificate
    /// was presented; lifecycle admission failures are not collapsed into that
    /// value. The immutable snapshot remains available after close.
    public var remoteCertificateDER: [UInt8]? {
        connState.withLock { $0.presentedRemoteCertificateDER }
    }

    /// Whether authenticated DTLS-SRTP keys are installed for media traffic.
    public var isMediaReady: Bool {
        connState.withLock { $0.mediaProtector != nil }
    }

    /// Read-only lifecycle diagnostics used by concurrency regression tests.
    /// No protocol owner or mutable state escapes this snapshot.
    struct EgressDebugSnapshot: Sendable, Equatable {
        let isTerminal: Bool
        let inFlightCount: UInt64
        let hasReservedTerminalBatch: Bool
        let isOwnerTeardownComplete: Bool
        let areEventsFinished: Bool
        let isNetworkTeardownComplete: Bool
    }

    var egressDebugSnapshot: EgressDebugSnapshot {
        connState.withLock { state in
            EgressDebugSnapshot(
                isTerminal: state.stateMachine.isTerminal,
                inFlightCount: state.egressInFlightCount,
                hasReservedTerminalBatch:
                    state.reservedTerminalEgressToken != nil,
                isOwnerTeardownComplete:
                    state.terminalOwnerTeardownPhase == .complete,
                areEventsFinished: state.areTerminalEventsFinished,
                isNetworkTeardownComplete:
                    state.terminalNetworkTeardownPhase == .closed
            )
        }
    }

    /// Claim the ordered consumer of data-channel lifecycle and payload events.
    ///
    /// The consumer is created eagerly and has a finite owner queue. Failure to
    /// consume it before the bound is reached terminates the connection
    /// explicitly; payloads are never silently dropped. A connection permits
    /// exactly one successful claim and one suspended `next()` call.
    public func claimDataChannelEvents()
        throws(WebRTCError) -> any WebRTCDataChannelEventConsuming {
        try channelState.withLock { state throws(WebRTCError) in
            guard !state.isEventConsumerClaimed else {
                throw .dataChannelEventStreamAlreadyClaimed
            }
            state.isEventConsumerClaimed = true
            return state.eventConsumer
        }
    }

    // MARK: - Private state

    private let dtlsEndpoint: DTLSEndpoint
    private let connState: SharedMutex<ConnState>
    private let channelState: SharedMutex<ChannelState>
    private let mediaHandlerState: SharedMutex<MediaHandlers>
    private let expectedFingerprint: CertificateFingerprint?
    private let mediaConfiguration: WebRTCMediaConfiguration?
    private let logger: WebRTCLogger
    private let lifecycleHooks: WebRTCLifecycleHooks
    private let mediaClassifier = RFC5761MuxClassifier()
    private let rtpParser = RFC3550RTPPacketParser()
    private let rtcpParser = RFC3550RTCPDatagramParser()

    private typealias MediaProtector = AESCM128HMACSHA1SRTPContext

    /// Identity token for packet-by-packet egress admission.
    ///
    /// The token has no mutable state. Replacing the instance invalidates every
    /// previously admitted batch without an integer generation that can wrap.
    private final class EgressEpoch: Sendable {}

    /// Identity for the one final protocol batch reserved by a terminal state
    /// transition. The reservation owns one in-flight lease before any teardown
    /// work can race the caller that emits the batch.
    private final class TerminalEgressToken: Sendable {}

    private struct EgressPermit: Sendable {
        let epoch: EgressEpoch
        let allowsTerminalState: Bool
        let terminalToken: TerminalEgressToken?

        init(
            epoch: EgressEpoch,
            allowsTerminalState: Bool,
            terminalToken: TerminalEgressToken? = nil
        ) {
            self.epoch = epoch
            self.allowsTerminalState = allowsTerminalState
            self.terminalToken = terminalToken
        }
    }

    private struct SCTPEgressBatch: Sendable {
        let packets: [SCTPPacket]
        let permit: EgressPermit
    }

    /// Time + deadline-sleep seam for the SCTP retransmission driver
    /// (`AsyncTimer.sleep(untilNanos:)`, never `Task.sleep` / `ContinuousClock`).
    private let timer: WebRTCTimer

    /// Owns the DTLS and SCTP timer Tasks without retaining this facade.
    private let timerTaskRegistry: TimerTaskRegistry

    /// Connection-independent owner used by the periodic task. The pump owns
    /// only shared protocol state and egress/lifecycle coordinators; it never
    /// stores a `WebRTCConnection` or the Task handle that runs it.
    private let sctpRetransmissionPump: SCTPRetransmissionPump

    /// Shared terminal and egress operations used by synchronous callers and
    /// by the connection-independent SCTP pump.
    private let terminalCoordinator: TerminalCoordinator
    private let egressCoordinator: EgressCoordinator

    /// Serializes each DTLS flight mutation with publication of its timer state.
    ///
    /// The swift-tls facade serializes engine mutation internally, but its lock is
    /// released before this transport can publish the returned timer generation.
    /// Without this outer transaction, a concurrent or synchronously reentrant
    /// receive can publish a newer generation before the older caller publishes
    /// its stale state. No transport callback or suspension occurs under this
    /// lock; it protects only the sans-I/O mutation and timer-owner handoff.
    private let dtlsFlightCoordinator: DTLSFlightCoordinator

    /// Connection-independent DTLS timeout driver. Timer tasks retain this pump,
    /// never the public facade or their own task-handle owner.
    private let dtlsTimeoutPump: DTLSTimeoutPump

    /// Interval between retransmission timer checks
    private static let retransmitTickInterval: Duration = .milliseconds(250)

    /// Reference owner around `Mutex` so a background pump and the public
    /// facade can share one exact state/isolation contract without copying or
    /// weakening the mutex on WASM or Embedded targets.
    private final class SharedMutex<Value: ~Copyable>: Sendable {
        private let storage: Mutex<Value>

        init(_ value: consuming sending Value) {
            self.storage = Mutex(consume value)
        }

        borrowing func withLock<Result: ~Copyable, Failure: Error>(
            _ body: (inout sending Value) throws(Failure) -> sending Result
        ) throws(Failure) -> sending Result {
            try storage.withLock(body)
        }
    }

    private struct ConnState: Sendable {
        var stateMachine: ConnectionStateMachine = ConnectionStateMachine()
        var iceAgent: WebRTCICEAgent
        var sctpAssociation: SCTPAssociation
        var channelManager: DataChannelManager
        var isClient: Bool
        /// The peer fingerprint verified at handshake completion, if obtainable.
        var verifiedRemoteFingerprint: CertificateFingerprint?
        /// Immutable peer certificate snapshot committed with the handshake.
        var presentedRemoteCertificateDER: [UInt8]?
        var mediaProtector: MediaProtector?
        var isDTLSCompletionInProgress: Bool = false
        var terminalFailure: WebRTCError? = nil
        var egressEpoch = EgressEpoch()
        var reservedTerminalEgressToken: TerminalEgressToken?
        var egressInFlightCount: UInt64 = 0
        var terminalOwnerTeardownPhase: TerminalOwnerTeardownPhase = .idle
        var areTerminalEventsFinished = false
        var terminalNetworkTeardownPhase: TerminalNetworkTeardownPhase = .idle

        var state: WebRTCConnectionState {
            stateMachine.state
        }
    }

    private enum TerminalOwnerTeardownPhase: Sendable, Equatable {
        case idle
        case preparing
        case complete
    }

    private enum TerminalNetworkTeardownPhase: Sendable, Equatable {
        case idle
        case closing
        case closed
    }

    private struct ChannelState: Sendable {
        let eventConsumer: WebRTCDataChannelEventConsumer
        let eventBudget: WebRTCDataChannelEventBudget
        var pendingEvents: WebRTCDataChannelEventQueue
        var isDraining = false
        var isEventConsumerClaimed = false
        var isEventFinishRequested = false
        var eventFinishFailure: WebRTCError? = nil
        var areEventsFinished = false
    }

    private static let maximumBufferedDataChannelEventCount = 1_024
    /// Matches the SCTP reassembly/reorder byte ceiling. Completed messages
    /// cannot accumulate beyond the same connection-level memory class merely
    /// by crossing into the application event boundary.
    private static let maximumBufferedDataChannelEventPayloadByteCount =
        16 * 1_024 * 1_024

    private struct MediaHandlers: Sendable {
        var rtp: RTPHandler?
        var rtcp: RTCPHandler?
        var acceptsInstallation = true
    }

    private final class DTLSTimerPublication: Sendable {
        private let generationState: Mutex<UInt64>

        init(generation: UInt64) {
            self.generationState = Mutex(generation)
        }

        var generation: UInt64 {
            generationState.withLock { $0 }
        }

        func publish(generation: UInt64) {
            generationState.withLock { $0 = generation }
        }
    }

    private final class TimerTaskToken: Sendable {}

    private struct TimerTaskOwner: Sendable {
        let token: TimerTaskToken
        var task: Task<Void, Never>?
    }

    private struct DTLSTimerOwner: Sendable {
        let token: TimerTaskToken
        let publication: DTLSTimerPublication
        var task: Task<Void, Never>?
    }

    private final class TimerTaskRegistry: Sendable {
        private struct State: Sendable {
            var sctp: TimerTaskOwner?
            var dtls: DTLSTimerOwner?
        }

        private let state = Mutex(State())

        func withSCTP<Result>(
            _ body: (inout TimerTaskOwner?) -> Result
        ) -> Result {
            state.withLock { body(&$0.sctp) }
        }

        func withDTLS<Result>(
            _ body: (inout DTLSTimerOwner?) -> Result
        ) -> Result {
            state.withLock { body(&$0.dtls) }
        }

        func clearSCTP(token: TimerTaskToken) {
            state.withLock { state in
                if state.sctp?.token === token {
                    state.sctp = nil
                }
            }
        }

        func clearDTLS(token: TimerTaskToken) {
            state.withLock { state in
                if state.dtls?.token === token {
                    state.dtls = nil
                }
            }
        }

        func containsSCTP(token: TimerTaskToken) -> Bool {
            state.withLock { $0.sctp?.token === token }
        }

        func containsDTLS(token: TimerTaskToken) -> Bool {
            state.withLock { $0.dtls?.token === token }
        }

        func attachSCTP(
            _ task: Task<Void, Never>,
            token: TimerTaskToken
        ) -> Bool {
            state.withLock { state in
                guard var owner = state.sctp,
                      owner.token === token else {
                    return false
                }
                owner.task = task
                state.sctp = owner
                return true
            }
        }

        func attachDTLS(
            _ task: Task<Void, Never>,
            token: TimerTaskToken
        ) -> Bool {
            state.withLock { state in
                guard var owner = state.dtls,
                      owner.token === token else {
                    return false
                }
                owner.task = task
                state.dtls = owner
                return true
            }
        }

        func cancelAll() {
            let tasks = state.withLock {
                state -> (Task<Void, Never>?, Task<Void, Never>?) in
                let current = (state.sctp?.task, state.dtls?.task)
                state.sctp = nil
                state.dtls = nil
                return current
            }
            tasks.0?.cancel()
            tasks.1?.cancel()
        }
    }

    private struct DTLSTimeoutSchedule: Sendable {
        let generation: UInt64
        let delayNanos: UInt64
    }

    /// A timer-owner state transition reserved while the DTLS flight mutex is
    /// held, then applied only after that mutex has been released.
    private enum DTLSTimerReconciliation: Sendable {
        case unchanged
        case cancel(Task<Void, Never>?)
        case install(DTLSTimerInstallation)
    }

    private struct DTLSTimerInstallation: Sendable {
        let token: TimerTaskToken
        let publication: DTLSTimerPublication
        let previous: Task<Void, Never>?
        let generation: UInt64
        let delayNanos: UInt64
    }

    private enum DTLSTimeoutDriveResult: Sendable {
        case stopped
        case terminal
        case next(DTLSTimeoutSchedule)
    }

    private struct TerminalOwnerTeardown {
        let channelManager: DataChannelManager
        let mediaProtector: MediaProtector?
    }

    private enum OpenDataChannelResult {
        case success(DataChannel, SCTPEgressBatch)
        case invalidState(WebRTCConnectionState)
        case dataChannelError(DataChannelError)
        case sctpError(SCTPError)
    }

    private enum SendDataResult {
        case success(SCTPEgressBatch)
        case invalidState(WebRTCConnectionState)
        case dataChannelError(DataChannelError)
        case sctpError(SCTPError)
    }

    private enum StreamResetRequestResult {
        case success(SCTPEgressBatch?)
        case invalidState(WebRTCConnectionState)
        case dataChannelError(DataChannelError)
        case sctpError(SCTPError)
    }

    private enum ShutdownRequestResult {
        case success(SCTPEgressBatch?)
        case invalidState(WebRTCConnectionState)
        case terminal(WebRTCError?)
        case sctpError(SCTPError)
    }

    private struct SCTPInboundEffects {
        var packets: [SCTPPacket]
        var egressPermit: EgressPermit?
        var events: [WebRTCDataChannelEvent] = []
        var rejectedStreamIDs: [UInt16] = []
        var becameConnected = false
        var ownsEventDrain = false
    }

    private enum SCTPInboundOutcome {
        case alreadyTerminal(WebRTCError?)
        case discardedVerificationTag(expected: UInt32, actual: UInt32)
        case success(SCTPInboundEffects)
        case closed(SCTPInboundEffects)
        case terminal(SCTPInboundEffects, WebRTCError)
        case failure(WebRTCError)
    }

    private enum StartResult {
        case claimed
        case terminal
        case invalidState(WebRTCConnectionState)
    }

    private enum EgressAdmission {
        case allowed
        case rejected(WebRTCError)
    }

    private enum SCTPRetransmissionDriveResult {
        case stopped
        case success(SCTPEgressBatch?)
        case terminal(SCTPEgressBatch?, SCTPError)
    }

    /// Serializes DTLS engine mutation without owning a timer task or facade.
    private final class DTLSFlightCoordinator: Sendable {
        private let transaction = Mutex<Void>(())

        func perform<Output>(
            _ operation: () throws(TLSError) -> Output
        ) throws(TLSError) -> Output {
            try transaction.withLock { _ throws(TLSError) -> Output in
                try operation()
            }
        }
    }

    /// Owns terminal protocol/application cleanup without retaining the public
    /// connection facade or its periodic Task handle.
    private final class TerminalCoordinator: Sendable {
        private let connState: SharedMutex<ConnState>
        private let channelState: SharedMutex<ChannelState>
        private let mediaHandlerState: SharedMutex<MediaHandlers>
        private let dtlsEndpoint: DTLSEndpoint
        private let logger: WebRTCLogger
        private let lifecycleHooks: WebRTCLifecycleHooks

        init(
            connState: SharedMutex<ConnState>,
            channelState: SharedMutex<ChannelState>,
            mediaHandlerState: SharedMutex<MediaHandlers>,
            dtlsEndpoint: DTLSEndpoint,
            logger: WebRTCLogger,
            lifecycleHooks: WebRTCLifecycleHooks
        ) {
            self.connState = connState
            self.channelState = channelState
            self.mediaHandlerState = mediaHandlerState
            self.dtlsEndpoint = dtlsEndpoint
            self.logger = logger
            self.lifecycleHooks = lifecycleHooks
        }

        func commitFailure(_ error: WebRTCError, context: String) -> Bool {
            let reason = WebRTCConnection.failureReason(error, context: context)
            return connState.withLock { state -> Bool in
                state.sctpAssociation.terminate()
                switch state.stateMachine.state {
                case .closed:
                    return false
                case .failed:
                    if state.terminalFailure == nil {
                        state.terminalFailure = error
                    }
                    return true
                case .new, .connecting, .dtlsHandshaking, .sctpConnecting,
                     .connected, .disconnected, .closing:
                    state.terminalFailure = error
                    _ = state.stateMachine.process(.error(reason))
                    state.egressEpoch = EgressEpoch()
                    return true
                }
            }
        }

        func prepare() {
            let teardown = connState.withLock {
                state -> TerminalOwnerTeardown? in
                guard state.stateMachine.isTerminal,
                      state.terminalOwnerTeardownPhase == .idle else {
                    return nil
                }
                state.terminalOwnerTeardownPhase = .preparing
                state.sctpAssociation.terminate()
                let mediaProtector = state.mediaProtector
                state.mediaProtector = nil
                return TerminalOwnerTeardown(
                    channelManager: state.channelManager,
                    mediaProtector: mediaProtector
                )
            }
            guard let teardown else {
                completeNetworkTeardown()
                return
            }

            teardown.channelManager.shutdown()
            withExtendedLifetime(teardown.mediaProtector) {}

            if let eventFailure = finishDataChannelEvents() {
                let reason = WebRTCConnection.failureReason(
                    eventFailure,
                    context: "Terminal event drain failed"
                )
                logger.warning("Terminal event drain failed: \(reason)")
            }
            let detachedMediaHandlers = mediaHandlerState.withLock {
                handlers -> (RTPHandler?, RTCPHandler?) in
                let current = (handlers.rtp, handlers.rtcp)
                handlers.rtp = nil
                handlers.rtcp = nil
                handlers.acceptsInstallation = false
                return current
            }
            withExtendedLifetime(detachedMediaHandlers) {}

            connState.withLock { state in
                guard state.terminalOwnerTeardownPhase == .preparing else {
                    return
                }
                state.terminalOwnerTeardownPhase = .complete
            }
            completeNetworkTeardown()
        }

        func completeNetworkTeardown() {
            let iceAgent = connState.withLock { state -> WebRTCICEAgent? in
                guard state.stateMachine.isTerminal,
                      state.terminalOwnerTeardownPhase == .complete,
                      state.areTerminalEventsFinished,
                      state.egressInFlightCount == 0,
                      state.terminalNetworkTeardownPhase == .idle else {
                    return nil
                }
                state.terminalNetworkTeardownPhase = .closing
                return state.iceAgent
            }
            guard let iceAgent else { return }

            do {
                _ = try dtlsEndpoint.close()
            } catch {
                let reason = WebRTCConnection.failureReason(
                    error,
                    context: "DTLS close failed"
                )
                logger.warning("DTLS local shutdown failed: \(reason)")
            }
            iceAgent.close()
            connState.withLock { state in
                if state.terminalNetworkTeardownPhase == .closing {
                    state.terminalNetworkTeardownPhase = .closed
                }
            }
        }

        func finishDataChannelEvents() -> WebRTCError? {
            let failure = connState.withLock { $0.terminalFailure }
            enum FinishAction {
                case none
                case drain
                case finish(WebRTCDataChannelEventConsumer, WebRTCError?)
            }
            let action = channelState.withLock { state -> FinishAction in
                guard !state.areEventsFinished,
                      !state.isEventFinishRequested else {
                    return .none
                }
                state.isEventFinishRequested = true
                state.eventFinishFailure = failure
                if state.isDraining { return .none }
                if state.pendingEvents.count == 0 {
                    state.areEventsFinished = true
                    return .finish(state.eventConsumer, failure)
                }
                state.isDraining = true
                return .drain
            }
            switch action {
            case .none:
                if channelState.withLock({ $0.areEventsFinished }) {
                    markEventsFinished()
                }
                return nil
            case .drain:
                return drainDataChannelEvents()
            case .finish(let consumer, let failure):
                consumer.finish(failure: failure)
                markEventsFinished()
                return nil
            }
        }

        func drainDataChannelEvents() -> WebRTCError? {
            while true {
                enum DrainStep {
                    case event(
                        WebRTCDataChannelEvent,
                        WebRTCDataChannelEventConsumer,
                        WebRTCDataChannelEventBudget
                    )
                    case finished
                    case finish(WebRTCDataChannelEventConsumer, WebRTCError?)
                    case terminated
                }

                let step = channelState.withLock { state -> DrainStep in
                    guard state.isDraining else { return .finished }
                    guard !state.areEventsFinished else {
                        state.isDraining = false
                        return .terminated
                    }
                    if let event = state.pendingEvents.popFirst() {
                        return .event(
                            event,
                            state.eventConsumer,
                            state.eventBudget
                        )
                    }
                    state.isDraining = false
                    guard state.isEventFinishRequested else {
                        return .finished
                    }
                    state.areEventsFinished = true
                    return .finish(
                        state.eventConsumer,
                        state.eventFinishFailure
                    )
                }

                switch step {
                case .finished:
                    if channelState.withLock({ $0.areEventsFinished }) {
                        markEventsFinished()
                    }
                    return nil
                case .finish(let consumer, let failure):
                    consumer.finish(failure: failure)
                    markEventsFinished()
                    return nil
                case .terminated:
                    markEventsFinished()
                    return connState.withLock { $0.stateMachine.isTerminal }
                        ? nil
                        : .dataChannelEventStreamTerminated
                case .event(let event, let consumer, let budget):
                    lifecycleHooks.beforeDataChannelEventHandoff?()
                    switch consumer.yieldReserved(event, from: budget) {
                    case .enqueued:
                        continue
                    case .dropped:
                        budget.release(event)
                        let failure = WebRTCError
                            .dataChannelEventBufferExceeded(
                                limit: WebRTCConnection
                                    .maximumBufferedDataChannelEventCount
                            )
                        terminateRejectedEventDrain(failure: failure)
                        return failure
                    case .terminated:
                        budget.release(event)
                        let terminal = connState.withLock {
                            state -> (Bool, WebRTCError?) in
                            (
                                state.stateMachine.isTerminal,
                                state.terminalFailure
                            )
                        }
                        let failure = terminal.1
                            ?? (terminal.0
                                ? .closed
                                : .dataChannelEventStreamTerminated)
                        terminateRejectedEventDrain(failure: failure)
                        return terminal.0 ? nil : failure
                    }
                }
            }
        }

        func terminateRejectedEventDrain(failure: WebRTCError) {
            let cleanup = channelState.withLock { state -> (
                [WebRTCDataChannelEvent],
                WebRTCDataChannelEventConsumer,
                WebRTCDataChannelEventBudget,
                WebRTCError
            )? in
                state.isDraining = false
                guard !state.areEventsFinished else { return nil }
                state.isEventFinishRequested = true
                if state.eventFinishFailure == nil {
                    state.eventFinishFailure = failure
                }
                let finalFailure = state.eventFinishFailure ?? failure
                let pending = state.pendingEvents.drain()
                state.areEventsFinished = true
                return (
                    pending,
                    state.eventConsumer,
                    state.eventBudget,
                    finalFailure
                )
            }
            guard let cleanup else { return }
            cleanup.2.release(cleanup.0)
            cleanup.1.finish(failure: cleanup.3)
            if connState.withLock({ $0.stateMachine.isTerminal }) {
                markEventsFinished()
            }
        }

        private func markEventsFinished() {
            connState.withLock { state in
                guard state.stateMachine.isTerminal else { return }
                state.areTerminalEventsFinished = true
            }
            completeNetworkTeardown()
        }
    }

    /// Drives one DTLS timeout generation without retaining the public facade or
    /// the `Task` handle that invokes it.
    private final class DTLSTimeoutPump: Sendable {
        private let connState: SharedMutex<ConnState>
        private let dtlsEndpoint: DTLSEndpoint
        private let flightCoordinator: DTLSFlightCoordinator
        private let egressCoordinator: EgressCoordinator
        private let terminalCoordinator: TerminalCoordinator
        private let logger: WebRTCLogger

        init(
            connState: SharedMutex<ConnState>,
            dtlsEndpoint: DTLSEndpoint,
            flightCoordinator: DTLSFlightCoordinator,
            egressCoordinator: EgressCoordinator,
            terminalCoordinator: TerminalCoordinator,
            logger: WebRTCLogger
        ) {
            self.connState = connState
            self.dtlsEndpoint = dtlsEndpoint
            self.flightCoordinator = flightCoordinator
            self.egressCoordinator = egressCoordinator
            self.terminalCoordinator = terminalCoordinator
            self.logger = logger
        }

        func drive(
            generation: UInt64,
            publication: DTLSTimerPublication
        ) -> DTLSTimeoutDriveResult {
            guard !connState.withLock({ $0.stateMachine.isTerminal }) else {
                return .terminal
            }

            let timeoutResult = Result<DTLSRetransmissionState?, WebRTCError>(
                catching: { () throws(WebRTCError) -> DTLSRetransmissionState? in
                    try runTimeout(
                        generation: generation,
                        publication: publication
                    )
                }
            )
            switch timeoutResult {
            case .success(let next):
                guard let next,
                      let delay = next.nextDelay else {
                    return .stopped
                }
                return .next(DTLSTimeoutSchedule(
                    generation: next.generation,
                    delayNanos: delay.facadeNanoseconds
                ))
            case .failure(let error):
                if connState.withLock({ $0.stateMachine.isTerminal }) {
                    return .terminal
                }
                let reason = WebRTCConnection.failureReason(
                    error,
                    context: "DTLS retransmission failed"
                )
                logger.error("\(reason)")
                if terminalCoordinator.commitFailure(
                    error,
                    context: "DTLS retransmission failed"
                ) {
                    terminalCoordinator.prepare()
                }
                return .terminal
            }
        }

        private func runTimeout(
            generation: UInt64,
            publication: DTLSTimerPublication
        ) throws(WebRTCError) -> DTLSRetransmissionState? {
            try egressCoordinator.withNormalLease {
                permit throws(WebRTCError) -> DTLSRetransmissionState? in
                let result: DTLSTimeoutResult
                do {
                    result = try flightCoordinator.perform {
                        () throws(TLSError) -> DTLSTimeoutResult in
                        let result = try dtlsEndpoint.handleTimeout(
                            generation: generation
                        )
                        if case .retransmit(_, let next) = result {
                            publication.publish(generation: next.generation)
                        }
                        return result
                    }
                } catch {
                    throw WebRTCError.dtlsHandshakeFailed(
                        WebRTCConnection.failureReason(
                            error,
                            context: "DTLS retransmission limit exceeded"
                        )
                    )
                }

                switch result {
                case .superseded:
                    return nil
                case .retransmit(let datagrams, let next):
                    var emittedDatagram = false
                    for datagram in datagrams {
                        if emittedDatagram {
                            try egressCoordinator.validateNormalPermit(permit)
                        }
                        try egressCoordinator.transfer(consume datagram)
                        emittedDatagram = true
                    }
                    return next
                }
            }
        }
    }

    /// Shared synchronous egress owner. It contains no Task and no reference to
    /// the public connection, so the periodic pump cannot create a retain cycle.
    private final class EgressCoordinator: Sendable {
        private let connState: SharedMutex<ConnState>
        private let dtlsEndpoint: DTLSEndpoint
        private let sendHandler: SendHandler
        private let terminalCoordinator: TerminalCoordinator

        init(
            connState: SharedMutex<ConnState>,
            dtlsEndpoint: DTLSEndpoint,
            sendHandler: @escaping SendHandler,
            terminalCoordinator: TerminalCoordinator
        ) {
            self.connState = connState
            self.dtlsEndpoint = dtlsEndpoint
            self.sendHandler = sendHandler
            self.terminalCoordinator = terminalCoordinator
        }

        func withNormalLease<Output>(
            permit requestedPermit: EgressPermit? = nil,
            _ body: (EgressPermit) throws(WebRTCError) -> Output
        ) throws(WebRTCError) -> Output {
            let permit = try acquireNormalLease(permit: requestedPermit)
            defer { releaseLease() }
            return try body(permit)
        }

        func acquireNormalLease(
            permit requestedPermit: EgressPermit? = nil
        ) throws(WebRTCError) -> EgressPermit {
            let admission = connState.withLock {
                state -> Result<EgressPermit, WebRTCError> in
                guard !state.stateMachine.isTerminal else {
                    return .failure(state.terminalFailure ?? .closed)
                }
                let permit = requestedPermit ?? EgressPermit(
                    epoch: state.egressEpoch,
                    allowsTerminalState: false
                )
                guard !permit.allowsTerminalState,
                      permit.terminalToken == nil,
                      state.egressEpoch === permit.epoch else {
                    return .failure(state.terminalFailure ?? .closed)
                }
                let (nextCount, overflow) = state.egressInFlightCount
                    .addingReportingOverflow(1)
                guard !overflow else {
                    return .failure(.invalidState(
                        "Egress lease count exhausted"
                    ))
                }
                state.egressInFlightCount = nextCount
                return .success(permit)
            }
            switch admission {
            case .success(let permit):
                return permit
            case .failure(let error):
                throw error
            }
        }

        func withReservedTerminalLease<Output>(
            _ permit: EgressPermit,
            _ body: () throws(WebRTCError) -> Output
        ) throws(WebRTCError) -> Output {
            let admission = connState.withLock { state -> EgressAdmission in
                guard permit.allowsTerminalState,
                      let token = permit.terminalToken,
                      state.stateMachine.isTerminal,
                      state.egressEpoch === permit.epoch,
                      state.reservedTerminalEgressToken === token else {
                    return .rejected(state.terminalFailure ?? .closed)
                }
                state.reservedTerminalEgressToken = nil
                return .allowed
            }
            switch admission {
            case .allowed:
                break
            case .rejected(let error):
                throw error
            }
            defer { releaseLease() }
            return try body()
        }

        func abandonReservedTerminalPermit(_ permit: EgressPermit?) {
            guard let permit,
                  permit.allowsTerminalState,
                  let token = permit.terminalToken else {
                return
            }
            let released = connState.withLock { state -> Bool in
                guard state.reservedTerminalEgressToken === token else {
                    return false
                }
                precondition(state.egressInFlightCount > 0)
                state.reservedTerminalEgressToken = nil
                state.egressInFlightCount -= 1
                return true
            }
            if released { terminalCoordinator.completeNetworkTeardown() }
        }

        func releaseLease() {
            connState.withLock { state in
                precondition(state.egressInFlightCount > 0)
                state.egressInFlightCount -= 1
            }
            terminalCoordinator.completeNetworkTeardown()
        }

        func validateNormalPermit(
            _ permit: EgressPermit
        ) throws(WebRTCError) {
            let rejection = connState.withLock { state -> WebRTCError? in
                guard !state.stateMachine.isTerminal,
                      !permit.allowsTerminalState,
                      state.egressEpoch === permit.epoch else {
                    return state.terminalFailure ?? .closed
                }
                return nil
            }
            if let rejection { throw rejection }
        }

        func transfer(
            _ datagram: consuming [UInt8]
        ) throws(WebRTCError) {
            switch sendHandler(consume datagram) {
            case .success:
                return
            case .failure(let failure):
                throw .datagramSendFailed(failure)
            }
        }

        func sendEncrypted(
            _ plaintext: [UInt8],
            permit: EgressPermit
        ) throws(WebRTCError) {
            precondition(
                !permit.allowsTerminalState || permit.terminalToken != nil
            )
            let encrypted: [UInt8]
            do {
                encrypted = try dtlsEndpoint.send(plaintext)
            } catch {
                throw .dtlsHandshakeFailed(WebRTCConnection.failureReason(
                    error,
                    context: "DTLS encrypt/send failed"
                ))
            }
            try transfer(consume encrypted)
        }

        func sendSCTPPackets(
            _ batch: SCTPEgressBatch
        ) throws(WebRTCError) {
            guard !batch.packets.isEmpty else { return }

            if batch.permit.allowsTerminalState {
                try withReservedTerminalLease(batch.permit) {
                    () throws(WebRTCError) -> Void in
                    for packet in batch.packets {
                        try sendEncrypted(
                            packet.encodeBytes(),
                            permit: batch.permit
                        )
                    }
                }
                return
            }

            var emittedPacket = false
            for packet in batch.packets {
                do {
                    try withNormalLease(permit: batch.permit) {
                        permit throws(WebRTCError) in
                        try sendEncrypted(
                            packet.encodeBytes(),
                            permit: permit
                        )
                    }
                    emittedPacket = true
                } catch {
                    if emittedPacket {
                        let wasInvalidated = connState.withLock { state in
                            state.stateMachine.isTerminal
                                || state.egressEpoch !== batch.permit.epoch
                        }
                        if wasInvalidated { return }
                    }
                    throw error
                }
            }
        }
    }

    /// Drives the SCTP clock without retaining `WebRTCConnection`.
    private final class SCTPRetransmissionPump: Sendable {
        private let connState: SharedMutex<ConnState>
        private let egressCoordinator: EgressCoordinator
        private let terminalCoordinator: TerminalCoordinator
        private let logger: WebRTCLogger

        init(
            connState: SharedMutex<ConnState>,
            egressCoordinator: EgressCoordinator,
            terminalCoordinator: TerminalCoordinator,
            logger: WebRTCLogger
        ) {
            self.connState = connState
            self.egressCoordinator = egressCoordinator
            self.terminalCoordinator = terminalCoordinator
            self.logger = logger
        }

        func drive() -> Bool {
            let result = connState.withLock {
                state -> SCTPRetransmissionDriveResult in
                guard !state.stateMachine.isTerminal else { return .stopped }
                switch state.sctpAssociation.pollOutboundPacketsOutcome() {
                case .packets(let packets):
                    let sctpState = state.sctpAssociation.state
                    switch sctpState {
                    case .shutdownPending, .shutdownSent, .shutdownReceived,
                         .shutdownAckSent:
                        _ = state.stateMachine.process(
                            .sctpShutdownStarted(sctpState)
                        )
                    case .closed, .cookieWait, .cookieEchoed, .established:
                        break
                    }
                    guard !packets.isEmpty else { return .success(nil) }
                    return .success(SCTPEgressBatch(
                        packets: packets,
                        permit: EgressPermit(
                            epoch: state.egressEpoch,
                            allowsTerminalState: false
                        )
                    ))
                case .terminal(let packets, let error):
                    let failure = WebRTCError.sctpProtocolFailed(error)
                    if state.terminalFailure == nil {
                        state.terminalFailure = failure
                        _ = state.stateMachine.process(.error(
                            WebRTCConnection.failureReason(
                                failure,
                                context: "SCTP outbound timer terminated"
                            )
                        ))
                    }
                    let permit = WebRTCConnection.reserveTerminalEgress(
                        for: packets,
                        state: &state
                    )
                    let batch = permit.map {
                        SCTPEgressBatch(packets: packets, permit: $0)
                    }
                    return .terminal(batch, error)
                }
            }

            switch result {
            case .stopped:
                return true
            case .success(nil):
                return false
            case .success(let batch?):
                do {
                    try egressCoordinator.sendSCTPPackets(batch)
                } catch {
                    let reason = WebRTCConnection.failureReason(
                        error,
                        context: "SCTP retransmission send failed"
                    )
                    logger.error("\(reason)")
                    if terminalCoordinator.commitFailure(
                        error,
                        context: "SCTP retransmission send failed"
                    ) {
                        terminalCoordinator.prepare()
                    }
                    return true
                }
                return false
            case .terminal(let batch, let error):
                let reason = WebRTCConnection.failureReason(
                    error,
                    context: "SCTP retransmission limit exceeded"
                )
                logger.error("\(reason)")
                terminalCoordinator.prepare()
                defer {
                    egressCoordinator.abandonReservedTerminalPermit(
                        batch?.permit
                    )
                    terminalCoordinator.completeNetworkTeardown()
                }
                if let batch {
                    do {
                        try egressCoordinator.sendSCTPPackets(batch)
                    } catch {
                        let sendReason = WebRTCConnection.failureReason(
                            error,
                            context: "Final SCTP ABORT send failed"
                        )
                        logger.error("\(sendReason)")
                    }
                }
                return true
            }
        }
    }

    // MARK: - Init

    /// Create a client-side connection
    public static func asClient(
        certificate: WebRTCCertificate,
        remoteFingerprint expectedFingerprint: CertificateFingerprint,
        iceConfiguration: WebRTCICEConfiguration = .prevalidated,
        mediaConfiguration: WebRTCMediaConfiguration? = nil,
        negotiatedDataChannels: [WebRTCNegotiatedDataChannel] = [],
        sendHandler: @escaping SendHandler,
        timer: WebRTCTimer = .platformDefault,
        logger: WebRTCLogger = WebRTCLogger(label: "webrtc.connection")
    ) throws(WebRTCError) -> WebRTCConnection {
        try WebRTCConnection(
            certificate: certificate,
            isClient: true,
            expectedFingerprint: expectedFingerprint,
            iceConfiguration: iceConfiguration,
            mediaConfiguration: mediaConfiguration,
            negotiatedDataChannels: negotiatedDataChannels,
            sendHandler: sendHandler,
            timer: timer,
            logger: logger
        )
    }

    /// Create a server-side connection.
    ///
    /// The server always requires the client to present a certificate and prove
    /// possession of its private key (mutual DTLS authentication). When an expected
    /// fingerprint is supplied and matches, it becomes available through
    /// `remoteFingerprint`. Otherwise an upper layer must bind
    /// `remoteCertificateDER` to peer identity before treating it as verified.
    ///
    /// - Parameter remoteFingerprint: When the dialer's certificate fingerprint is
    ///   known ahead of time (e.g. from signaling / a `/certhash` multiaddr), pass it
    ///   to have the handshake fail on mismatch. Pass `nil` when the identity is bound
    ///   by a subsequent layer instead.
    public static func asServer(
        certificate: WebRTCCertificate,
        remoteFingerprint expectedFingerprint: CertificateFingerprint? = nil,
        iceConfiguration: WebRTCICEConfiguration = .prevalidated,
        mediaConfiguration: WebRTCMediaConfiguration? = nil,
        negotiatedDataChannels: [WebRTCNegotiatedDataChannel] = [],
        sendHandler: @escaping SendHandler,
        timer: WebRTCTimer = .platformDefault,
        logger: WebRTCLogger = WebRTCLogger(label: "webrtc.connection")
    ) throws(WebRTCError) -> WebRTCConnection {
        try WebRTCConnection(
            certificate: certificate,
            isClient: false,
            expectedFingerprint: expectedFingerprint,
            iceConfiguration: iceConfiguration,
            mediaConfiguration: mediaConfiguration,
            negotiatedDataChannels: negotiatedDataChannels,
            sendHandler: sendHandler,
            timer: timer,
            logger: logger
        )
    }

    init(
        certificate: WebRTCCertificate,
        isClient: Bool,
        expectedFingerprint: CertificateFingerprint?,
        iceConfiguration: WebRTCICEConfiguration = .prevalidated,
        mediaConfiguration: WebRTCMediaConfiguration?,
        negotiatedDataChannels: [WebRTCNegotiatedDataChannel] = [],
        sendHandler: @escaping SendHandler,
        timer: WebRTCTimer = .platformDefault,
        logger: WebRTCLogger,
        sctpClock: any SCTPMonotonicClock = SCTPSystemMonotonicClock(),
        lifecycleHooks: WebRTCLifecycleHooks = WebRTCLifecycleHooks()
    ) throws(WebRTCError) {
        let iceCredentials = iceConfiguration.credentials
        guard iceCredentials.localUfrag.count >= 4,
              iceCredentials.localPassword.count >= 22 else {
            throw .iceFailed("Local ICE credentials do not meet RFC 8445 length requirements")
        }
        if iceConfiguration.role == .controlling {
            guard let remoteUfrag = iceCredentials.remoteUfrag,
                  remoteUfrag.count >= 4,
                  let remotePassword = iceCredentials.remotePassword,
                  remotePassword.count >= 22 else {
                throw .iceFailed(
                    "Controlling ICE requires valid remote credentials"
                )
            }
        }
        guard mediaConfiguration == nil || expectedFingerprint != nil else {
            throw .mediaPeerAuthenticationRequired
        }
        self.localFingerprint = certificate.fingerprint
        // The DTLS server (this endpoint when !isClient) MUST require the client to
        // present a certificate and prove possession of its private key. Otherwise an
        // attacker could complete the handshake presenting a victim's (public) WebRTC
        // certificate without holding its key — full inbound peer impersonation.
        //
        do {
            self.dtlsEndpoint = try DTLSEndpoint.make(
                certificate: certificate,
                isClient: isClient,
                requireClientCertificate: !isClient,
                mediaConfiguration: mediaConfiguration
            )
        } catch {
            throw .invalidLocalIdentity
        }
        self.expectedFingerprint = expectedFingerprint
        self.mediaConfiguration = mediaConfiguration
        self.logger = logger
        self.lifecycleHooks = lifecycleHooks
        self.timer = timer
        let channelManager = DataChannelManager(isInitiator: isClient)
        for channel in negotiatedDataChannels {
            do throws(DataChannelError) {
                _ = try channelManager.openNegotiatedChannel(
                    id: channel.id,
                    label: channel.label,
                    ordered: channel.ordered,
                    reliability: channel.reliability
                )
            } catch {
                throw .dataChannelFailed(error)
            }
        }
        let connState = SharedMutex(ConnState(
            iceAgent: WebRTCICEAgent(configuration: iceConfiguration),
            sctpAssociation: SCTPAssociation(clock: sctpClock),
            channelManager: channelManager,
            isClient: isClient,
            verifiedRemoteFingerprint: nil,
            presentedRemoteCertificateDER: nil,
            mediaProtector: nil
        ))
        self.connState = connState
        let dataChannelEventBudget = WebRTCDataChannelEventBudget(
            maximumEventCount: Self.maximumBufferedDataChannelEventCount,
            maximumPayloadByteCount:
                Self.maximumBufferedDataChannelEventPayloadByteCount
        )
        let channelState = SharedMutex(ChannelState(
            eventConsumer: WebRTCDataChannelEventConsumer(
                maximumBufferedEventCount:
                    Self.maximumBufferedDataChannelEventCount,
                eventBudget: dataChannelEventBudget
            ),
            eventBudget: dataChannelEventBudget,
            pendingEvents: WebRTCDataChannelEventQueue(
                maximumCount: Self.maximumBufferedDataChannelEventCount
            )
        ))
        self.channelState = channelState
        let mediaHandlerState = SharedMutex(MediaHandlers())
        self.mediaHandlerState = mediaHandlerState
        self.timerTaskRegistry = TimerTaskRegistry()
        let dtlsFlightCoordinator = DTLSFlightCoordinator()
        self.dtlsFlightCoordinator = dtlsFlightCoordinator
        let terminalCoordinator = TerminalCoordinator(
            connState: connState,
            channelState: channelState,
            mediaHandlerState: mediaHandlerState,
            dtlsEndpoint: self.dtlsEndpoint,
            logger: logger,
            lifecycleHooks: lifecycleHooks
        )
        self.terminalCoordinator = terminalCoordinator
        let egressCoordinator = EgressCoordinator(
            connState: connState,
            dtlsEndpoint: self.dtlsEndpoint,
            sendHandler: sendHandler,
            terminalCoordinator: terminalCoordinator
        )
        self.egressCoordinator = egressCoordinator
        self.dtlsTimeoutPump = DTLSTimeoutPump(
            connState: connState,
            dtlsEndpoint: self.dtlsEndpoint,
            flightCoordinator: dtlsFlightCoordinator,
            egressCoordinator: egressCoordinator,
            terminalCoordinator: terminalCoordinator,
            logger: logger
        )
        self.sctpRetransmissionPump = SCTPRetransmissionPump(
            connState: connState,
            egressCoordinator: egressCoordinator,
            terminalCoordinator: terminalCoordinator,
            logger: logger
        )
    }

    deinit {
        // The periodic Task never retains this facade, so deinitialization is a
        // reachable final safety net even when a direct factory caller omits
        // `close()`. `close()` is idempotent and cancels Tasks outside locks.
        close()
    }

    // MARK: - Connection lifecycle

    /// ICE credentials for this connection
    public var iceCredentials: ICECredentials {
        connState.withLock { $0.iceAgent.credentials }
    }

    /// Set remote ICE credentials (from signaling)
    public func setRemoteICECredentials(ufrag: String, password: String) {
        connState.withLock { state in
            state.iceAgent.setRemoteCredentials(ufrag: ufrag, password: password)
        }
    }

    /// Performs the nominated-pair ICE connectivity check for a controlling
    /// connection, including RFC 5389 retransmission with the same transaction.
    ///
    /// The method returns only after an authenticated Binding Success Response
    /// has been processed by ``receive(_:remoteAddress:)``. Lite and explicitly
    /// prevalidated connections have no active check and return immediately.
    public func establishICEConnectivity(
        timeout: Duration = .seconds(10)
    ) async throws(WebRTCError) {
        let deadline: UInt64 = {
            let now = timer.monotonicNanos()
            let delta = timeout.facadeNanoseconds
            let (sum, overflow) = now.addingReportingOverflow(delta)
            return overflow ? UInt64.max : sum
        }()
        var retransmissionNanos: UInt64 = 100_000_000

        while true {
            let action = connState.withLock {
                state -> Result<[UInt8]?, WebRTCError> in
                switch state.iceAgent.state {
                case .connected, .completed:
                    state.stateMachine.process(.iceConnected)
                    return .success(nil)
                case .failed:
                    return .failure(.iceFailed(
                        state.iceAgent.failureReason
                            ?? "ICE connectivity check failed"
                    ))
                case .closed:
                    return .failure(.closed)
                case .new, .checking:
                    guard let check = state.iceAgent.connectivityCheck()
                    else {
                        return .success(nil)
                    }
                    switch check {
                    case .send(let bytes):
                        return .success(bytes)
                    case .connected:
                        state.stateMachine.process(.iceConnected)
                        return .success(nil)
                    case .failed(let reason):
                        return .failure(.iceFailed(reason))
                    }
                }
            }

            let datagram: [UInt8]?
            switch action {
            case .success(let bytes):
                datagram = bytes
            case .failure(let error):
                failConnection(error, context: "ICE connectivity check failed")
                throw error
            }
            guard let datagram else { return }

            do {
                try sendDatagram(datagram)
            } catch {
                failConnection(error, context: "ICE connectivity check send failed")
                throw error
            }

            let now = timer.monotonicNanos()
            if now >= deadline {
                let error = WebRTCError.iceFailed(
                    "ICE connectivity check timed out"
                )
                connState.withLock { state in
                    state.iceAgent.fail("ICE connectivity check timed out")
                    state.stateMachine.process(.iceFailed)
                }
                failConnection(error, context: "ICE connectivity check timed out")
                throw error
            }
            let (candidateWake, wakeOverflow) = now.addingReportingOverflow(
                retransmissionNanos
            )
            let wake = min(
                deadline,
                wakeOverflow ? UInt64.max : candidateWake
            )
            do {
                try await timer.sleep(untilNanos: wake)
            } catch {
                throw .closed
            }
            retransmissionNanos = min(
                retransmissionNanos &* 2,
                1_600_000_000
            )
        }
    }

    /// Install or clear the authenticated RTP delivery callback.
    ///
    /// A terminal connection rejects registration and does not retain the
    /// supplied callback.
    @discardableResult
    public func setRTPHandler(
        _ handler: RTPHandler?
    ) -> Result<Void, WebRTCError> {
        mediaHandlerState.withLock { state in
            guard state.acceptsInstallation else {
                return .failure(.closed)
            }
            state.rtp = handler
            return .success(())
        }
    }

    /// Install or clear the authenticated RTCP delivery callback.
    ///
    /// A terminal connection rejects registration and does not retain the
    /// supplied callback.
    @discardableResult
    public func setRTCPHandler(
        _ handler: RTCPHandler?
    ) -> Result<Void, WebRTCError> {
        mediaHandlerState.withLock { state in
            guard state.acceptsInstallation else {
                return .failure(.closed)
            }
            state.rtcp = handler
            return .success(())
        }
    }

    /// Start the connection process (client-side: initiates DTLS handshake)
    public func start() throws(WebRTCError) {
        let startResult = connState.withLock { state -> StartResult in
            if state.iceAgent.requiresConnectivityCheckBeforeDTLS,
               state.iceAgent.state != .connected,
               state.iceAgent.state != .completed {
                return .invalidState(state.stateMachine.state)
            }
            switch state.stateMachine.state {
            case .new, .connecting:
                state.stateMachine.process(.dtlsHandshakeStarted)
                return .claimed
            case .failed, .closed:
                return .terminal
            case .dtlsHandshaking, .sctpConnecting, .connected,
                 .disconnected, .closing:
                return .invalidState(state.stateMachine.state)
            }
        }
        switch startResult {
        case .claimed:
            break
        case .terminal:
            throw .closed
        case .invalidState(let state):
            throw .invalidState("Cannot start connection in state \(state.label)")
        }

        // Both roles start the handshake FSM; the client emits its ClientHello,
        // the server has nothing to send until the first ClientHello arrives.
        // The lease covers DTLS mutation as well as every synchronous callback,
        // preventing close from releasing the endpoint midway through a flight.
        do {
            try withNormalEgressLease { permit throws(WebRTCError) in
                let datagrams: [[UInt8]]
                do {
                    datagrams = try performDTLSFlightMutation {
                        () throws(TLSError) -> (
                            [[UInt8]],
                            DTLSRetransmissionState
                        ) in
                        let datagrams = try dtlsEndpoint.startHandshake()
                        return (
                            datagrams,
                            dtlsEndpoint.retransmissionState
                        )
                    }
                } catch {
                    throw WebRTCError.dtlsHandshakeFailed(
                        Self.failureReason(
                            error,
                            context: "DTLS handshake start failed"
                        )
                    )
                }
                var emittedDatagram = false
                for datagram in datagrams {
                    if emittedDatagram {
                        try validateNormalEgressPermit(permit)
                    }
                    try transferDatagramUnderLease(datagram)
                    emittedDatagram = true
                }
            }
        } catch {
            failConnection(error, context: "DTLS initial flight send failed")
            throw error
        }
    }

    /// Process incoming raw UDP data
    ///
    /// Demultiplexes STUN, DTLS, and other data based on the first byte:
    /// - STUN: detected via `STUNMessage.isSTUN()` (RFC 5389)
    /// - DTLS (first byte 20-63): content type range for DTLS records
    /// - Other: logged and ignored
    ///
    /// Contract: every throw from this method means the connection is
    /// terminal (`state.isTerminal == true`). The connection has already
    /// transitioned to `.failed`/`.closed` and the claimed DataChannel event stream has been
    /// finished before the error propagates — callers should stop feeding
    /// data, drop their routing entry, and dispose of the connection.
    /// Recoverable conditions (unknown protocol bytes, packets that fail
    /// SCTP verification-tag validation per RFC 4960 §8.5, DTLS packets
    /// arriving in a non-DTLS state) are discarded internally and do NOT
    /// throw.
    ///
    /// - Throws: `WebRTCError.closed` if the connection has been closed,
    ///   `WebRTCError.dtlsHandshakeFailed` on a fatal DTLS failure,
    ///   `WebRTCError.sctpProtocolFailed` on a fatal SCTP failure
    public func receive(
        _ data: consuming [UInt8],
        remoteAddress: [UInt8] = []
    ) throws(WebRTCError) {
        // P2.4: Check for closed/failed state before processing
        let isClosed = connState.withLock { state in
            state.stateMachine.isTerminal
        }
        if isClosed {
            throw WebRTCError.closed
        }

        guard !data.isEmpty else { return }

        do {
            try demultiplex(data, remoteAddress: remoteAddress)
        } catch {
            // Enforce the terminal contract: any error escaping receive()
            // leaves the connection failed and the DataChannel event stream
            // finished, including paths whose handlers did not transition
            // explicitly (e.g. send failures while emitting responses).
            failConnection(error, context: "receive() processing failed")
            throw error
        }
    }

    #if canImport(Foundation)
    /// Foundation `Data` convenience: process an incoming UDP datagram. Wraps the
    /// `[UInt8]` core so existing host callers keep passing `Data`.
    public func receive(
        _ data: Data,
        remoteAddress: Data = Data()
    ) throws(WebRTCError) {
        try receive([UInt8](data), remoteAddress: [UInt8](remoteAddress))
    }
    #endif

    private func demultiplex(
        _ data: consuming [UInt8],
        remoteAddress: [UInt8]
    ) throws(WebRTCError) {
        let firstByte = data[data.startIndex]

        // RFC 5764 §5.1.2 demultiplex by first byte value:
        //   0-3:     STUN
        //   20-63:   DTLS
        //   128-191: RTP/RTCP (not used in WebRTC Direct)
        //
        // DTLS must be checked BEFORE STUNMessage.isSTUN() because
        // isSTUN() only checks `data[0] & 0xC0 == 0`, which is true
        // for DTLS content types 20-63 as well.

        if firstByte >= 20 && firstByte <= 63 {
            // Validate ICE before DTLS processing. A server can receive the
            // first ClientHello immediately after connectivity succeeds and
            // before its asynchronous owner resumes to call start(). Claim the
            // server handshake atomically with admission so the packet is not
            // discarded while the endpoint itself is ready to accept it.
            let admission: (Bool, WebRTCConnectionState) = connState.withLock {
                state -> (Bool, WebRTCConnectionState) in
                if !state.isClient {
                    let connectivityAdmitsDTLS: Bool
                    switch state.iceAgent.state {
                    case .checking, .connected, .completed:
                        connectivityAdmitsDTLS = true
                    case .new, .failed, .closed:
                        connectivityAdmitsDTLS = false
                    }
                    if connectivityAdmitsDTLS {
                        switch state.stateMachine.state {
                        case .new, .connecting:
                            state.stateMachine.process(.dtlsHandshakeStarted)
                        case .dtlsHandshaking, .sctpConnecting, .connected,
                             .disconnected, .closing, .failed, .closed:
                            break
                        }
                    }
                }
                return (
                    state.stateMachine.shouldProcessDTLS(),
                    state.stateMachine.state
                )
            }
            let (shouldProcess, currentState) = admission
            if !shouldProcess {
                logger.warning("Ignoring DTLS packet (\(data.count)B): state=\(currentState)")
                return
            }
            try processDTLS(data, remoteAddress: remoteAddress)
            return
        }

        if STUNMessage.isSTUN(data) {
            try processSTUN(data, remoteAddress: remoteAddress)
            return
        }

        if (128...191).contains(firstByte) {
            try processProtectedMedia(consume data)
            return
        }

        // Unknown protocol — log and ignore
        logger.debug("Ignoring unknown protocol byte: \(firstByte)")
    }

    /// Open a new outgoing data channel
    /// - Parameters:
    ///   - label: Channel label
    ///   - ordered: Whether messages should be delivered in order
    /// - Returns: The opened data channel
    /// - Throws: `WebRTCError.invalidState` if the connection is not established
    public func openDataChannel(
        label: String,
        ordered: Bool = true,
        reliability: DataChannelReliability = .reliable
    ) throws(WebRTCError) -> DataChannel {
        let result = connState.withLock { state -> OpenDataChannelResult in
            guard state.stateMachine.isConnected else {
                return .invalidState(state.stateMachine.state)
            }

            let opened = Result { () throws(DataChannelError) -> (DataChannel, [UInt8]) in
                try state.channelManager.openChannelBytes(
                    label: label,
                    ordered: ordered,
                    reliability: reliability
                )
            }
            let channel: DataChannel
            let dcepData: [UInt8]
            switch opened {
            case .success(let value):
                (channel, dcepData) = value
            case .failure(let error):
                return .dataChannelError(error)
            }

            let sent = Result { () throws(SCTPError) -> [SCTPPacket] in
                try state.sctpAssociation.sendDataPackets(
                    streamID: channel.id,
                    payloadProtocolIdentifier: DataChannelPPID.dcep.rawValue,
                    data: dcepData
                )
            }
            switch sent {
            case .success(let packets):
                return .success(channel, SCTPEgressBatch(
                    packets: packets,
                    permit: EgressPermit(
                        epoch: state.egressEpoch,
                        allowsTerminalState: false
                    )
                ))
            case .failure(let error):
                return .sctpError(error)
            }
        }

        let channel: DataChannel
        let egressBatch: SCTPEgressBatch
        switch result {
        case .success(let openedChannel, let batch):
            channel = openedChannel
            egressBatch = batch
        case .invalidState(let state):
            throw WebRTCError.invalidState("Cannot open data channel in state \(state.label)")
        case .dataChannelError(let error):
            throw WebRTCError.dataChannelFailed(error)
        case .sctpError(let error):
            let failure = WebRTCError.sctpProtocolFailed(error)
            // The channel manager committed the stream ID and channel before
            // SCTP admission. Without a rollback primitive, this association
            // cannot remain reusable: doing so would retain a connecting channel
            // for which the caller never received a handle.
            failConnection(failure, context: "SCTP rejected DCEP open")
            throw failure
        }
        do {
            try sendSCTPPackets(egressBatch)
        } catch {
            // DCEP and SCTP have already committed their channel/TSN state.
            // The connection must not remain reusable after initial transport
            // rejection: retrying the public operation in this association could
            // create a duplicate message or an unobservable remote channel.
            failConnection(error, context: "DCEP initial datagram send failed")
            throw error
        }
        return channel
    }

    /// Send data on a data channel
    /// - Parameters:
    ///   - data: The data to send
    ///   - channelID: The data channel stream ID
    ///   - binary: Whether data is binary (true) or string (false)
    /// - Throws: `WebRTCError.invalidState` if the connection is not established
    public func send(_ data: [UInt8], on channelID: UInt16, binary: Bool = true) throws(WebRTCError) {
        let ppid: UInt32
        if data.isEmpty {
            ppid = binary ? DataChannelPPID.binaryEmpty.rawValue : DataChannelPPID.stringEmpty.rawValue
        } else {
            ppid = binary ? DataChannelPPID.binary.rawValue : DataChannelPPID.string.rawValue
        }

        let result = connState.withLock { state -> SendDataResult in
            guard state.stateMachine.isConnected else {
                return .invalidState(state.stateMachine.state)
            }

            let policy = Result { () throws(DataChannelError) -> DataChannelSendPolicy in
                try state.channelManager.sendPolicy(id: channelID)
            }
            let sendPolicy: DataChannelSendPolicy
            switch policy {
            case .success(let value):
                sendPolicy = value
            case .failure(let error):
                return .dataChannelError(error)
            }

            let sent = Result { () throws(SCTPError) -> [SCTPPacket] in
                try state.sctpAssociation.sendDataPackets(
                    streamID: channelID,
                    payloadProtocolIdentifier: ppid,
                    data: data,
                    unordered: sendPolicy.unordered,
                    reliability: sendPolicy.reliability
                )
            }
            switch sent {
            case .success(let packets):
                return .success(SCTPEgressBatch(
                    packets: packets,
                    permit: EgressPermit(
                        epoch: state.egressEpoch,
                        allowsTerminalState: false
                    )
                ))
            case .failure(let error):
                return .sctpError(error)
            }
        }

        let egressBatch: SCTPEgressBatch
        switch result {
        case .success(let batch):
            egressBatch = batch
        case .invalidState(let state):
            throw WebRTCError.invalidState("Cannot send data in state \(state.label)")
        case .dataChannelError(let error):
            throw .dataChannelFailed(error)
        case .sctpError(let error):
            throw .sctpProtocolFailed(error)
        }

        do {
            try sendSCTPPackets(egressBatch)
        } catch {
            // SCTP owns the committed TSNs after sendDataPackets returns. Terminate
            // this association so the caller retries only on a new connection,
            // never by duplicating the application payload in the same one.
            failConnection(error, context: "SCTP initial datagram send failed")
            throw error
        }
    }

    /// Begin an RFC 8831 close for one data channel.
    ///
    /// The channel becomes non-writable immediately and is released only after
    /// both SCTP stream directions complete their RFC 6525 reset handshake.
    public func closeDataChannel(_ channelID: UInt16) throws(WebRTCError) {
        let result = connState.withLock { state -> StreamResetRequestResult in
            guard state.stateMachine.isConnected else {
                return .invalidState(state.stateMachine.state)
            }

            let close = Result { () throws(DataChannelError) -> Bool in
                try state.channelManager.beginClose(id: channelID)
            }
            switch close {
            case .failure(let error):
                return .dataChannelError(error)
            case .success(false):
                return .success(nil)
            case .success(true):
                break
            }

            let reset = Result { () throws(SCTPError) -> SCTPPacket? in
                try state.sctpAssociation.requestOutgoingStreamReset(
                    .listed([channelID])
                )
            }
            switch reset {
            case .success(let packet):
                return .success(packet.map { packet in
                    SCTPEgressBatch(
                        packets: [packet],
                        permit: EgressPermit(
                            epoch: state.egressEpoch,
                            allowsTerminalState: false
                        )
                    )
                })
            case .failure(let error):
                return .sctpError(error)
            }
        }

        let egressBatch: SCTPEgressBatch?
        switch result {
        case .success(let acceptedBatch):
            egressBatch = acceptedBatch
        case .invalidState(let state):
            throw .invalidState("Cannot close data channel in state \(state.label)")
        case .dataChannelError(let error):
            throw .dataChannelFailed(error)
        case .sctpError(let error):
            let failure = WebRTCError.sctpProtocolFailed(error)
            failConnection(failure, context: "SCTP stream reset request failed")
            throw failure
        }

        guard let egressBatch else { return }
        do {
            try sendSCTPPackets(egressBatch)
        } catch {
            // The reset request and channel closing state are committed. The
            // association cannot safely roll them back after transport rejection.
            failConnection(error, context: "SCTP stream reset datagram send failed")
            throw error
        }
    }

    /// Start a graceful RFC 9260 SCTP shutdown.
    ///
    /// The connection enters ``WebRTCConnectionState/closing`` before any
    /// external transport I/O, so synchronous send-handler re-entry observes a
    /// non-writable connection. Outstanding DATA remains owned by SCTP and is
    /// drained by the existing retransmission driver before SHUTDOWN is emitted.
    /// Repeated calls while closing are idempotent.
    public func shutdown() throws(WebRTCError) {
        let result = connState.withLock { state -> ShutdownRequestResult in
            switch state.stateMachine.state {
            case .closing, .closed:
                return .success(nil)
            case .failed:
                return .terminal(state.terminalFailure)
            case .connected:
                break
            case .new, .connecting, .dtlsHandshaking, .sctpConnecting,
                 .disconnected:
                return .invalidState(state.stateMachine.state)
            }

            let requested = Result { () throws(SCTPError) -> SCTPPacket? in
                try state.sctpAssociation.requestShutdown()
            }
            switch requested {
            case .success(let packet):
                _ = state.stateMachine.process(.sctpShutdownStarted(
                    state.sctpAssociation.state
                ))
                return .success(packet.map { packet in
                    SCTPEgressBatch(
                        packets: [packet],
                        permit: EgressPermit(
                            epoch: state.egressEpoch,
                            allowsTerminalState: false
                        )
                    )
                })
            case .failure(let error):
                return .sctpError(error)
            }
        }

        let egressBatch: SCTPEgressBatch?
        switch result {
        case .success(let value):
            egressBatch = value
        case .invalidState(let state):
            throw .invalidState(
                "Cannot start graceful shutdown in state \(state.label)"
            )
        case .terminal(let failure):
            throw failure ?? .closed
        case .sctpError(let error):
            let failure = WebRTCError.sctpProtocolFailed(error)
            failConnection(failure, context: "SCTP graceful shutdown request failed")
            throw failure
        }

        guard let egressBatch else { return }
        do {
            try sendSCTPPackets(egressBatch)
        } catch {
            failConnection(error, context: "SCTP SHUTDOWN datagram send failed")
            throw error
        }
    }

    /// Protect and send one plaintext RTP packet using the negotiated SRTP keys.
    ///
    /// Ownership is transferred so AES-CTR can mutate the packet payload in
    /// place. Callers that need the plaintext after this call must retain their
    /// own copy before transferring it.
    public func sendRTP(_ plaintextPacket: consuming [UInt8]) throws(WebRTCError) {
        var packet = consume plaintextPacket
        _ = try acquireNormalEgressLease()
        defer { releaseEgressLease() }

        let status = connState.withLock { state -> (
            unavailable: Bool,
            protector: MediaProtector?
        ) in
            (
                state.stateMachine.state == .closing,
                state.mediaProtector
            )
        }
        guard !status.unavailable else { throw .closed }
        guard let configuration = mediaConfiguration else {
            throw .mediaNotConfigured
        }
        guard let protector = status.protector else {
            throw .mediaNotReady
        }

        let layout: RTPPacketLayout
        switch Result<RTPPacketLayout, RTPWireError>(
            catching: { () throws(RTPWireError) -> RTPPacketLayout in
                try rtpParser.layout(in: packet.span)
            }
        ) {
        case .success(let parsedLayout):
            layout = parsedLayout
        case .failure(let error):
            throw .mediaWireFailure(error)
        }
        let payloadType = layout.fixedHeader.payloadType
        guard configuration.rtpPayloadTypes.contains(payloadType) else {
            throw .unnegotiatedRTPPayloadType(payloadType)
        }

        switch Result<Void, SRTPError>(
            catching: { () throws(SRTPError) in
                try protector.protectRTP(&packet)
            }
        ) {
        case .success:
            break
        case .failure(let error):
            throw .mediaProtectionFailed(error)
        }
        try transferDatagramUnderLease(consume packet)
    }

    /// Protect and send one plaintext RTCP datagram using the negotiated SRTCP keys.
    public func sendRTCP(_ plaintextPacket: consuming [UInt8]) throws(WebRTCError) {
        var packet = consume plaintextPacket
        _ = try acquireNormalEgressLease()
        defer { releaseEgressLease() }

        let status = connState.withLock { state -> (
            unavailable: Bool,
            protector: MediaProtector?
        ) in
            (
                state.stateMachine.state == .closing,
                state.mediaProtector
            )
        }
        guard !status.unavailable else { throw .closed }
        guard let configuration = mediaConfiguration else {
            throw .mediaNotConfigured
        }
        guard let protector = status.protector else {
            throw .mediaNotReady
        }

        let framing: RTCPFraming = configuration.allowsReducedSizeRTCP
            ? .reducedSize
            : .compound
        switch Result<RTCPDatagramLayout, RTPWireError>(
            catching: { () throws(RTPWireError) -> RTCPDatagramLayout in
                try rtcpParser.layout(in: packet.span, framing: framing)
            }
        ) {
        case .success:
            break
        case .failure(let error):
            throw .mediaWireFailure(error)
        }

        switch Result<Void, SRTPError>(
            catching: { () throws(SRTPError) in
                try protector.protectRTCP(&packet)
            }
        ) {
        case .success:
            break
        case .failure(let error):
            throw .mediaProtectionFailed(error)
        }
        try transferDatagramUnderLease(consume packet)
    }

    #if canImport(Foundation)
    /// Foundation `Data` convenience: send data on a data channel. Wraps the
    /// `[UInt8]` core so existing host callers keep passing `Data`.
    public func send(
        _ data: Data,
        on channelID: UInt16,
        binary: Bool = true
    ) throws(WebRTCError) {
        try send([UInt8](data), on: channelID, binary: binary)
    }
    #endif

    /// Close the connection.
    ///
    /// This call invalidates new protocol work and atomically detaches media
    /// handlers. It is intentionally not a callback-quiescence barrier: an RTP
    /// or RTCP callback admitted before the detach may finish after this method
    /// returns, which also permits a handler to call `close()` reentrantly.
    public func close() {
        connState.withLock { state in
            let wasTerminal = state.stateMachine.isTerminal
            if !wasTerminal {
                state.stateMachine.process(.userClose)
                state.egressEpoch = EgressEpoch()
            }
            state.sctpAssociation.terminate()
        }
        prepareTerminalOwnerTeardown()
        completeTerminalNetworkTeardown()
    }

    /// Reports a datagram failure discovered after synchronous admission.
    ///
    /// A transport may accept an owner into a bounded queue and only discover
    /// the platform write failure later. The adapter must report that failure
    /// through this method so the affected connection becomes terminal with the
    /// original typed cause. A clean close or an earlier terminal failure wins a
    /// race and is never overwritten.
    public func transportDidFail(_ failure: WebRTCDatagramSendFailure) {
        failConnection(
            .datagramSendFailed(failure),
            context: "Datagram transport failed after admission"
        )
    }

    /// Release protocol/application owners that are not needed to encrypt the
    /// final SCTP response. This is idempotent and performs no external network
    /// callback.
    private func prepareTerminalOwnerTeardown() {
        timerTaskRegistry.cancelAll()
        terminalCoordinator.prepare()
    }

    /// Close DTLS and ICE after the final SCTP response has been encrypted and
    /// handed to the transport. Hard close/failure calls this immediately.
    private func completeTerminalNetworkTeardown() {
        terminalCoordinator.completeNetworkTeardown()
    }

    // MARK: - Private protocol processing

    private func processSTUN(
        _ data: [UInt8],
        remoteAddress: [UInt8]
    ) throws(WebRTCError) {
        let endpoint = Self.decodeRemoteEndpoint(remoteAddress)

        // Single lock for ICE processing + state transition (fixes race condition)
        let response = connState.withLock { state -> [UInt8]? in
            let stunResponse = state.iceAgent.processSTUNBytes(
                data: data,
                sourceAddress: endpoint.address,
                sourcePort: endpoint.port
            )

            // Update state machine based on ICE state
            if state.iceAgent.state == .connected {
                state.stateMachine.process(.iceConnected)
            } else if state.iceAgent.state == .failed {
                state.stateMachine.process(.iceFailed)
            }

            return stunResponse
        }

        let iceFailure = connState.withLock { state -> WebRTCError? in
            guard state.iceAgent.state == .failed else { return nil }
            return .iceFailed(
                state.iceAgent.failureReason ?? "ICE connectivity check failed"
            )
        }
        if let iceFailure {
            throw iceFailure
        }

        if let response {
            try sendDatagram(response)
        }
    }

    /// Authenticate, decrypt, validate, and deliver one RTP/RTCP datagram.
    ///
    /// The owned network buffer is transferred into this method, transformed in
    /// place, and then transferred to the callback. No packet-sized owner is
    /// materialized between UDP receive and the media consumer.
    private func processProtectedMedia(
        _ protectedPacket: consuming [UInt8]
    ) throws(WebRTCError) {
        guard let configuration = mediaConfiguration else {
            logger.debug("Ignoring RTP/RTCP on a data-channel-only connection")
            return
        }
        guard let protector = connState.withLock({ $0.mediaProtector }) else {
            // Media can race the final DTLS flight on UDP. Dropping it is a
            // recoverable ordering condition; unauthenticated bytes are never
            // delivered or parsed as plaintext.
            logger.debug("Ignoring RTP/RTCP before authenticated SRTP key installation")
            return
        }

        let kind: RTPRTCPPacketKind
        do {
            kind = try mediaClassifier.classify(protectedPacket.span)
        } catch {
            logger.warning("Discarding malformed RTP/RTCP mux datagram")
            return
        }

        // Make the ownership transfer explicit. The classifier only borrows the
        // datagram, after which SRTP mutates and forwards that same owner.
        var packet = consume protectedPacket
        do {
            switch kind {
            case .rtp:
                try protector.unprotectRTP(&packet)
            case .rtcp:
                try protector.unprotectRTCP(&packet)
            }
        } catch {
            guard !Self.isRecoverableInboundMediaFailure(error) else {
                logger.warning("Discarding unauthentic, replayed, or malformed protected media")
                return
            }
            throw .mediaProtectionFailed(error)
        }

        switch kind {
        case .rtp:
            let layout: RTPPacketLayout
            do {
                layout = try rtpParser.layout(in: packet.span)
            } catch {
                // SRTPCore validates authenticated plaintext before returning,
                // but retain a fail-closed boundary if the parser policy grows.
                logger.warning("Discarding authenticated RTP with an invalid plaintext layout")
                return
            }
            guard configuration.rtpPayloadTypes.contains(layout.fixedHeader.payloadType) else {
                logger.warning("Discarding authenticated RTP with an unnegotiated payload type")
                return
            }
            let handler = mediaHandlerState.withLock { $0.rtp }
            handler?(WebRTCRTPPacket(bytes: consume packet, layout: layout))

        case .rtcp:
            let framing: RTCPFraming = configuration.allowsReducedSizeRTCP ? .reducedSize : .compound
            let layout: RTCPDatagramLayout
            do {
                layout = try rtcpParser.layout(in: packet.span, framing: framing)
            } catch {
                logger.warning("Discarding authenticated RTCP that violates negotiated framing")
                return
            }
            let handler = mediaHandlerState.withLock { $0.rtcp }
            handler?(WebRTCRTCPPacket(bytes: consume packet, layout: layout))
        }
    }

    private static func isRecoverableInboundMediaFailure(_ error: SRTPError) -> Bool {
        switch error {
        case .packetTooShort,
             .encryptedPortionTooLarge,
             .malformedRTP,
             .malformedRTCP,
             .authenticationFailure,
             .replayedPacket,
             .packetTooOld,
             .unencryptedSRTCPRejected:
            return true
        case .invalidMasterKeyLength,
             .invalidMasterSaltLength,
             .invalidAuthenticationTagLength,
             .outboundIndexReuse,
             .indexExhausted,
             .stateReservationLost,
             .counterMode:
            return false
        }
    }

    static func decodeRemoteEndpoint(_ remoteAddress: [UInt8]) -> (address: [UInt8], port: UInt16) {
        switch remoteAddress.count {
        case 6:
            let address = Array(remoteAddress[0..<4])
            let port = UInt16(remoteAddress[4]) << 8 | UInt16(remoteAddress[5])
            return (address, port)
        case 18:
            let address = Array(remoteAddress[0..<16])
            let port = UInt16(remoteAddress[16]) << 8 | UInt16(remoteAddress[17])
            return (address, port)
        case 22:
            // A scoped IPv6 transport appends a four-byte scope ID for DTLS
            // cookie binding. STUN still operates on the 16-byte IP and port.
            let address = Array(remoteAddress[0..<16])
            let port = UInt16(remoteAddress[16]) << 8 | UInt16(remoteAddress[17])
            return (address, port)
        default:
            return (remoteAddress, 0)
        }
    }

    private func processDTLS(_ data: [UInt8], remoteAddress: [UInt8]) throws(WebRTCError) {
        try withNormalEgressLease { permit throws(WebRTCError) in
            let output: DTLSOutput
            do {
                output = try performDTLSFlightMutation {
                    () throws(TLSError) -> (
                        DTLSOutput,
                        DTLSRetransmissionState
                    ) in
                    let output = try dtlsEndpoint.receive(
                        data,
                        remoteAddress: remoteAddress
                    )
                    return (output, output.retransmissionState)
                }
            } catch {
                let reason = Self.failureReason(
                    error,
                    context: "DTLS receive failed"
                )
                throw WebRTCError.dtlsHandshakeFailed(reason)
            }

            var emittedDatagram = false
            for datagram in output.datagramsToSend {
                if emittedDatagram {
                    try validateNormalEgressPermit(permit)
                }
                try transferDatagramUnderLease(datagram)
                emittedDatagram = true
            }
            // A callback or concurrent owner may close after the final (or an
            // output-free) DTLS step. Fence every subsequent handshake/SCTP
            // commit against that terminal epoch.
            try validateNormalEgressPermit(permit)
            if output.handshakeComplete {
                try onHandshakeComplete(permit: permit)
            }

            if !output.applicationData.isEmpty {
                try processSCTP(output.applicationData)
            }
        }
    }

    private func onHandshakeComplete(
        permit: EgressPermit
    ) throws(WebRTCError) {
        let ownsCompletion = connState.withLock { state -> Bool in
            guard !state.stateMachine.isTerminal,
                  state.egressEpoch === permit.epoch,
                  !state.stateMachine.isDTLSConnected,
                  !state.isDTLSCompletionInProgress else {
                return false
            }
            state.isDTLSCompletionInProgress = true
            return true
        }
        guard ownsCompletion else { return }
        defer {
            connState.withLock { $0.isDTLSCompletionInProgress = false }
        }
        lifecycleHooks.beforeHandshakeCommit?()

        // Snapshot the certificate once. The endpoint remains internally
        // synchronized, but all public reads use the connection-state snapshot
        // committed below so lifecycle admission cannot be mistaken for an
        // absent certificate.
        let presentedRemoteCertificateDER = dtlsEndpoint.remoteCertificateDER

        // Verify remote fingerprint if expected.
        //
        // FAIL-CLOSED: WebRTC's DTLS-SRTP peer authentication binds the peer's
        // leaf-certificate fingerprint to the value advertised in signaling. The
        // swift-tls Tier-1 DTLS facade surfaces the peer certificate (see
        // ``DTLSEndpoint``), so when an expected fingerprint is configured we
        // compute the peer's fingerprint and accept ONLY on an exact match —
        // rejecting on mismatch, or when the peer presented no certificate. Never
        // silently accept an unverified peer. When no expected fingerprint is set
        // (e.g. a server whose peer identity is bound by a subsequent layer), the
        // handshake proceeds.
        let verifiedRemoteFingerprint: CertificateFingerprint?
        if let expected = expectedFingerprint {
            guard let presentedRemoteCertificateDER else {
                let reason = "Cannot verify remote fingerprint: the peer presented no certificate (expected \(expected.sdpFormat))"
                throw WebRTCError.dtlsHandshakeFailed(reason)
            }
            let actual = CertificateFingerprint.fromDER(
                presentedRemoteCertificateDER
            )
            guard actual == expected else {
                let reason = "Remote fingerprint mismatch: expected \(expected.sdpFormat), got \(actual.sdpFormat)"
                throw WebRTCError.dtlsHandshakeFailed(reason)
            }
            verifiedRemoteFingerprint = actual
        } else {
            verifiedRemoteFingerprint = nil
        }

        let mediaProtector: MediaProtector?
        if mediaConfiguration != nil {
            // A media connection is only constructible with an expected peer
            // fingerprint. Recheck the authenticated result here so no SRTP
            // exporter material becomes usable through an unbound DTLS peer.
            guard verifiedRemoteFingerprint != nil else {
                throw .mediaPeerAuthenticationRequired
            }
            mediaProtector = try makeMediaProtector()
        } else {
            mediaProtector = nil
        }

        let committed = connState.withLock { state -> Bool in
            guard !state.stateMachine.isTerminal,
                  state.egressEpoch === permit.epoch else {
                return false
            }
            if let mediaProtector, state.mediaProtector == nil {
                state.mediaProtector = mediaProtector
            }
            state.verifiedRemoteFingerprint = verifiedRemoteFingerprint
            state.presentedRemoteCertificateDER =
                presentedRemoteCertificateDER
            _ = state.stateMachine.process(.dtlsHandshakeComplete)
            return true
        }
        guard committed else {
            throw connState.withLock { $0.terminalFailure ?? .closed }
        }
        logger.info("DTLS handshake complete, establishing SCTP")

        // Initiate SCTP association (client side)
        let initPacket = connState.withLock { state -> SCTPPacket? in
            guard !state.stateMachine.isTerminal,
                  state.egressEpoch === permit.epoch,
                  state.isClient else {
                return nil
            }
            _ = state.stateMachine.process(.sctpAssociating)
            return state.sctpAssociation.generateInit()
        }
        if let initPacket {
            try validateNormalEgressPermit(permit)
            try sendEncryptedUnderLease(
                initPacket.encodeBytes(),
                permit: permit
            )
        }
    }

    private func makeMediaProtector() throws(WebRTCError) -> MediaProtector {
        let material: DTLSSRTPKeyingMaterial
        do {
            material = try dtlsEndpoint.srtpKeyingMaterial()
        } catch {
            throw .dtlsHandshakeFailed(
                Self.failureReason(error, context: "DTLS-SRTP key export failed")
            )
        }

        let outbound: SRTPMasterKeyMaterial
        let inbound: SRTPMasterKeyMaterial
        do {
            outbound = try SRTPMasterKeyMaterial(
                masterKey: material.localMasterKey,
                masterSalt: material.localMasterSalt
            )
            inbound = try SRTPMasterKeyMaterial(
                masterKey: material.remoteMasterKey,
                masterSalt: material.remoteMasterSalt
            )
            return try MediaProtector(
                outbound: outbound,
                inbound: inbound,
                crypto: .webRTCDefault()
            )
        } catch {
            throw .mediaProtectionFailed(error)
        }
    }

    /// Invalidate every normal producer and reserve one final terminal SCTP
    /// batch before releasing the connection mutex. The reservation itself is
    /// counted as in-flight, so DTLS/ICE teardown cannot overtake its sender.
    private static func reserveTerminalEgress(
        for packets: [SCTPPacket],
        state: inout ConnState
    ) -> EgressPermit? {
        // The first terminal transition owns invalidation and the optional final
        // batch. A concurrently admitted producer that observes terminal state
        // must not replace that epoch or invalidate its unique reservation.
        guard state.reservedTerminalEgressToken == nil else { return nil }
        state.egressEpoch = EgressEpoch()
        guard !packets.isEmpty else { return nil }
        let (nextCount, overflow) = state.egressInFlightCount
            .addingReportingOverflow(1)
        precondition(!overflow, "Terminal egress lease count exhausted")
        let token = TerminalEgressToken()
        state.egressInFlightCount = nextCount
        state.reservedTerminalEgressToken = token
        return EgressPermit(
            epoch: state.egressEpoch,
            allowsTerminalState: true,
            terminalToken: token
        )
    }

    private func processSCTP(_ plaintext: [UInt8]) throws(WebRTCError) {
        let packet: SCTPPacket
        do {
            packet = try SCTPPacket.decode(from: plaintext)
        } catch {
            throw .sctpWireFailed(error)
        }
        lifecycleHooks.beforeSCTPTransaction?()

        // Association mutation, channel mutation, and event-queue admission are
        // one transaction. External transport I/O starts only after all three
        // have committed, so synchronous SendHandler re-entry cannot observe an
        // old channel binding or overtake an OPEN/CLOSE event.
        let outcome = connState.withLock { state -> SCTPInboundOutcome in
            guard !state.stateMachine.isTerminal else {
                return .alreadyTerminal(state.terminalFailure)
            }
            let result: SCTPProcessResult
            let cleanlyClosed: Bool
            let processed = Result { () throws(SCTPError) -> SCTPProcessOutcome in
                try state.sctpAssociation.processPacketBytesOutcome(packet)
            }
            switch processed {
            case .success(.processed(let value)):
                result = value
                cleanlyClosed = false
            case .success(.closed(let value)):
                result = value
                cleanlyClosed = true
            case .success(.terminal(let terminalResult, let error)):
                let failure = WebRTCError.sctpProtocolFailed(error)
                if state.terminalFailure == nil {
                    state.terminalFailure = failure
                    _ = state.stateMachine.process(.error(
                        Self.failureReason(
                            failure,
                            context: "SCTP association terminated"
                        )
                    ))
                }
                state.sctpAssociation.terminate()
                var effects = SCTPInboundEffects(
                    packets: terminalResult.responses
                )
                effects.egressPermit = Self.reserveTerminalEgress(
                    for: effects.packets,
                    state: &state
                )
                return .terminal(
                    effects,
                    state.terminalFailure ?? failure
                )
            case .failure(let error):
                if case .verificationTagMismatch(let expected, let actual) = error {
                    return .discardedVerificationTag(
                        expected: expected,
                        actual: actual
                    )
                }
                let failure = WebRTCError.sctpProtocolFailed(error)
                state.sctpAssociation.terminate()
                if state.terminalFailure == nil {
                    state.terminalFailure = failure
                    _ = state.stateMachine.process(.error(
                        Self.failureReason(
                            failure,
                            context: "SCTP packet processing failed"
                        )
                    ))
                }
                _ = Self.reserveTerminalEgress(for: [], state: &state)
                return .terminal(
                    SCTPInboundEffects(packets: []),
                    state.terminalFailure ?? failure
                )
            }

            var effects = SCTPInboundEffects(packets: result.responses)
            let sctpState = state.sctpAssociation.state
            if sctpState == .established && !state.stateMachine.isSCTPEstablished {
                guard state.sctpAssociation.supportsStreamReconfiguration else {
                    return .failure(.sctpProtocolFailed(
                        .streamReconfigurationNotNegotiated
                    ))
                }
                _ = state.stateMachine.process(.sctpEstablished)
                effects.becameConnected = true
            }
            switch sctpState {
            case .shutdownPending, .shutdownSent, .shutdownReceived,
                 .shutdownAckSent:
                _ = state.stateMachine.process(.sctpShutdownStarted(sctpState))
            case .closed, .cookieWait, .cookieEchoed, .established:
                break
            }

            for delivery in result.deliveries {
                let failure: WebRTCError?
                switch delivery {
                case .message(let message):
                    failure = applySCTPMessage(
                        message,
                        state: &state,
                        effects: &effects
                    )
                case .event(let event):
                    failure = applySCTPAssociationEvent(
                        event,
                        state: &state,
                        effects: &effects
                    )
                }
                if let failure { return .failure(failure) }
            }

            switch enqueueDataChannelEvents(effects.events) {
            case .success(let ownsDrain):
                effects.ownsEventDrain = ownsDrain
                if cleanlyClosed {
                    _ = state.stateMachine.process(.sctpClosed)
                    effects.egressPermit = Self.reserveTerminalEgress(
                        for: effects.packets,
                        state: &state
                    )
                    return .closed(effects)
                }
                effects.egressPermit = EgressPermit(
                    epoch: state.egressEpoch,
                    allowsTerminalState: false
                )
                return .success(effects)
            case .failure(let error):
                return .failure(error)
            }
        }

        let effects: SCTPInboundEffects
        let terminalFailure: WebRTCError?
        let cleanlyClosed: Bool
        switch outcome {
        case .alreadyTerminal(let failure):
            throw failure ?? .closed
        case .discardedVerificationTag(let expected, let actual):
            // RFC 4960 section 8.5 requires silent discard. Failing here would
            // let a single injected datagram terminate an authenticated peer.
            logger.warning("Discarding SCTP packet: verification tag mismatch (expected \(expected), got \(actual))")
            return
        case .failure(let error):
            throw error
        case .success(let committed):
            effects = committed
            terminalFailure = nil
            cleanlyClosed = false
        case .closed(let committed):
            effects = committed
            terminalFailure = nil
            cleanlyClosed = true
        case .terminal(let committed, let error):
            effects = committed
            terminalFailure = error
            cleanlyClosed = false
        }

        let requiresTerminalTeardown = cleanlyClosed || terminalFailure != nil
        if requiresTerminalTeardown {
            prepareTerminalOwnerTeardown()
        }
        defer {
            if requiresTerminalTeardown {
                abandonReservedTerminalEgressPermit(effects.egressPermit)
                completeTerminalNetworkTeardown()
            }
        }

        if effects.ownsEventDrain, let failure = drainDataChannelEvents() {
            throw failure
        }

        for streamID in effects.rejectedStreamIDs {
            logger.warning("Resetting protocol-violating SCTP stream \(streamID)")
        }

        if effects.becameConnected {
            logger.info("WebRTC connection established")
            startRetransmissionDriver()
        }

        let sendResult = Result { () throws(WebRTCError) -> Void in
            if !effects.packets.isEmpty {
                guard let permit = effects.egressPermit else {
                    throw WebRTCError.invalidState(
                        "SCTP response batch has no egress permit"
                    )
                }
                try sendSCTPPackets(SCTPEgressBatch(
                    packets: effects.packets,
                    permit: permit
                ))
            }
        }
        if case .failure(let error) = sendResult {
            // The SCTP protocol failure was committed under the state lock before
            // this reentrant I/O. A final-response send error must not replace it.
            if let terminalFailure {
                throw terminalFailure
            }
            throw error
        }
        if let terminalFailure {
            throw terminalFailure
        }
    }

    /// Apply one ordered SCTP message while the connection transaction is held.
    private func applySCTPMessage(
        _ message: SCTPReceivedMessage,
        state: inout ConnState,
        effects: inout SCTPInboundEffects
    ) -> WebRTCError? {
        let streamID = message.streamID
        if message.ppid == DataChannelPPID.dcep.rawValue {
            let response: [UInt8]?
            let channel: DataChannel?
            do {
                (response, channel) = try state.channelManager.processIncomingDCEPBytes(
                    streamID: streamID,
                    data: message.data
                )
            } catch {
                effects.rejectedStreamIDs.append(streamID)
                return requestStreamResetForProtocolViolation(
                    streamID: streamID,
                    state: &state,
                    effects: &effects
                )
            }

            if let response {
                do {
                    let packets = try state.sctpAssociation.sendDataPackets(
                        streamID: streamID,
                        payloadProtocolIdentifier: DataChannelPPID.dcep.rawValue,
                        data: response
                    )
                    effects.packets.append(contentsOf: packets)
                } catch {
                    return .sctpProtocolFailed(error)
                }
            }

            if let channel {
                let direction: WebRTCDataChannelDirection = message.data.first
                    == DCEPMessageType.dataChannelOpen.rawValue
                    ? .remote
                    : .local
                effects.events.append(.opened(
                    channel: channel,
                    direction: direction
                ))
            }
            return nil
        }

        guard let channel = state.channelManager.channel(id: streamID) else {
            effects.rejectedStreamIDs.append(streamID)
            return requestStreamResetForProtocolViolation(
                streamID: streamID,
                state: &state,
                effects: &effects
            )
        }

        let messageChannel: DataChannel
        do {
            if let opened = try state.channelManager.observeIncomingMessage(id: streamID) {
                effects.events.append(.opened(
                    channel: opened,
                    direction: .local
                ))
                messageChannel = opened
            } else {
                messageChannel = channel
            }
        } catch {
            return .dataChannelFailed(error)
        }
        effects.events.append(.message(
            channelID: streamID,
            generation: messageChannel.generation,
            payload: message.data
        ))
        return nil
    }

    /// Apply one reset transition while the connection transaction is held.
    private func applySCTPAssociationEvent(
        _ event: SCTPAssociationEvent,
        state: inout ConnState,
        effects: inout SCTPInboundEffects
    ) -> WebRTCError? {
        let transition = state.channelManager.apply(event)
        for closeEvent in transition.closeEvents {
            effects.events.append(.closed(closeEvent))
        }
        guard let selection = transition.reciprocalReset else { return nil }
        do {
            if let packet = try state.sctpAssociation.requestOutgoingStreamReset(selection) {
                effects.packets.append(packet)
            }
            return nil
        } catch {
            return .sctpProtocolFailed(error)
        }
    }

    private func requestStreamResetForProtocolViolation(
        streamID: UInt16,
        state: inout ConnState,
        effects: inout SCTPInboundEffects
    ) -> WebRTCError? {
        if state.channelManager.channel(id: streamID) != nil {
            do {
                _ = try state.channelManager.beginClose(id: streamID)
            } catch {
                return .dataChannelFailed(error)
            }
        }
        do {
            if let packet = try state.sctpAssociation.requestOutgoingStreamReset(
                .listed([streamID])
            ) {
                effects.packets.append(packet)
            }
            return nil
        } catch {
            return .sctpProtocolFailed(error)
        }
    }

    /// Admit a batch before releasing the association transaction. The caller
    /// that flips `isDraining` owns the external event-consumer drain.
    private func enqueueDataChannelEvents(
        _ events: [WebRTCDataChannelEvent]
    ) -> Result<Bool, WebRTCError> {
        guard !events.isEmpty else { return .success(false) }
        return channelState.withLock { state in
            guard !state.areEventsFinished,
                  !state.isEventFinishRequested else {
                return .failure(.dataChannelEventStreamTerminated)
            }
            guard events.count <= state.pendingEvents.maximumCount
                    - state.pendingEvents.count else {
                return .failure(.dataChannelEventBufferExceeded(
                    limit: Self.maximumBufferedDataChannelEventCount
                ))
            }
            switch state.eventBudget.reserve(events) {
            case .success:
                break
            case .failure(.eventCount):
                return .failure(.dataChannelEventBufferExceeded(
                    limit: Self.maximumBufferedDataChannelEventCount
                ))
            case .failure(.payloadByteCount):
                return .failure(.dataChannelEventByteBufferExceeded(
                    limit: Self
                        .maximumBufferedDataChannelEventPayloadByteCount
                ))
            }
            guard state.pendingEvents.append(contentsOf: events) else {
                preconditionFailure("Event count changed while holding its mutex")
            }
            guard !state.isDraining else { return .success(false) }
            state.isDraining = true
            return .success(true)
        }
    }

    /// Drain events without a framework lock. Concurrent and reentrant receive
    /// calls append behind this owner and preserve the committed batch order.
    private func drainDataChannelEvents() -> WebRTCError? {
        terminalCoordinator.drainDataChannelEvents()
    }

    // MARK: - Retransmission driver

    /// Perform one sans-I/O DTLS flight mutation and publish the exact timer
    /// state produced by that mutation as one ordered transaction.
    ///
    /// `operation` must not perform transport I/O, invoke application callbacks,
    /// or suspend. Those effects run only after this method releases the lock.
    private func performDTLSFlightMutation<Output>(
        _ operation: () throws(TLSError) -> (
            output: Output,
            retransmissionState: DTLSRetransmissionState
        )
    ) throws(TLSError) -> Output {
        let transaction = try dtlsFlightCoordinator.perform {
            () throws(TLSError) -> (
                output: Output,
                reconciliation: DTLSTimerReconciliation
            ) in
            let result = try operation()
            let reconciliation = reserveDTLSRetransmissionTimer(
                result.retransmissionState
            )
            return (result.output, reconciliation)
        }
        applyDTLSRetransmissionTimer(transaction.reconciliation)
        return transaction.output
    }

    /// Reserve the caller-owned timeout driver state while the DTLS flight
    /// mutation is serialized.
    ///
    /// A repeated state with the same generation deliberately keeps the
    /// existing deadline. This is how partial, malformed, or unauthenticated
    /// input avoids extending the peer's retransmission window. This method
    /// mutates only in-memory owner state; it never creates or cancels a Task.
    private func reserveDTLSRetransmissionTimer(
        _ state: DTLSRetransmissionState
    ) -> DTLSTimerReconciliation {
        guard let delay = state.nextDelay else {
            return .cancel(removeDTLSRetransmissionTimer())
        }
        guard !connState.withLock({ $0.stateMachine.isTerminal }) else {
            return .cancel(removeDTLSRetransmissionTimer())
        }

        let generation = state.generation
        let delayNanos = delay.facadeNanoseconds

        let installation = timerTaskRegistry.withDTLS { owner -> (
            token: TimerTaskToken,
            publication: DTLSTimerPublication,
            previous: Task<Void, Never>?
        )? in
            guard owner?.publication.generation != generation else {
                return nil
            }
            let previous = owner?.task
            let token = TimerTaskToken()
            let publication = DTLSTimerPublication(generation: generation)
            owner = DTLSTimerOwner(
                token: token,
                publication: publication,
                task: nil
            )
            return (token, publication, previous)
        }

        guard let installation else {
            return .unchanged
        }
        return .install(DTLSTimerInstallation(
            token: installation.token,
            publication: installation.publication,
            previous: installation.previous,
            generation: generation,
            delayNanos: delayNanos
        ))
    }

    /// Apply a previously reserved timer transition without the DTLS flight
    /// mutex. Cancellation handlers and injected timer implementations may
    /// re-enter the connection, so every Task effect belongs on this side of
    /// the serialization boundary.
    private func applyDTLSRetransmissionTimer(
        _ reconciliation: DTLSTimerReconciliation
    ) {
        switch reconciliation {
        case .unchanged:
            return
        case .cancel(let task):
            task?.cancel()
            return
        case .install(let installation):
            installDTLSRetransmissionTimer(installation)
        }
    }

    private func installDTLSRetransmissionTimer(
        _ installation: DTLSTimerInstallation
    ) {
        installation.previous?.cancel()

        let timer = self.timer
        let pump = dtlsTimeoutPump
        let taskRegistry = timerTaskRegistry

        // Publish the token before creating the unstructured task. A task may
        // start and finish immediately when a test or platform injects a timer
        // whose deadline is already due. In that interleaving `clearDTLS`
        // removes the token and `attachDTLS` below refuses to resurrect the
        // completed task. A concurrent close follows the same path.
        let candidate = Task {
            guard taskRegistry.containsDTLS(token: installation.token) else {
                return
            }
            defer {
                taskRegistry.clearDTLS(token: installation.token)
            }
            var schedule = DTLSTimeoutSchedule(
                generation: installation.generation,
                delayNanos: installation.delayNanos
            )
            while !Task.isCancelled {
                guard await WebRTCConnection.parkForDelay(
                    schedule.delayNanos,
                    on: timer
                ) else {
                    return
                }
                switch pump.drive(
                    generation: schedule.generation,
                    publication: installation.publication
                ) {
                case .stopped:
                    return
                case .terminal:
                    taskRegistry.cancelAll()
                    return
                case .next(let next):
                    schedule = next
                }
            }
        }
        guard taskRegistry.attachDTLS(
            candidate,
            token: installation.token
        ) else {
            candidate.cancel()
            return
        }

        // Close/failure can race the installation after the first terminal
        // check. Recheck after publication so no live timer survives a terminal
        // connection regardless of interleaving.
        if connState.withLock({ $0.stateMachine.isTerminal }) {
            cancelDTLSRetransmissionTimer()
        }
    }

    /// Remove the currently published DTLS timeout and return its Task owner.
    /// The caller must cancel the Task only after releasing the DTLS flight
    /// mutex.
    private func removeDTLSRetransmissionTimer() -> Task<Void, Never>? {
        timerTaskRegistry.withDTLS {
            owner -> Task<Void, Never>? in
            let current = owner?.task
            owner = nil
            return current
        }
    }

    /// Remove and cancel the currently published DTLS timeout, if any.
    private func cancelDTLSRetransmissionTimer() {
        removeDTLSRetransmissionTimer()?.cancel()
    }

    /// Start the periodic SCTP retransmission driver (RFC 4960 §6.3 T3-rtx).
    ///
    /// `SCTPAssociation` is purely reactive — it only acts when a packet
    /// arrives — so a periodic driver is required for lost DATA chunks to
    /// ever be retransmitted.
    private func startRetransmissionDriver() {
        guard !connState.withLock({ $0.stateMachine.isTerminal }) else {
            return
        }
        let taskRegistry = timerTaskRegistry
        let token = taskRegistry.withSCTP {
            owner -> TimerTaskToken? in
            guard owner == nil else { return nil }
            let token = TimerTaskToken()
            owner = TimerTaskOwner(token: token, task: nil)
            return token
        }
        guard let token else { return }

        // The retransmission tick is scheduled through the injected
        // `AsyncTimer` seam (`timer.sleep(untilNanos:)`), NOT `Task.sleep` /
        // `ContinuousClock`, both of which are unavailable under Embedded.
        let tickNanos = Self.retransmitTickInterval.facadeNanoseconds
        let timer = self.timer
        let pump = sctpRetransmissionPump
        // The tick suspension goes through `parkForTick(_:on:)`, a NON-throwing
        // helper that swallows the timer's typed `CancellationError` internally.
        // The Task closure therefore contains no throwing call, so Embedded does
        // not have to infer a thrown type across the `await` boundary (a bare
        // `catch` there widens to `any Error`, which Embedded rejects).
        // The closure captures only the connection-independent pump. The
        // facade remains deinitializable even when the caller omits close().
        let task = Task {
            guard taskRegistry.containsSCTP(token: token) else { return }
            defer { taskRegistry.clearSCTP(token: token) }
            while !Task.isCancelled {
                if !(await Self.parkForTick(tickNanos, on: timer)) { return }
                if pump.drive() {
                    taskRegistry.cancelAll()
                    return
                }
            }
        }
        guard taskRegistry.attachSCTP(task, token: token) else {
            task.cancel()
            return
        }
        if connState.withLock({ $0.stateMachine.isTerminal }) {
            taskRegistry.cancelAll()
        }
    }

    /// Suspend for one retransmission tick via the injected `AsyncTimer`,
    /// swallowing the timer's typed `CancellationError`.
    ///
    /// - Returns: `true` if the tick elapsed normally, `false` if the task was
    ///   cancelled during the suspension (the caller stops the loop).
    private static func parkForTick(
        _ tickNanos: UInt64,
        on timer: WebRTCTimer
    ) async -> Bool {
        await parkForDelay(tickNanos, on: timer)
    }

    /// Suspend for one relative delay using a saturating absolute deadline.
    private static func parkForDelay(
        _ delayNanos: UInt64,
        on timer: WebRTCTimer
    ) async -> Bool {
        let now = timer.monotonicNanos()
        let (deadline, overflow) = now.addingReportingOverflow(delayNanos)
        do {
            try await timer.sleep(untilNanos: overflow ? UInt64.max : deadline)
            return true
        } catch {
            return false
        }
    }

    /// Render a caught error into the human-readable reason string carried by
    /// `WebRTCError` / the connection state machine.
    ///
    /// `String(describing:)` is unavailable under Embedded Swift, so the rich
    /// per-error description is host-only. Under Embedded the caller's stable
    /// static `context` (a plain `String` literal, the only Embedded-legal
    /// reason source) describes WHICH operation failed — the failing subsystem is
    /// the actionable signal; the inner error's text is not reconstructible
    /// without Foundation reflection. Fail-closed behavior is preserved either
    /// way: the connection still transitions to the same terminal state.
    private static func failureReason(_ error: any Error, context: String) -> String {
        #if !hasFeature(Embedded)
        return String(describing: error)
        #else
        return context
        #endif
    }

    /// Encrypt and transfer one SCTP packet while the caller owns an in-flight
    /// lease. DTLS and the synchronous transport callback therefore cannot race
    /// terminal network-owner release.
    private func sendEncryptedUnderLease(
        _ plaintext: [UInt8],
        permit: EgressPermit
    ) throws(WebRTCError) {
        try egressCoordinator.sendEncrypted(plaintext, permit: permit)
    }

    /// Emit an SCTP batch with a fresh admission check before every datagram.
    ///
    /// A permit acquired before a concurrent `close()` authorizes that one
    /// datagram. The callback runs without the connection mutex. If the callback
    /// closes or fails the connection, replacing the epoch prevents every later
    /// packet in the same batch from being emitted.
    private func sendSCTPPackets(
        _ batch: SCTPEgressBatch
    ) throws(WebRTCError) {
        try egressCoordinator.sendSCTPPackets(batch)
    }

    /// Acquire one normal in-flight lease at the connection linearization point.
    /// No facade mutex is held while `body` performs crypto or transport I/O.
    private func withNormalEgressLease<Output>(
        permit requestedPermit: EgressPermit? = nil,
        _ body: (EgressPermit) throws(WebRTCError) -> Output
    ) throws(WebRTCError) -> Output {
        try egressCoordinator.withNormalLease(
            permit: requestedPermit,
            body
        )
    }

    /// Linearize admission and account for one normal egress operation.
    private func acquireNormalEgressLease(
        permit requestedPermit: EgressPermit? = nil
    ) throws(WebRTCError) -> EgressPermit {
        try egressCoordinator.acquireNormalLease(permit: requestedPermit)
    }

    /// Release a reserved final batch that cannot reach the sender because an
    /// earlier operation in the same terminal path failed.
    private func abandonReservedTerminalEgressPermit(
        _ permit: EgressPermit?
    ) {
        egressCoordinator.abandonReservedTerminalPermit(permit)
    }

    private func releaseEgressLease() {
        egressCoordinator.releaseLease()
    }

    /// Verify a multi-datagram producer's original epoch between callbacks.
    /// The already admitted first datagram remains authorized if close races it;
    /// later datagrams are suppressed after the epoch changes.
    private func validateNormalEgressPermit(
        _ permit: EgressPermit
    ) throws(WebRTCError) {
        try egressCoordinator.validateNormalPermit(permit)
    }

    /// Transfer one datagram owner to the transport while an in-flight lease is
    /// held, without retaining facade state across the callback.
    private func transferDatagramUnderLease(
        _ datagram: consuming [UInt8]
    ) throws(WebRTCError) {
        try egressCoordinator.transfer(consume datagram)
    }

    /// Transfer one standalone datagram through the common egress coordinator.
    private func sendDatagram(
        _ datagram: consuming [UInt8]
    ) throws(WebRTCError) {
        _ = try egressCoordinator.acquireNormalLease()
        defer { egressCoordinator.releaseLease() }
        try egressCoordinator.transfer(consume datagram)
    }

    /// Move a connection to its terminal failure state outside callback paths.
    private func failConnection(_ error: WebRTCError, context: String) {
        guard terminalCoordinator.commitFailure(error, context: context) else {
            return
        }
        prepareTerminalOwnerTeardown()
        completeTerminalNetworkTeardown()
    }

}
