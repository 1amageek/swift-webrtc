/// SCTP Association (RFC 4960) — caller-locked protocol adapter.
///
/// This is the host boundary over the Embedded-clean ``SCTPAssociationEngine``.
/// It is a `final class & Sendable` that holds the value-type engine behind a
/// ``FacadeLock`` (the same `Synchronization.Mutex` contract on every target),
/// keeps the historical `Data`-based
/// public API, supplies the COOKIE HMAC via an immutable non-generic crypto
/// context backed by `P2PCrypto.DefaultHMACSHA256`, sources the random handshake material from the
/// `RandomSource` seam, and supplies the monotonic millisecond clock the
/// engine's T3-rtx / cookie timing needs.
///
/// All protocol correctness and security invariants live in the engine; this
/// adapter owns synchronization and injected time/crypto contexts. Host-only
/// compatibility overloads additionally bridge `Data` to `[UInt8]`.

import Synchronization
#if !hasFeature(Embedded) && !os(WASI)
import Foundation
#endif

/// SCTP association managing streams and TSN tracking.
final class SCTPAssociation: Sendable {
    private let engine: FacadeLock<SCTPAssociationStorage>
    private let clock: any SCTPMonotonicClock

    init(
        localPort: UInt16 = 5000,
        remotePort: UInt16 = 5000,
        maxInboundStreams: UInt16 = 65535,
        maxOutboundStreams: UInt16 = 65535,
        clock: any SCTPMonotonicClock = SCTPSystemMonotonicClock()
    ) {
        // RFC 4960 §3.3.2: the initiate tag must not be 0. The random handshake
        // material is sourced from the `RandomSource` seam here so the engine
        // stays deterministic and Embedded-clean.
        let tag = SCTPSecureRandom.uint32NonZero()
        let initialTSN = SCTPSecureRandom.uint32()
        let secretKey = SCTPSecureRandom.bytes(count: 32)
        self.clock = clock
        self.engine = FacadeLock(
            SCTPAssociationStorage(
                engine: SCTPAssociationEngine(
                    localPort: localPort,
                    remotePort: remotePort,
                    maxInboundStreams: maxInboundStreams,
                    maxOutboundStreams: maxOutboundStreams,
                    initiateTag: tag,
                    initialTSN: initialTSN,
                    cookieSecretKey: secretKey,
                    cookieCrypto: makeSCTPCookieCryptoContext()
                )
            )
        )
    }

    /// Current association state.
    var state: SCTPAssociationState {
        engine.withLock { $0.engine.state }
    }

    /// Whether the retransmission queue holds unacknowledged data.
    var hasUnacknowledgedData: Bool {
        engine.withLock { $0.engine.hasUnacknowledgedData }
    }

    /// Whether the peer advertised RFC 6525 RE-CONFIG support.
    var supportsStreamReconfiguration: Bool {
        engine.withLock { $0.engine.supportsStreamReconfiguration }
    }

    /// Generate an INIT chunk to start the association.
    func generateInit() -> SCTPPacket {
        engine.withLock { $0.engine.generateInit() }
    }

    #if !hasFeature(Embedded) && !os(WASI)
    /// Process an incoming SCTP packet (host `Data` surface).
    /// - Returns: response packets to send, and any received application data.
    /// - Throws: `SCTPError.verificationTagMismatch` for spoofed/stale packets,
    ///   `SCTPError.associationAborted` on peer abort, decode/buffer-limit errors.
    func processPacket(
        _ packet: SCTPPacket
    ) throws(SCTPError) -> (responses: [SCTPPacket], receivedData: [(streamID: UInt16, ppid: UInt32, data: Data)]) {
        let restartEntropy = Self.restartEntropy(for: packet)
        let now = try clock.currentMilliseconds()
        let result = try engine.withLock { storage throws(SCTPError) in
            try storage.engine.processPacket(
                packet,
                nowMillis: now,
                restartEntropy: restartEntropy
            )
        }
        // Bridge the engine's `[UInt8]` payloads to `Data` at this boundary.
        let received = result.receivedData.map { msg in
            (streamID: msg.streamID, ppid: msg.ppid, data: Data(msg.data))
        }
        return (result.responses, received)
    }

    /// Send data on a stream (host `Data` surface).
    /// - Throws: `SCTPError.sendQueueFull` (typed backpressure).
    func sendData(
        streamID: UInt16,
        payloadProtocolIdentifier: UInt32,
        data: Data,
        unordered: Bool = false,
        reliability: SCTPMessageReliability = .reliable
    ) throws(SCTPError) -> SCTPPacket {
        let now = try clock.currentMilliseconds()
        let bytes = [UInt8](data)
        return try engine.withLock { storage throws(SCTPError) in
            try storage.engine.sendData(
                streamID: streamID,
                payloadProtocolIdentifier: payloadProtocolIdentifier,
                data: bytes,
                unordered: unordered,
                reliability: reliability,
                nowMillis: now
            )
        }
    }

    /// Fragment and send data through the canonical packet-batch surface.
    ///
    /// The complete message is admitted atomically. The returned packets are the
    /// immediately window-eligible prefix and must be emitted in array order;
    /// the retained suffix is later returned by processing a SACK or by
    /// ``pollOutboundPackets()``.
    func sendDataPackets(
        streamID: UInt16,
        payloadProtocolIdentifier: UInt32,
        data: Data,
        unordered: Bool = false,
        reliability: SCTPMessageReliability = .reliable,
        maximumPacketByteCount: Int = 1_200
    ) throws(SCTPError) -> [SCTPPacket] {
        let now = try clock.currentMilliseconds()
        let bytes = [UInt8](data)
        return try engine.withLock { storage throws(SCTPError) in
            try storage.engine.sendDataPackets(
                streamID: streamID,
                payloadProtocolIdentifier: payloadProtocolIdentifier,
                data: bytes,
                unordered: unordered,
                reliability: reliability,
                nowMillis: now,
                maximumPacketByteCount: maximumPacketByteCount
            )
        }
    }
    #endif

    /// Process an incoming SCTP packet (`[UInt8]` payload surface).
    ///
    /// The Embedded-clean currency. The host `Data` overload above wraps this for
    /// the historical API; the WebRTC facade uses this directly under Embedded.
    /// - Returns: response packets to send, and any received application data.
    /// - Throws: `SCTPError.verificationTagMismatch` for spoofed/stale packets,
    ///   `SCTPError.associationAborted` on peer abort, decode/buffer-limit errors.
    func processPacketBytes(
        _ packet: SCTPPacket
    ) throws(SCTPError) -> (responses: [SCTPPacket], receivedData: [SCTPReceivedMessage]) {
        let restartEntropy = Self.restartEntropy(for: packet)
        let now = try clock.currentMilliseconds()
        return try engine.withLock { storage throws(SCTPError) in
            try storage.engine.processPacket(
                packet,
                nowMillis: now,
                restartEntropy: restartEntropy
            )
        }
    }

    /// Process a packet and preserve ordered stream-reset events alongside
    /// application messages.
    func processPacketBytesWithEvents(
        _ packet: SCTPPacket
    ) throws(SCTPError) -> SCTPProcessResult {
        let restartEntropy = Self.restartEntropy(for: packet)
        let now = try clock.currentMilliseconds()
        return try engine.withLock { storage throws(SCTPError) in
            try storage.engine.processPacketWithEvents(
                packet,
                nowMillis: now,
                restartEntropy: restartEntropy
            )
        }
    }

    /// Canonical transport-owner surface preserving a terminal wire response
    /// alongside its typed protocol failure.
    func processPacketBytesOutcome(
        _ packet: SCTPPacket
    ) throws(SCTPError) -> SCTPProcessOutcome {
        let restartEntropy = Self.restartEntropy(for: packet)
        let now = try clock.currentMilliseconds()
        return try engine.withLock { storage throws(SCTPError) in
            try storage.engine.processPacketOutcome(
                packet,
                nowMillis: now,
                restartEntropy: restartEntropy
            )
        }
    }

    /// Request reset of selected outgoing SCTP streams.
    ///
    /// `nil` means the request was accepted behind the single in-flight reset;
    /// the next packet is emitted by ``pollOutboundPackets()`` after the
    /// current response is processed.
    func requestOutgoingStreamReset(
        _ selection: SCTPStreamSelection
    ) throws(SCTPError) -> SCTPPacket? {
        let now = try clock.currentMilliseconds()
        return try engine.withLock { storage throws(SCTPError) in
            try storage.engine.requestOutgoingStreamReset(selection, nowMillis: now)
        }
    }

    /// Begin an RFC 9260 graceful association shutdown.
    ///
    /// A returned packet is ready for immediate transport emission. `nil`
    /// means the association entered SHUTDOWN-PENDING and will emit SHUTDOWN
    /// from ``pollOutboundPackets()`` after retained DATA and control work drain.
    func requestShutdown() throws(SCTPError) -> SCTPPacket? {
        let now = try clock.currentMilliseconds()
        return try engine.withLock { storage throws(SCTPError) in
            try storage.engine.requestShutdown(nowMillis: now)
        }
    }

    /// Immediately release association-owned DATA and control state.
    ///
    /// This performs no I/O. Call ``requestShutdown()`` when the owner intends
    /// to complete the RFC 9260 graceful wire handshake first.
    func terminate() {
        engine.withLock { $0.engine.terminate() }
    }

    /// Send data on a stream (`[UInt8]` payload surface).
    /// - Throws: `SCTPError.sendQueueFull` (typed backpressure).
    func sendDataBytes(
        streamID: UInt16,
        payloadProtocolIdentifier: UInt32,
        data: [UInt8],
        unordered: Bool = false,
        reliability: SCTPMessageReliability = .reliable
    ) throws(SCTPError) -> SCTPPacket {
        let now = try clock.currentMilliseconds()
        return try engine.withLock { storage throws(SCTPError) in
            try storage.engine.sendData(
                streamID: streamID,
                payloadProtocolIdentifier: payloadProtocolIdentifier,
                data: data,
                unordered: unordered,
                reliability: reliability,
                nowMillis: now
            )
        }
    }

    /// Fragment and atomically admit one `[UInt8]` user message.
    ///
    /// I/O remains the caller's responsibility and must occur after this method
    /// releases the association mutex. The returned packets are only the
    /// immediately window-eligible prefix; SACK processing and
    /// ``pollOutboundPackets()`` release the retained suffix.
    func sendDataPackets(
        streamID: UInt16,
        payloadProtocolIdentifier: UInt32,
        data: [UInt8],
        unordered: Bool = false,
        reliability: SCTPMessageReliability = .reliable,
        maximumPacketByteCount: Int = 1_200
    ) throws(SCTPError) -> [SCTPPacket] {
        let now = try clock.currentMilliseconds()
        return try engine.withLock { storage throws(SCTPError) in
            try storage.engine.sendDataPackets(
                streamID: streamID,
                payloadProtocolIdentifier: payloadProtocolIdentifier,
                data: data,
                unordered: unordered,
                reliability: reliability,
                nowMillis: now,
                maximumPacketByteCount: maximumPacketByteCount
            )
        }
    }

    /// Poll every packet currently eligible for transport emission while
    /// preserving a final wire response beside any typed terminal failure.
    ///
    /// I/O remains outside the association mutex. A monotonic-clock failure is
    /// terminal because retransmission and shutdown deadlines can no longer be
    /// driven safely.
    func pollOutboundPacketsOutcome() -> SCTPOutboundPollOutcome {
        let now: UInt64
        do {
            now = try clock.currentMilliseconds()
        } catch let error {
            engine.withLock { $0.engine.terminate() }
            return .terminal(packets: [], error: error)
        }
        return engine.withLock {
            $0.engine.pollOutboundPacketsOutcome(nowMillis: now)
        }
    }

    /// Compatibility projection for callers that cannot emit a terminal wire
    /// response beside its typed failure.
    func pollOutboundPackets() -> Result<[SCTPPacket], SCTPError> {
        switch pollOutboundPacketsOutcome() {
        case .packets(let packets):
            return .success(packets)
        case .terminal(_, let error):
            return .failure(error)
        }
    }

    /// Compatibility spelling for the former retransmission-only contract.
    @available(*, deprecated, renamed: "pollOutboundPackets()")
    func getPendingRetransmissions() -> Result<[SCTPPacket], SCTPError> {
        pollOutboundPackets()
    }

    /// Source restart entropy before entering the synchronized engine
    /// transaction. Non-INIT packets incur no random generation.
    private static func restartEntropy(
        for packet: SCTPPacket
    ) -> SCTPAssociationRestartEntropy? {
        guard packet.chunks.contains(where: {
            $0.chunkType == SCTPChunkType.initChunk.rawValue
        }) else {
            return nil
        }
        return SCTPAssociationRestartEntropy(
            initiateTag: SCTPSecureRandom.uint32NonZero(),
            initialTSN: SCTPSecureRandom.uint32()
        )
    }

    #if !hasFeature(Embedded) && !os(WASI)
    /// Deterministically poll the canonical terminal-aware surface at an
    /// injected host instant.
    func pollOutboundPacketsOutcome(
        now: ContinuousClock.Instant
    ) -> SCTPOutboundPollOutcome {
        let millis = SCTPSystemMonotonicClock.milliseconds(from: now)
        return engine.withLock {
            $0.engine.pollOutboundPacketsOutcome(nowMillis: millis)
        }
    }

    /// Poll outbound protocol work at an injected instant (host-only, for
    /// deterministic timer testing).
    func pollOutboundPackets(
        now: ContinuousClock.Instant
    ) -> Result<[SCTPPacket], SCTPError> {
        switch pollOutboundPacketsOutcome(now: now) {
        case .packets(let packets):
            return .success(packets)
        case .terminal(_, let error):
            return .failure(error)
        }
    }

    /// Compatibility spelling for the former retransmission-only contract.
    @available(*, deprecated, renamed: "pollOutboundPackets(now:)")
    func getPendingRetransmissions(
        now: ContinuousClock.Instant
    ) -> Result<[SCTPPacket], SCTPError> {
        pollOutboundPackets(now: now)
    }
    #endif
}

/// Concrete adapter-owned layout for the cookie-MAC-configured SCTP engine.
///
/// Swift 6.4 normal WASM can trap when a cross-module engine value is
/// materialized directly as the generic `Mutex<Value>` argument. The
/// association remains the sole owner; this module-local value preserves the
/// same `Mutex` storage, isolation, mutation entry points, and shutdown lifetime
/// on every target.
private struct SCTPAssociationStorage: Sendable {
    var engine: SCTPAssociationEngine
}
