/// SCTP Association (RFC 4960) — caller-locked Foundation/host adapter.
///
/// This is the host boundary over the Embedded-clean ``SCTPAssociationEngine``.
/// It is a `final class & Sendable` that holds the value-type engine behind a
/// ``FacadeLock`` (the proven caller-locked pattern: `Synchronization.Mutex` on
/// host, an `Atomic` spinlock under Embedded), keeps the historical `Data`-based
/// public API, supplies the COOKIE HMAC via the `MessageAuthenticationCode` seam
/// (host: ``FoundationHMACSHA256``; Embedded: `BoringHMACSHA256`), sources the
/// random handshake material from the `RandomSource` seam, and supplies the
/// monotonic millisecond clock the engine's T3-rtx / cookie timing needs.
///
/// All protocol correctness and security invariants live in the engine; this
/// adapter only bridges `Data` ⇄ `[UInt8]`, owns synchronization, and injects the
/// time/crypto seams.

import SCTPWireCore
#if !hasFeature(Embedded)
import Foundation
#endif
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(WASILibc)
import WASILibc
#endif

#if !hasFeature(Embedded)
/// The concrete COOKIE HMAC for the host build.
private typealias SCTPCookieMAC = FoundationHMACSHA256
#else
import P2PCryptoBoringSSL
/// The concrete COOKIE HMAC for the Embedded build.
private typealias SCTPCookieMAC = BoringHMACSHA256
#endif

/// SCTP association managing streams and TSN tracking.
public final class SCTPAssociation: Sendable {
    private let engine: FacadeLock<SCTPAssociationEngine<SCTPCookieMAC>>

    public init(
        localPort: UInt16 = 5000,
        remotePort: UInt16 = 5000,
        maxInboundStreams: UInt16 = 65535,
        maxOutboundStreams: UInt16 = 65535
    ) {
        // RFC 4960 §3.3.2: the initiate tag must not be 0. The random handshake
        // material is sourced from the `RandomSource` seam here so the engine
        // stays deterministic and Embedded-clean.
        let tag = SCTPSecureRandom.uint32NonZero()
        let initialTSN = SCTPSecureRandom.uint32()
        let secretKey = SCTPSecureRandom.bytes(count: 32)
        self.engine = FacadeLock(SCTPAssociationEngine<SCTPCookieMAC>(
            localPort: localPort,
            remotePort: remotePort,
            maxInboundStreams: maxInboundStreams,
            maxOutboundStreams: maxOutboundStreams,
            initiateTag: tag,
            initialTSN: initialTSN,
            cookieSecretKey: secretKey
        ))
    }

    /// Current association state.
    public var state: SCTPAssociationState {
        engine.withLock { $0.state }
    }

    /// Whether the retransmission queue holds unacknowledged data.
    public var hasUnacknowledgedData: Bool {
        engine.withLock { $0.hasUnacknowledgedData }
    }

    /// Generate an INIT chunk to start the association.
    public func generateInit() -> SCTPPacket {
        engine.withLock { $0.generateInit() }
    }

    #if !hasFeature(Embedded)
    /// Process an incoming SCTP packet (host `Data` surface).
    /// - Returns: response packets to send, and any received application data.
    /// - Throws: `SCTPError.verificationTagMismatch` for spoofed/stale packets,
    ///   `SCTPError.associationAborted` on peer abort, decode/buffer-limit errors.
    public func processPacket(
        _ packet: SCTPPacket
    ) throws(SCTPError) -> (responses: [SCTPPacket], receivedData: [(streamID: UInt16, ppid: UInt32, data: Data)]) {
        let now = Self.nowMillis()
        let result = try engine.withLock { engine throws(SCTPError) in
            try engine.processPacket(packet, nowMillis: now)
        }
        // Bridge the engine's `[UInt8]` payloads to `Data` at this boundary.
        let received = result.receivedData.map { msg in
            (streamID: msg.streamID, ppid: msg.ppid, data: Data(msg.data))
        }
        return (result.responses, received)
    }

    /// Send data on a stream (host `Data` surface).
    /// - Throws: `SCTPError.sendQueueFull` (typed backpressure).
    public func sendData(
        streamID: UInt16,
        payloadProtocolIdentifier: UInt32,
        data: Data,
        unordered: Bool = false
    ) throws(SCTPError) -> SCTPPacket {
        let now = Self.nowMillis()
        let bytes = [UInt8](data)
        return try engine.withLock { engine throws(SCTPError) in
            try engine.sendData(
                streamID: streamID,
                payloadProtocolIdentifier: payloadProtocolIdentifier,
                data: bytes,
                unordered: unordered,
                nowMillis: now
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
    public func processPacketBytes(
        _ packet: SCTPPacket
    ) throws(SCTPError) -> (responses: [SCTPPacket], receivedData: [SCTPReceivedMessage]) {
        let now = Self.nowMillis()
        return try engine.withLock { engine throws(SCTPError) in
            try engine.processPacket(packet, nowMillis: now)
        }
    }

    /// Send data on a stream (`[UInt8]` payload surface).
    /// - Throws: `SCTPError.sendQueueFull` (typed backpressure).
    public func sendDataBytes(
        streamID: UInt16,
        payloadProtocolIdentifier: UInt32,
        data: [UInt8],
        unordered: Bool = false
    ) throws(SCTPError) -> SCTPPacket {
        let now = Self.nowMillis()
        return try engine.withLock { engine throws(SCTPError) in
            try engine.sendData(
                streamID: streamID,
                payloadProtocolIdentifier: payloadProtocolIdentifier,
                data: data,
                unordered: unordered,
                nowMillis: now
            )
        }
    }

    /// Get pending retransmissions.
    /// - Returns: packets to retransmit, or `.maxRetransmitsExceeded` once the
    ///   per-chunk limit is exceeded (the association then transitions to closed).
    public func getPendingRetransmissions() -> Result<[SCTPPacket], SCTPError> {
        let now = Self.nowMillis()
        return engine.withLock { $0.getPendingRetransmissions(nowMillis: now) }
    }

    #if !hasFeature(Embedded)
    /// Get pending retransmissions at an injected instant (host-only, for
    /// deterministic timer testing). The instant is converted to the engine's
    /// monotonic-millisecond domain against a fixed epoch.
    /// - Parameter now: the instant to evaluate retransmission timers at.
    public func getPendingRetransmissions(
        now: ContinuousClock.Instant
    ) -> Result<[SCTPPacket], SCTPError> {
        let millis = Self.millis(from: now)
        return engine.withLock { $0.getPendingRetransmissions(nowMillis: millis) }
    }
    #endif

    // MARK: - Monotonic clock (host boundary)

    #if !hasFeature(Embedded)
    /// Fixed epoch so injected `ContinuousClock.Instant`s and the self-sourced
    /// "now" share one monotonic millisecond domain.
    private static let epoch = ContinuousClock.now

    private static func nowMillis() -> UInt64 {
        millis(from: ContinuousClock.now)
    }

    private static func millis(from instant: ContinuousClock.Instant) -> UInt64 {
        let d = instant - epoch
        let (seconds, attoseconds) = d.components
        guard seconds > 0 || attoseconds > 0 else { return 0 }
        let secMillis = UInt64(max(0, seconds)) &* 1000
        let attoMillis = UInt64(max(0, attoseconds) / 1_000_000_000_000_000)
        return secMillis &+ attoMillis
    }
    #else
    private static func nowMillis() -> UInt64 {
        #if canImport(WASILibc)
        var timestamp: __wasi_timestamp_t = 0
        let result = __wasi_clock_time_get(__wasi_clockid_t(1), 1, &timestamp)
        precondition(result == 0, "WASI monotonic clock failed")
        return UInt64(timestamp) / 1_000_000
        #else
        var ts = timespec()
        let result = clock_gettime(CLOCK_MONOTONIC, &ts)
        precondition(result == 0, "clock_gettime(CLOCK_MONOTONIC) failed")
        let seconds = UInt64(ts.tv_sec)
        let nanos = UInt64(ts.tv_nsec)
        return (seconds &* 1_000_000_000 &+ nanos) / 1_000_000
        #endif
    }
    #endif
}
