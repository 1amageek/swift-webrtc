/// SCTP Cookie (RFC 4960 Section 5.1.3) — Foundation adapter.
///
/// The cookie FRAMING and the SECURITY binding check (recompute-and-constant-time
/// compare, expiry) live in the Embedded-clean `SCTPCookieCore`. This adapter
/// keeps the historical `Data`-based public surface, supplies the monotonic clock
/// (`ProcessInfo.systemUptime`), and routes the HMAC through the
/// `MessageAuthenticationCode` seam using the lib-internal
/// ``FoundationHMACSHA256`` provider. The cookie-secret rotation stays with the
/// caller (`SCTPAssociation`). The binding check is fail-closed: any mismatch
/// (HMAC, expiry, future timestamp) is rejected via the core, never accepted.
///
/// Host-only: this `Data`/`ProcessInfo`-clock surface exists for the historical
/// public API and the test suite. The Embedded path (and the cored
/// ``SCTPAssociationEngine``) drives ``SCTPWireCore/SCTPCookieCore`` directly with
/// an injected `nowMillis`, so this wrapper is gated out of the Embedded build.

#if !hasFeature(Embedded)
import Foundation
import SCTPWireCore

/// SCTP Cookie for secure handshake validation (`Data`-based adapter surface).
public struct SCTPCookie: Sendable, Equatable {
    /// Cookie expiration time (default: 60 seconds)
    public static let defaultMaxAge: TimeInterval = 60.0

    /// The Embedded-clean cookie value (framing + binding check live here).
    private let core: SCTPCookieCore

    /// Timestamp when cookie was created (milliseconds since system boot uptime)
    public var timestamp: UInt64 { core.timestamp }

    /// Peer's initiate tag (from INIT)
    public var peerTag: UInt32 { core.peerTag }

    /// Local initiate tag (for verification)
    public var localTag: UInt32 { core.localTag }

    /// Peer's initial TSN (from INIT)
    public var peerInitialTSN: UInt32 { core.peerInitialTSN }

    /// Peer's advertised receiver window credit
    public var peerARWC: UInt32 { core.peerARWC }

    /// Number of outbound streams
    public var outboundStreams: UInt16 { core.outboundStreams }

    /// Number of inbound streams
    public var inboundStreams: UInt16 { core.inboundStreams }

    /// HMAC-SHA256 of the cookie data (32 bytes)
    public var hmac: Data { Data(core.hmac) }

    /// Cookie encoding size: 60 bytes.
    public static let encodedSize = SCTPCookieCore.encodedSize

    private init(core: SCTPCookieCore) {
        self.core = core
    }

    /// Generate a new cookie for INIT-ACK.
    ///
    /// The HMAC is computed through the `MessageAuthenticationCode` seam
    /// (HMAC-SHA256); the timestamp is the adapter's monotonic clock.
    /// - Parameters:
    ///   - secretKey: Server's secret key for HMAC (should be at least 32 bytes)
    ///   - peerTag: Peer's initiate tag from INIT
    ///   - localTag: Local initiate tag for INIT-ACK
    ///   - peerInitialTSN: Peer's initial TSN from INIT
    ///   - peerARWC: Peer's advertised receiver window credit
    ///   - outboundStreams: Negotiated outbound streams
    ///   - inboundStreams: Negotiated inbound streams
    /// - Returns: A new SCTPCookie
    public static func generate(
        secretKey: Data,
        peerTag: UInt32,
        localTag: UInt32,
        peerInitialTSN: UInt32,
        peerARWC: UInt32,
        outboundStreams: UInt16,
        inboundStreams: UInt16
    ) -> SCTPCookie {
        let core = SCTPCookieCore.generate(
            secretKey: [UInt8](secretKey),
            timestamp: currentTimestampMilliseconds(),
            peerTag: peerTag,
            localTag: localTag,
            peerInitialTSN: peerInitialTSN,
            peerARWC: peerARWC,
            outboundStreams: outboundStreams,
            inboundStreams: inboundStreams,
            as: FoundationHMACSHA256.self
        )
        return SCTPCookie(core: core)
    }

    /// Validate a cookie received in COOKIE-ECHO.
    ///
    /// Delegates the fail-closed binding check (expiry + constant-time HMAC
    /// compare) to ``SCTPCookieCore/validateBinding(secretKey:nowMillis:maxAgeMillis:as:)``.
    /// - Parameters:
    ///   - secretKey: Server's secret key for HMAC
    ///   - maxAge: Maximum cookie age (default: 60 seconds)
    /// - Returns: True if cookie is valid and not expired
    public func validate(secretKey: Data, maxAge: TimeInterval = defaultMaxAge) -> Bool {
        core.validateBinding(
            secretKey: [UInt8](secretKey),
            nowMillis: Self.currentTimestampMilliseconds(),
            maxAgeMillis: UInt64(maxAge * 1000),
            as: FoundationHMACSHA256.self
        )
    }

    /// Encode the cookie to wire format.
    public func encode() -> Data {
        Data(core.encode())
    }

    /// Decode a cookie from wire format.
    /// - Parameter data: The encoded cookie data
    /// - Returns: Decoded cookie
    /// - Throws: SCTPError if data is malformed
    public static func decode(from data: Data) throws -> SCTPCookie {
        do {
            let core = try SCTPCookieCore.decode(from: [UInt8](data))
            return SCTPCookie(core: core)
        } catch {
            try error.rethrowUnwrapped()
        }
    }

    // MARK: - Clock (adapter-side)

    /// Current monotonic timestamp in milliseconds, on the same clock used for
    /// cookie creation/validation. Exposed so the association's consumed-cookie
    /// cache evicts entries on the identical time base.
    public static func nowMilliseconds() -> UInt64 {
        currentTimestampMilliseconds()
    }

    private static func currentTimestampMilliseconds() -> UInt64 {
        UInt64(ProcessInfo.processInfo.systemUptime * 1000)
    }
}

#endif
