/// SCTP Cookie (RFC 4960 Section 5.1.3) — Foundation adapter.
///
/// The cookie FRAMING and the SECURITY binding check (recompute-and-constant-time
/// compare, expiry) live in the Embedded-clean `SCTPCookieCore`. This adapter
/// keeps the historical `Data`-based public surface, supplies the monotonic clock
/// (`ProcessInfo.systemUptime`), and routes the HMAC through the
/// immutable non-generic crypto context using `SSLCrypto.HMACSHA256` on
/// every target. The cookie-secret rotation stays with the
/// caller (`SCTPAssociation`). The binding check is fail-closed: any mismatch
/// (HMAC, expiry, future timestamp) is rejected via the core, never accepted.
///
/// Non-Embedded only: this `Data`/`ProcessInfo`-clock surface exists for the
/// historical public API and the test suite. The Embedded path (and the cored
/// ``SCTPAssociationEngine``) drives ``SCTPWireCore/SCTPCookieCore`` directly with
/// an injected `nowMillis`, so this wrapper is gated out of the Embedded build.

#if !hasFeature(Embedded) && !os(WASI)
import Foundation

/// SCTP Cookie for secure handshake validation (`Data`-based adapter surface).
struct SCTPCookie: Sendable, Equatable {
    /// Cookie expiration time (default: 60 seconds)
    static let defaultMaxAge: TimeInterval = 60.0

    /// The Embedded-clean cookie value (framing + binding check live here).
    private let core: SCTPCookieCore

    /// Timestamp when cookie was created (milliseconds since system boot uptime)
    var timestamp: UInt64 { core.timestamp }

    /// Peer's initiate tag (from INIT)
    var peerTag: UInt32 { core.peerTag }

    /// Local initiate tag (for verification)
    var localTag: UInt32 { core.localTag }

    /// Local verification tag from the existing TCB, or zero for a cold open.
    var localTieTag: UInt32 { core.localTieTag }

    /// Peer verification tag from the existing TCB, or zero when unknown.
    var peerTieTag: UInt32 { core.peerTieTag }

    /// Local initial TSN advertised in the INIT-ACK.
    var localInitialTSN: UInt32 { core.localInitialTSN }

    /// Peer's initial TSN (from INIT)
    var peerInitialTSN: UInt32 { core.peerInitialTSN }

    /// Peer's advertised receiver window credit
    var peerARWC: UInt32 { core.peerARWC }

    /// Number of outbound streams
    var outboundStreams: UInt16 { core.outboundStreams }

    /// Number of inbound streams
    var inboundStreams: UInt16 { core.inboundStreams }

    /// Negotiated extension capability flags protected by the cookie HMAC.
    var extensionFlags: UInt32 { core.extensionFlags }

    /// Local SCTP port protected by the cookie HMAC.
    var localPort: UInt16 { core.localPort }

    /// Peer SCTP port protected by the cookie HMAC.
    var peerPort: UInt16 { core.peerPort }

    /// HMAC-SHA256 of the cookie data (32 bytes)
    var hmac: Data { Data(core.hmac) }

    /// Cookie encoding size: 80 bytes.
    static let encodedSize = SCTPCookieCore.encodedSize

    private init(core: SCTPCookieCore) {
        self.core = core
    }

    /// Generate a new cookie for INIT-ACK.
    ///
    /// The HMAC is computed through the injected non-generic HMAC-SHA256
    /// context; the timestamp is the adapter's monotonic clock.
    /// - Parameters:
    ///   - secretKey: Server's secret key for HMAC (should be at least 32 bytes)
    ///   - peerTag: Peer's initiate tag from INIT
    ///   - localTag: Local initiate tag for INIT-ACK
    ///   - localTieTag: Existing local verification tag, or zero for a cold open
    ///   - peerTieTag: Existing peer verification tag, or zero when unknown
    ///   - localInitialTSN: Local initial TSN advertised in INIT-ACK
    ///   - peerInitialTSN: Peer's initial TSN from INIT
    ///   - peerARWC: Peer's advertised receiver window credit
    ///   - outboundStreams: Negotiated outbound streams
    ///   - inboundStreams: Negotiated inbound streams
    /// - Returns: A new SCTPCookie
    static func generate(
        secretKey: Data,
        peerTag: UInt32,
        localTag: UInt32,
        localTieTag: UInt32,
        peerTieTag: UInt32,
        localInitialTSN: UInt32,
        peerInitialTSN: UInt32,
        peerARWC: UInt32,
        outboundStreams: UInt16,
        inboundStreams: UInt16,
        extensionFlags: UInt32 = 0,
        localPort: UInt16,
        peerPort: UInt16
    ) -> SCTPCookie {
        let core = SCTPCookieCore.generate(
            secretKey: [UInt8](secretKey),
            timestamp: currentTimestampMilliseconds(),
            peerTag: peerTag,
            localTag: localTag,
            localTieTag: localTieTag,
            peerTieTag: peerTieTag,
            localInitialTSN: localInitialTSN,
            peerInitialTSN: peerInitialTSN,
            peerARWC: peerARWC,
            outboundStreams: outboundStreams,
            inboundStreams: inboundStreams,
            extensionFlags: extensionFlags,
            localPort: localPort,
            peerPort: peerPort,
            crypto: makeSCTPCookieCryptoContext()
        )
        return SCTPCookie(core: core)
    }

    /// Validate a cookie received in COOKIE-ECHO.
    ///
    /// Delegates the fail-closed binding check (expiry + constant-time HMAC
    /// compare) to the non-generic `SCTPCookieCore` crypto context boundary.
    /// - Parameters:
    ///   - secretKey: Server's secret key for HMAC
    ///   - maxAge: Maximum cookie age (default: 60 seconds)
    /// - Returns: True if cookie is valid and not expired
    func validate(secretKey: Data, maxAge: TimeInterval = defaultMaxAge) -> Bool {
        core.validateBinding(
            secretKey: [UInt8](secretKey),
            nowMillis: Self.currentTimestampMilliseconds(),
            maxAgeMillis: UInt64(maxAge * 1000),
            crypto: makeSCTPCookieCryptoContext()
        )
    }

    /// Encode the cookie to wire format.
    func encode() -> Data {
        Data(core.encode())
    }

    /// Decode a cookie from wire format.
    /// - Parameter data: The encoded cookie data
    /// - Returns: Decoded cookie
    /// - Throws: SCTPError if data is malformed
    static func decode(from data: Data) throws -> SCTPCookie {
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
    static func nowMilliseconds() -> UInt64 {
        currentTimestampMilliseconds()
    }

    private static func currentTimestampMilliseconds() -> UInt64 {
        UInt64(ProcessInfo.processInfo.systemUptime * 1000)
    }
}

#endif
