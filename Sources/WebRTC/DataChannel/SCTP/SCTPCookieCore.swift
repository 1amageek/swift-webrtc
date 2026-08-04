/// Embedded-clean SCTP State Cookie (RFC 4960 Section 5.1.3).
///
/// This core owns the cookie FRAMING (encode/decode over `[UInt8]`), the
/// signable-input construction, and the SECURITY binding check: expiry plus a
/// recompute-and-constant-time-compare of the HMAC. The concrete HMAC-SHA256 is
/// supplied by the caller through an immutable `SCTPCookieCryptoContext`, so
/// the concrete crypto, the cookie-secret rotation, and the clock all stay
/// adapter-side. The binding check is fail-closed: any mismatch (expiry, length,
/// or MAC) returns `false`; it never accepts on mismatch.

import P2PCoreBytes

/// SCTP State Cookie value type, Embedded-clean.
///
/// Stores the cookie fields plus the HMAC computed over them. The HMAC is fed in
/// by the adapter (via `SCTPCookieCryptoContext`) — the core never instantiates
/// a concrete crypto backend or invokes an associated-type witness.
struct SCTPCookieCore: Sendable, Equatable {
    /// Timestamp when the cookie was created, on the adapter's monotonic clock,
    /// in milliseconds.
    let timestamp: UInt64

    /// Peer's initiate tag (from INIT).
    let peerTag: UInt32

    /// Local initiate tag (for verification).
    let localTag: UInt32

    /// Local verification tag from the existing TCB, or zero when none exists.
    let localTieTag: UInt32

    /// Peer verification tag from the existing TCB, or zero when unknown.
    let peerTieTag: UInt32

    /// Local initial TSN advertised in the INIT-ACK that carried this cookie.
    let localInitialTSN: UInt32

    /// Peer's initial TSN (from INIT).
    let peerInitialTSN: UInt32

    /// Peer's advertised receiver window credit.
    let peerARWC: UInt32

    /// Number of outbound streams.
    let outboundStreams: UInt16

    /// Number of inbound streams.
    let inboundStreams: UInt16

    /// Negotiated extension capabilities carried across COOKIE-ECHO.
    /// Bit 0 denotes RFC 6525 stream reconfiguration support and bit 1 denotes
    /// RFC 3758 partial-reliability support.
    let extensionFlags: UInt32

    /// Local SCTP port bound into the authenticated cookie.
    let localPort: UInt16

    /// Peer SCTP port bound into the authenticated cookie.
    let peerPort: UInt16

    /// HMAC over the signable input (32 bytes for HMAC-SHA256).
    let hmac: [UInt8]

    /// Encoded size of the current cookie wire format.
    ///
    /// The peer treats State Cookie bytes as opaque. Exact-size framing prevents
    /// unauthenticated trailing bytes from being accepted while allowing this
    /// endpoint to evolve its private cookie layout.
    static let encodedSize = 80

    /// Size of the HMAC-covered prefix (everything except the trailing HMAC).
    static let signableSize = 48

    /// Memberwise initializer. The HMAC is provided by the adapter — the core
    /// does not compute it itself.
    init(
        timestamp: UInt64,
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
        peerPort: UInt16,
        hmac: [UInt8]
    ) {
        self.timestamp = timestamp
        self.peerTag = peerTag
        self.localTag = localTag
        self.localTieTag = localTieTag
        self.peerTieTag = peerTieTag
        self.localInitialTSN = localInitialTSN
        self.peerInitialTSN = peerInitialTSN
        self.peerARWC = peerARWC
        self.outboundStreams = outboundStreams
        self.inboundStreams = inboundStreams
        self.extensionFlags = extensionFlags
        self.localPort = localPort
        self.peerPort = peerPort
        self.hmac = hmac
    }

    // MARK: - Signable input (the HMAC-covered bytes)

    /// Builds the byte sequence the HMAC covers: every field except the HMAC
    /// itself, in wire order. Both `generate` and `validateBinding` derive the
    /// HMAC input from this single function so they cannot diverge.
    static func signableInput(
        timestamp: UInt64,
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
    ) -> [UInt8] {
        var data = [UInt8]()
        data.reserveCapacity(signableSize)
        appendUInt64(&data, timestamp)
        appendUInt32(&data, peerTag)
        appendUInt32(&data, localTag)
        appendUInt32(&data, peerInitialTSN)
        appendUInt32(&data, peerARWC)
        appendUInt16(&data, outboundStreams)
        appendUInt16(&data, inboundStreams)
        appendUInt32(&data, extensionFlags)
        appendUInt32(&data, localTieTag)
        appendUInt32(&data, peerTieTag)
        appendUInt32(&data, localInitialTSN)
        appendUInt16(&data, localPort)
        appendUInt16(&data, peerPort)
        return data
    }

    /// The signable input for this cookie instance.
    func signableInput() -> [UInt8] {
        Self.signableInput(
            timestamp: timestamp,
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
            peerPort: peerPort
        )
    }

    // MARK: - Generation (HMAC via seam)

    /// Generates a cookie through injected non-generic HMAC operations. The
    /// caller supplies `nowMillis` (its monotonic clock) and `secretKey` (its
    /// rotating secret).
    static func generate(
        secretKey: [UInt8],
        timestamp nowMillis: UInt64,
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
        peerPort: UInt16,
        crypto: SCTPCookieCryptoContext
    ) -> SCTPCookieCore {
        let input = signableInput(
            timestamp: nowMillis,
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
            peerPort: peerPort
        )
        let mac = crypto.authenticationCode(for: input, key: secretKey)
        return SCTPCookieCore(
            timestamp: nowMillis,
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
            hmac: mac
        )
    }

    // MARK: - Security binding check (fail-closed, constant-time)

    /// Recomputes and constant-time compares the cookie authentication code.
    func isAuthentic(
        secretKey: [UInt8],
        crypto: SCTPCookieCryptoContext
    ) -> Bool {
        crypto.isValid(hmac, for: signableInput(), key: secretKey)
    }

    /// Reports whether the timestamp exceeds the caller's accepted lifetime.
    /// A future timestamp is always invalid and therefore treated as expired.
    func isExpired(nowMillis: UInt64, maxAgeMillis: UInt64) -> Bool {
        guard nowMillis >= timestamp else { return true }
        return nowMillis - timestamp > maxAgeMillis
    }

    /// Validates the cookie: authentication first, then expiry. Fail-closed — returns `false` for
    /// expiry, future timestamp, or any MAC mismatch; never accepts on mismatch.
    ///
    /// - Parameters:
    ///   - secretKey: the server secret (adapter-supplied, possibly rotated).
    ///   - nowMillis: the current time on the adapter's monotonic clock.
    ///   - maxAgeMillis: maximum cookie age in milliseconds.
    ///   - crypto: immutable non-generic HMAC operations supplied by the SCTP composition layer.
    func validateBinding(
        secretKey: [UInt8],
        nowMillis: UInt64,
        maxAgeMillis: UInt64,
        crypto: SCTPCookieCryptoContext
    ) -> Bool {
        guard isAuthentic(secretKey: secretKey, crypto: crypto) else {
            return false
        }
        return !isExpired(nowMillis: nowMillis, maxAgeMillis: maxAgeMillis)
    }

    // MARK: - Framing

    /// Encode the cookie to wire format as `[UInt8]`.
    func encode() -> [UInt8] {
        var data = [UInt8]()
        data.reserveCapacity(Self.encodedSize)
        appendUInt64(&data, timestamp)
        appendUInt32(&data, peerTag)
        appendUInt32(&data, localTag)
        appendUInt32(&data, peerInitialTSN)
        appendUInt32(&data, peerARWC)
        appendUInt16(&data, outboundStreams)
        appendUInt16(&data, inboundStreams)
        appendUInt32(&data, extensionFlags)
        appendUInt32(&data, localTieTag)
        appendUInt32(&data, peerTieTag)
        appendUInt32(&data, localInitialTSN)
        appendUInt16(&data, localPort)
        appendUInt16(&data, peerPort)
        data.append(contentsOf: hmac)
        return data
    }

    /// Decode a cookie from `[UInt8]` wire format.
    ///
    /// - Throws: ``SCTPDecodeError/insufficientData`` if the buffer is too short.
    static func decode(from data: [UInt8]) throws(SCTPWireError) -> SCTPCookieCore {
        guard data.count >= encodedSize else {
            throw SCTPWireError.decode(.insufficientData(expected: encodedSize, actual: data.count))
        }
        guard data.count == encodedSize else {
            throw SCTPWireError.decode(.invalidFormat("State Cookie has trailing bytes"))
        }

        var offset = 0
        let timestamp = readUInt64(data, offset: offset); offset += 8
        let peerTag = readCookieUInt32(data, offset: offset); offset += 4
        let localTag = readCookieUInt32(data, offset: offset); offset += 4
        let peerInitialTSN = readCookieUInt32(data, offset: offset); offset += 4
        let peerARWC = readCookieUInt32(data, offset: offset); offset += 4
        let outboundStreams = readCookieUInt16(data, offset: offset); offset += 2
        let inboundStreams = readCookieUInt16(data, offset: offset); offset += 2
        let extensionFlags = readCookieUInt32(data, offset: offset); offset += 4
        let localTieTag = readCookieUInt32(data, offset: offset); offset += 4
        let peerTieTag = readCookieUInt32(data, offset: offset); offset += 4
        let localInitialTSN = readCookieUInt32(data, offset: offset); offset += 4
        let localPort = readCookieUInt16(data, offset: offset); offset += 2
        let peerPort = readCookieUInt16(data, offset: offset); offset += 2

        var hmac = [UInt8]()
        hmac.reserveCapacity(32)
        for i in 0..<32 {
            hmac.append(data[offset + i])
        }

        return SCTPCookieCore(
            timestamp: timestamp,
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
            hmac: hmac
        )
    }
}

// MARK: - Local big-endian encoding helpers

private func appendUInt16(_ data: inout [UInt8], _ value: UInt16) {
    data.append(UInt8(value >> 8))
    data.append(UInt8(value & 0xFF))
}

private func appendUInt32(_ data: inout [UInt8], _ value: UInt32) {
    data.append(UInt8(value >> 24))
    data.append(UInt8((value >> 16) & 0xFF))
    data.append(UInt8((value >> 8) & 0xFF))
    data.append(UInt8(value & 0xFF))
}

private func appendUInt64(_ data: inout [UInt8], _ value: UInt64) {
    data.append(UInt8(value >> 56))
    data.append(UInt8((value >> 48) & 0xFF))
    data.append(UInt8((value >> 40) & 0xFF))
    data.append(UInt8((value >> 32) & 0xFF))
    data.append(UInt8((value >> 24) & 0xFF))
    data.append(UInt8((value >> 16) & 0xFF))
    data.append(UInt8((value >> 8) & 0xFF))
    data.append(UInt8(value & 0xFF))
}

private func readCookieUInt16(_ data: [UInt8], offset: Int) -> UInt16 {
    UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
}

private func readCookieUInt32(_ data: [UInt8], offset: Int) -> UInt32 {
    UInt32(data[offset]) << 24 |
    UInt32(data[offset + 1]) << 16 |
    UInt32(data[offset + 2]) << 8 |
    UInt32(data[offset + 3])
}

private func readUInt64(_ data: [UInt8], offset: Int) -> UInt64 {
    UInt64(data[offset]) << 56 |
    UInt64(data[offset + 1]) << 48 |
    UInt64(data[offset + 2]) << 40 |
    UInt64(data[offset + 3]) << 32 |
    UInt64(data[offset + 4]) << 24 |
    UInt64(data[offset + 5]) << 16 |
    UInt64(data[offset + 6]) << 8 |
    UInt64(data[offset + 7])
}
