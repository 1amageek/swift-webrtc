/// Embedded-clean SCTP State Cookie (RFC 4960 Section 5.1.3).
///
/// This core owns the cookie FRAMING (encode/decode over `[UInt8]`), the
/// signable-input construction, and the SECURITY binding check: expiry plus a
/// recompute-and-constant-time-compare of the HMAC. The concrete HMAC-SHA256 is
/// supplied by the caller through the `MessageAuthenticationCode` seam, so the
/// concrete crypto, the cookie-secret rotation, and the clock all stay
/// adapter-side. The binding check is fail-closed: any mismatch (expiry, length,
/// or MAC) returns `false`; it never accepts on mismatch.

import P2PCoreBytes
import P2PCoreCrypto

/// SCTP State Cookie value type, Embedded-clean.
///
/// Stores the cookie fields plus the HMAC computed over them. The HMAC is fed in
/// by the adapter (via the `MessageAuthenticationCode` seam) — the core never
/// instantiates a concrete crypto backend.
public struct SCTPCookieCore: Sendable, Equatable {
    /// Timestamp when the cookie was created, on the adapter's monotonic clock,
    /// in milliseconds.
    public let timestamp: UInt64

    /// Peer's initiate tag (from INIT).
    public let peerTag: UInt32

    /// Local initiate tag (for verification).
    public let localTag: UInt32

    /// Peer's initial TSN (from INIT).
    public let peerInitialTSN: UInt32

    /// Peer's advertised receiver window credit.
    public let peerARWC: UInt32

    /// Number of outbound streams.
    public let outboundStreams: UInt16

    /// Number of inbound streams.
    public let inboundStreams: UInt16

    /// HMAC over the signable input (32 bytes for HMAC-SHA256).
    public let hmac: [UInt8]

    /// Encoded size: timestamp(8) + peerTag(4) + localTag(4) + peerTSN(4)
    /// + peerARWC(4) + streams(4) + hmac(32) = 60 bytes.
    public static let encodedSize = 60

    /// Size of the HMAC-covered prefix (everything except the trailing HMAC).
    public static let signableSize = 28

    /// Memberwise initializer. The HMAC is provided by the adapter — the core
    /// does not compute it itself.
    public init(
        timestamp: UInt64,
        peerTag: UInt32,
        localTag: UInt32,
        peerInitialTSN: UInt32,
        peerARWC: UInt32,
        outboundStreams: UInt16,
        inboundStreams: UInt16,
        hmac: [UInt8]
    ) {
        self.timestamp = timestamp
        self.peerTag = peerTag
        self.localTag = localTag
        self.peerInitialTSN = peerInitialTSN
        self.peerARWC = peerARWC
        self.outboundStreams = outboundStreams
        self.inboundStreams = inboundStreams
        self.hmac = hmac
    }

    // MARK: - Signable input (the HMAC-covered bytes)

    /// Builds the byte sequence the HMAC covers: every field except the HMAC
    /// itself, in wire order. Both `generate` and `validateBinding` derive the
    /// HMAC input from this single function so they cannot diverge.
    public static func signableInput(
        timestamp: UInt64,
        peerTag: UInt32,
        localTag: UInt32,
        peerInitialTSN: UInt32,
        peerARWC: UInt32,
        outboundStreams: UInt16,
        inboundStreams: UInt16
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
        return data
    }

    /// The signable input for this cookie instance.
    public func signableInput() -> [UInt8] {
        Self.signableInput(
            timestamp: timestamp,
            peerTag: peerTag,
            localTag: localTag,
            peerInitialTSN: peerInitialTSN,
            peerARWC: peerARWC,
            outboundStreams: outboundStreams,
            inboundStreams: inboundStreams
        )
    }

    // MARK: - Generation (HMAC via seam)

    /// Generates a cookie, routing the HMAC computation through the
    /// `MessageAuthenticationCode` seam. The caller supplies `nowMillis` (its
    /// monotonic clock) and `secretKey` (its rotating secret).
    public static func generate<M: MessageAuthenticationCode>(
        secretKey: [UInt8],
        timestamp nowMillis: UInt64,
        peerTag: UInt32,
        localTag: UInt32,
        peerInitialTSN: UInt32,
        peerARWC: UInt32,
        outboundStreams: UInt16,
        inboundStreams: UInt16,
        as macType: M.Type
    ) -> SCTPCookieCore {
        let input = signableInput(
            timestamp: nowMillis,
            peerTag: peerTag,
            localTag: localTag,
            peerInitialTSN: peerInitialTSN,
            peerARWC: peerARWC,
            outboundStreams: outboundStreams,
            inboundStreams: inboundStreams
        )
        let mac = M.authenticationCode(for: input.span, key: secretKey.span)
        return SCTPCookieCore(
            timestamp: nowMillis,
            peerTag: peerTag,
            localTag: localTag,
            peerInitialTSN: peerInitialTSN,
            peerARWC: peerARWC,
            outboundStreams: outboundStreams,
            inboundStreams: inboundStreams,
            hmac: mac
        )
    }

    // MARK: - Security binding check (fail-closed, constant-time)

    /// Validates the cookie: expiry first, then a recompute-and-constant-time
    /// compare of the HMAC through the seam. Fail-closed — returns `false` for
    /// expiry, future timestamp, or any MAC mismatch; never accepts on mismatch.
    ///
    /// - Parameters:
    ///   - secretKey: the server secret (adapter-supplied, possibly rotated).
    ///   - nowMillis: the current time on the adapter's monotonic clock.
    ///   - maxAgeMillis: maximum cookie age in milliseconds.
    ///   - macType: the concrete HMAC type backing the seam.
    public func validateBinding<M: MessageAuthenticationCode>(
        secretKey: [UInt8],
        nowMillis: UInt64,
        maxAgeMillis: UInt64,
        as macType: M.Type
    ) -> Bool {
        // Expiry check (must precede the MAC compare; a future timestamp or an
        // over-age cookie is rejected outright).
        guard nowMillis >= timestamp else { return false }
        let age = nowMillis - timestamp
        guard age <= maxAgeMillis else { return false }

        // Recompute over the signable input and constant-time compare against
        // the stored HMAC via the seam. `M.isValid` does the constant-time
        // comparison internally and never short-circuits on a difference.
        let input = signableInput()
        return M.isValid(hmac.span, for: input.span, key: secretKey.span)
    }

    // MARK: - Framing

    /// Encode the cookie to wire format as `[UInt8]`.
    public func encode() -> [UInt8] {
        var data = [UInt8]()
        data.reserveCapacity(Self.encodedSize)
        appendUInt64(&data, timestamp)
        appendUInt32(&data, peerTag)
        appendUInt32(&data, localTag)
        appendUInt32(&data, peerInitialTSN)
        appendUInt32(&data, peerARWC)
        appendUInt16(&data, outboundStreams)
        appendUInt16(&data, inboundStreams)
        data.append(contentsOf: hmac)
        return data
    }

    /// Decode a cookie from `[UInt8]` wire format.
    ///
    /// - Throws: ``SCTPDecodeError/insufficientData`` if the buffer is too short.
    public static func decode(from data: [UInt8]) throws(SCTPWireError) -> SCTPCookieCore {
        guard data.count >= encodedSize else {
            throw SCTPWireError.decode(.insufficientData(expected: encodedSize, actual: data.count))
        }

        var offset = 0
        let timestamp = readUInt64(data, offset: offset); offset += 8
        let peerTag = readUInt32(data, offset: offset); offset += 4
        let localTag = readUInt32(data, offset: offset); offset += 4
        let peerInitialTSN = readUInt32(data, offset: offset); offset += 4
        let peerARWC = readUInt32(data, offset: offset); offset += 4
        let outboundStreams = readUInt16(data, offset: offset); offset += 2
        let inboundStreams = readUInt16(data, offset: offset); offset += 2

        var hmac = [UInt8]()
        hmac.reserveCapacity(32)
        for i in 0..<32 {
            hmac.append(data[offset + i])
        }

        return SCTPCookieCore(
            timestamp: timestamp,
            peerTag: peerTag,
            localTag: localTag,
            peerInitialTSN: peerInitialTSN,
            peerARWC: peerARWC,
            outboundStreams: outboundStreams,
            inboundStreams: inboundStreams,
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

private func readUInt16(_ data: [UInt8], offset: Int) -> UInt16 {
    UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
}

private func readUInt32(_ data: [UInt8], offset: Int) -> UInt32 {
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
