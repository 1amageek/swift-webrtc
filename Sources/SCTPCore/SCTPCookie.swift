/// SCTP Cookie (RFC 4960 Section 5.1.3)
///
/// Secure cookie for SCTP 4-way handshake. The cookie contains:
/// - Timestamp for expiration check
/// - Peer initiate tag (from INIT)
/// - Local initiate tag (for INIT-ACK)
/// - HMAC-SHA256 for integrity protection

import Foundation
import Crypto

/// SCTP Cookie for secure handshake validation
public struct SCTPCookie: Sendable, Equatable {
    /// Cookie expiration time (default: 60 seconds)
    public static let defaultMaxAge: TimeInterval = 60.0

    /// Timestamp when cookie was created (milliseconds since reference date)
    public let timestamp: UInt64

    /// Peer's initiate tag (from INIT)
    public let peerTag: UInt32

    /// Local initiate tag (for verification)
    public let localTag: UInt32

    /// Peer's initial TSN (from INIT)
    public let peerInitialTSN: UInt32

    /// Peer's advertised receiver window credit
    public let peerARWC: UInt32

    /// Number of outbound streams
    public let outboundStreams: UInt16

    /// Number of inbound streams
    public let inboundStreams: UInt16

    /// HMAC-SHA256 of the cookie data (32 bytes)
    public let hmac: Data

    /// Cookie encoding size: timestamp(8) + peerTag(4) + localTag(4) + peerTSN(4) + peerARWC(4) + streams(4) + hmac(32) = 60 bytes
    public static let encodedSize = 60

    /// Create a new cookie
    private init(
        timestamp: UInt64,
        peerTag: UInt32,
        localTag: UInt32,
        peerInitialTSN: UInt32,
        peerARWC: UInt32,
        outboundStreams: UInt16,
        inboundStreams: UInt16,
        hmac: Data
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

    /// Generate a new cookie for INIT-ACK
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
        let timestamp = UInt64(Date().timeIntervalSinceReferenceDate * 1000)

        let dataToSign = buildSignableData(
            timestamp: timestamp,
            peerTag: peerTag,
            localTag: localTag,
            peerInitialTSN: peerInitialTSN,
            peerARWC: peerARWC,
            outboundStreams: outboundStreams,
            inboundStreams: inboundStreams
        )

        let hmac = computeHMAC(data: dataToSign, key: secretKey)

        return SCTPCookie(
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

    /// Validate a cookie received in COOKIE-ECHO
    /// - Parameters:
    ///   - secretKey: Server's secret key for HMAC
    ///   - maxAge: Maximum cookie age (default: 60 seconds)
    /// - Returns: True if cookie is valid and not expired
    public func validate(secretKey: Data, maxAge: TimeInterval = defaultMaxAge) -> Bool {
        // Check expiration
        let now = UInt64(Date().timeIntervalSinceReferenceDate * 1000)
        let age = Double(now - timestamp) / 1000.0
        guard age >= 0 && age <= maxAge else {
            return false
        }

        // Verify HMAC
        let dataToSign = Self.buildSignableData(
            timestamp: timestamp,
            peerTag: peerTag,
            localTag: localTag,
            peerInitialTSN: peerInitialTSN,
            peerARWC: peerARWC,
            outboundStreams: outboundStreams,
            inboundStreams: inboundStreams
        )

        let expectedHMAC = Self.computeHMAC(data: dataToSign, key: secretKey)
        return hmac == expectedHMAC
    }

    /// Encode the cookie to wire format
    public func encode() -> Data {
        var data = Data(capacity: Self.encodedSize)

        // Timestamp (8 bytes, big-endian)
        appendUInt64(&data, timestamp)

        // Peer tag (4 bytes)
        appendUInt32(&data, peerTag)

        // Local tag (4 bytes)
        appendUInt32(&data, localTag)

        // Peer initial TSN (4 bytes)
        appendUInt32(&data, peerInitialTSN)

        // Peer ARWC (4 bytes)
        appendUInt32(&data, peerARWC)

        // Streams (2 + 2 bytes)
        appendUInt16(&data, outboundStreams)
        appendUInt16(&data, inboundStreams)

        // HMAC (32 bytes)
        data.append(hmac)

        return data
    }

    /// Decode a cookie from wire format
    /// - Parameter data: The encoded cookie data
    /// - Returns: Decoded cookie
    /// - Throws: SCTPError if data is malformed
    public static func decode(from data: Data) throws -> SCTPCookie {
        guard data.count >= encodedSize else {
            throw SCTPError.insufficientData(expected: encodedSize, actual: data.count)
        }

        var offset = 0

        let timestamp = readUInt64(data, offset: offset)
        offset += 8

        let peerTag = readUInt32(data, offset: offset)
        offset += 4

        let localTag = readUInt32(data, offset: offset)
        offset += 4

        let peerInitialTSN = readUInt32(data, offset: offset)
        offset += 4

        let peerARWC = readUInt32(data, offset: offset)
        offset += 4

        let outboundStreams = readUInt16(data, offset: offset)
        offset += 2

        let inboundStreams = readUInt16(data, offset: offset)
        offset += 2

        let hmac = Data(data[offset..<offset + 32])

        return SCTPCookie(
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

    // MARK: - Private helpers

    private static func buildSignableData(
        timestamp: UInt64,
        peerTag: UInt32,
        localTag: UInt32,
        peerInitialTSN: UInt32,
        peerARWC: UInt32,
        outboundStreams: UInt16,
        inboundStreams: UInt16
    ) -> Data {
        var data = Data(capacity: 28)
        appendUInt64(&data, timestamp)
        appendUInt32(&data, peerTag)
        appendUInt32(&data, localTag)
        appendUInt32(&data, peerInitialTSN)
        appendUInt32(&data, peerARWC)
        appendUInt16(&data, outboundStreams)
        appendUInt16(&data, inboundStreams)
        return data
    }

    private static func computeHMAC(data: Data, key: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey)
        return Data(mac)
    }
}

// MARK: - Encoding helpers

private func appendUInt16(_ data: inout Data, _ value: UInt16) {
    data.append(UInt8(value >> 8))
    data.append(UInt8(value & 0xFF))
}

private func appendUInt32(_ data: inout Data, _ value: UInt32) {
    data.append(UInt8(value >> 24))
    data.append(UInt8((value >> 16) & 0xFF))
    data.append(UInt8((value >> 8) & 0xFF))
    data.append(UInt8(value & 0xFF))
}

private func appendUInt64(_ data: inout Data, _ value: UInt64) {
    data.append(UInt8(value >> 56))
    data.append(UInt8((value >> 48) & 0xFF))
    data.append(UInt8((value >> 40) & 0xFF))
    data.append(UInt8((value >> 32) & 0xFF))
    data.append(UInt8((value >> 24) & 0xFF))
    data.append(UInt8((value >> 16) & 0xFF))
    data.append(UInt8((value >> 8) & 0xFF))
    data.append(UInt8(value & 0xFF))
}

private func readUInt64(_ data: Data, offset: Int) -> UInt64 {
    let base = data.startIndex + offset
    return UInt64(data[base]) << 56 |
           UInt64(data[base + 1]) << 48 |
           UInt64(data[base + 2]) << 40 |
           UInt64(data[base + 3]) << 32 |
           UInt64(data[base + 4]) << 24 |
           UInt64(data[base + 5]) << 16 |
           UInt64(data[base + 6]) << 8 |
           UInt64(data[base + 7])
}
