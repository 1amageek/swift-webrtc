import NetworkingTime
import SSLCrypto
@testable import WebRTC
import Synchronization

typealias TestSRTPContext = AESCM128HMACSHA1SRTPContext
typealias MutatingFailureSRTPContext = AESCM128HMACSHA1SRTPContext

private protocol TestAESCounterModeCipher: Sendable {
    func applyKeystream(
        to bytes: inout [UInt8],
        range: Range<Int>,
        initialCounter: Span<UInt8>
    ) throws(AESCounterModeError)
}

private final class TestAES128CounterMode: TestAESCounterModeCipher, Sendable {
    private let primitive: AES128CounterMode

    init(key: Span<UInt8>) throws(AESCounterModeError) {
        do {
            primitive = try AES128CounterMode(key: key)
        } catch {
            throw .invalidKeyLength(expected: 16, actual: key.count)
        }
    }

    func applyKeystream(
        to bytes: inout [UInt8],
        range: Range<Int>,
        initialCounter: Span<UInt8>
    ) throws(AESCounterModeError) {
        do {
            try primitive.applyKeystream(
                to: &bytes,
                range: range,
                initialCounter: initialCounter
            )
        } catch let error {
            switch error {
            case .invalidLength(let expected, let actual):
                throw .invalidCounterLength(expected: expected, actual: actual)
            case .invalidRange:
                throw .invalidRange(
                    lowerBound: range.lowerBound,
                    upperBound: range.upperBound,
                    bufferCount: bytes.count
                )
            default:
                throw .primitiveFailure
            }
        }
    }
}

/// Test-only provider that succeeds for the master-key PRF but mutates one
/// packet byte and fails on the first use of each derived session cipher.
/// This models the strongest failure permitted by `AESCounterModeCipher`.
final class MutatingFailureAESCounterMode: TestAESCounterModeCipher, Sendable {
    private let underlying: TestAES128CounterMode
    private let failurePending: Mutex<Bool>

    init(key: Span<UInt8>) throws(AESCounterModeError) {
        underlying = try TestAES128CounterMode(key: key)

        var isFixtureMasterKey = key.count == 16
        if isFixtureMasterKey {
            for index in 0..<key.count where key[index] != UInt8(index) {
                isFixtureMasterKey = false
                break
            }
        }
        failurePending = Mutex(!isFixtureMasterKey)
    }

    func applyKeystream(
        to bytes: inout [UInt8],
        range: Range<Int>,
        initialCounter: Span<UInt8>
    ) throws(AESCounterModeError) {
        let mustFail = failurePending.withLock { pending in
            guard pending else { return false }
            pending = false
            return true
        }
        guard mustFail else {
            try underlying.applyKeystream(
                to: &bytes,
                range: range,
                initialCounter: initialCounter
            )
            return
        }

        if !range.isEmpty {
            try underlying.applyKeystream(
                to: &bytes,
                range: range.lowerBound..<(range.lowerBound + 1),
                initialCounter: initialCounter
            )
        }
        throw .primitiveFailure
    }
}

enum ConcurrentProtectedPacketOutcome: Sendable, Equatable {
    case packet([UInt8])
    case failure(SRTPError)
    case unexpectedFailure
}

enum HexFixtureError: Error {
    case oddLength
    case invalidDigit(UInt8)
}

func fixtureBytes(_ hexadecimal: String) throws -> [UInt8] {
    let digits = Array(hexadecimal.utf8)
    guard digits.count.isMultiple(of: 2) else {
        throw HexFixtureError.oddLength
    }
    var result = [UInt8]()
    result.reserveCapacity(digits.count / 2)
    var offset = 0
    while offset < digits.count {
        guard let high = hexNibble(digits[offset]) else {
            throw HexFixtureError.invalidDigit(digits[offset])
        }
        guard let low = hexNibble(digits[offset + 1]) else {
            throw HexFixtureError.invalidDigit(digits[offset + 1])
        }
        result.append(high << 4 | low)
        offset += 2
    }
    return result
}

private func hexNibble(_ digit: UInt8) -> UInt8? {
    switch digit {
    case 48...57: return digit - 48
    case 65...70: return digit - 55
    case 97...102: return digit - 87
    default: return nil
    }
}

func testKeyMaterial(byteOffset: UInt8 = 0) throws -> SRTPMasterKeyMaterial {
    let key = (0..<16).map { UInt8(truncatingIfNeeded: $0) &+ byteOffset }
    let salt = (0..<14).map { UInt8(truncatingIfNeeded: 0xA0 + $0) &+ byteOffset }
    return try SRTPMasterKeyMaterial(masterKey: key, masterSalt: salt)
}

func defaultSRTPCryptoContext() -> SRTPCryptoContext {
    SRTPCryptoContext(
        hmacSHA1ByteCount: HMACSHA1.tagByteCount,
        makeAES128CounterMode: { @Sendable (
            key: [UInt8]
        ) throws(AESCounterModeError) -> SRTPAES128CounterModeContext in
            let cipher = try TestAES128CounterMode(key: key.span)
            return erasedCounterModeContext(cipher)
        },
        authenticateSHA1: defaultSHA1AuthenticationCode
    )
}

func mutatingFailureSRTPCryptoContext() -> SRTPCryptoContext {
    SRTPCryptoContext(
        hmacSHA1ByteCount: HMACSHA1.tagByteCount,
        makeAES128CounterMode: { @Sendable (
            key: [UInt8]
        ) throws(AESCounterModeError) -> SRTPAES128CounterModeContext in
            let cipher = try MutatingFailureAESCounterMode(key: key.span)
            return erasedCounterModeContext(cipher)
        },
        authenticateSHA1: defaultSHA1AuthenticationCode
    )
}

private func erasedCounterModeContext<Cipher: TestAESCounterModeCipher>(
    _ cipher: Cipher
) -> SRTPAES128CounterModeContext {
    SRTPAES128CounterModeContext(
        applyKeystream: { @Sendable (
            bytes: inout [UInt8],
            range: Range<Int>,
            initialCounter: [UInt8]
        ) throws(AESCounterModeError) in
            try cipher.applyKeystream(
                to: &bytes,
                range: range,
                initialCounter: initialCounter.span
            )
        }
    )
}

private func defaultSHA1AuthenticationCode(
    message: [UInt8],
    authenticatedRange: Range<Int>,
    suffix: [UInt8]?,
    key: [UInt8]
) -> [UInt8] {
    var output = [UInt8](repeating: 0, count: HMACSHA1.tagByteCount)
    do {
        var authenticator = try HMACSHA1.makeContext(authenticatingWith: key.span)
        try authenticator.update(message.span.extracting(authenticatedRange))
        if let suffix {
            try authenticator.update(suffix.span)
        }
        var destination = output.mutableSpan
        try authenticator.finalize(into: &destination)
    } catch {
        preconditionFailure("Test HMAC input violated the primitive contract: \(error)")
    }
    return output
}

func testHMACSHA1(message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
    var output = [UInt8](repeating: 0, count: HMACSHA1.tagByteCount)
    do {
        var destination = output.mutableSpan
        try HMACSHA1.authenticate(message, using: key, into: &destination)
    } catch {
        preconditionFailure("Test HMAC input violated the primitive contract: \(error)")
    }
    return output
}

func testContext(
    outbound: SRTPMasterKeyMaterial? = nil,
    inbound: SRTPMasterKeyMaterial? = nil
) throws -> TestSRTPContext {
    let shared = try testKeyMaterial()
    return try TestSRTPContext(
        outbound: outbound ?? shared,
        inbound: inbound ?? shared,
        crypto: defaultSRTPCryptoContext()
    )
}

func rtpPacket(
    sequenceNumber: UInt16,
    synchronizationSource: UInt32 = 0x1122_3344,
    payload: [UInt8] = [0x10, 0x20, 0x30, 0x40]
) -> [UInt8] {
    [
        0x80, 0x60,
        UInt8(truncatingIfNeeded: sequenceNumber >> 8),
        UInt8(truncatingIfNeeded: sequenceNumber),
        0x01, 0x02, 0x03, 0x04,
        UInt8(truncatingIfNeeded: synchronizationSource >> 24),
        UInt8(truncatingIfNeeded: synchronizationSource >> 16),
        UInt8(truncatingIfNeeded: synchronizationSource >> 8),
        UInt8(truncatingIfNeeded: synchronizationSource),
    ] + payload
}

func rtcpPictureLossIndication(
    synchronizationSource: UInt32 = 0x1122_3344,
    mediaSource: UInt32 = 0x5566_7788
) -> [UInt8] {
    [
        0x81, 0xCE, 0x00, 0x02,
        UInt8(truncatingIfNeeded: synchronizationSource >> 24),
        UInt8(truncatingIfNeeded: synchronizationSource >> 16),
        UInt8(truncatingIfNeeded: synchronizationSource >> 8),
        UInt8(truncatingIfNeeded: synchronizationSource),
        UInt8(truncatingIfNeeded: mediaSource >> 24),
        UInt8(truncatingIfNeeded: mediaSource >> 16),
        UInt8(truncatingIfNeeded: mediaSource >> 8),
        UInt8(truncatingIfNeeded: mediaSource),
    ]
}

func maximumEncryptedRTCPDatagram() -> [UInt8] {
    let maximumRTCPPacketByteCount = 65_536 * 4
    let synchronizationSource: UInt32 = 0x1122_3344
    var datagram = [UInt8](
        repeating: 0,
        count: 8 + TestSRTPContext.maximumEncryptedByteCount
    )

    // One 8-byte unknown RTCP packet carries the SSRC read by SRTCP, followed
    // by four maximum-size unknown packets. Reduced-size RTCP intentionally
    // preserves unknown packet types for extension compatibility.
    datagram[0] = 0x80
    datagram[1] = 210
    datagram[2] = 0
    datagram[3] = 1
    datagram[4] = UInt8(truncatingIfNeeded: synchronizationSource >> 24)
    datagram[5] = UInt8(truncatingIfNeeded: synchronizationSource >> 16)
    datagram[6] = UInt8(truncatingIfNeeded: synchronizationSource >> 8)
    datagram[7] = UInt8(truncatingIfNeeded: synchronizationSource)

    for packetIndex in 0..<4 {
        let offset = 8 + packetIndex * maximumRTCPPacketByteCount
        datagram[offset] = 0x80
        datagram[offset + 1] = 210
        datagram[offset + 2] = 0xFF
        datagram[offset + 3] = 0xFF
    }
    return datagram
}

func storageAddress(of bytes: inout [UInt8]) -> UInt {
    // The pointer borrow ends inside this synchronous closure. Its integer
    // value is compared only as storage identity and is never dereferenced.
    bytes.withUnsafeMutableBufferPointer { buffer in
        guard let baseAddress = buffer.baseAddress else { return 0 }
        return UInt(bitPattern: baseAddress)
    }
}
