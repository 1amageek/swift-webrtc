/// Browser-compatible JSON signaling for one trickled ICE candidate.
public struct WebRTCTrickleICECandidate: Sendable, Equatable {
    public static let maximumJSONByteCount = 8 * 1_024

    public let candidate: WebRTCICECandidate
    public let mediaStreamIdentification: String?
    public let mediaLineIndex: UInt16?
    public let usernameFragment: String?

    public init(
        candidate: WebRTCICECandidate,
        mediaStreamIdentification: String? = "0",
        mediaLineIndex: UInt16? = 0,
        usernameFragment: String? = nil
    ) throws(WebRTCSessionDescriptionError) {
        if let mediaStreamIdentification {
            guard !mediaStreamIdentification.isEmpty,
                  mediaStreamIdentification.utf8.count <= 32,
                  !mediaStreamIdentification.contains(where: { $0.isWhitespace }),
                  mediaStreamIdentification.utf8.allSatisfy({
                      (0x21...0x7E).contains($0)
                  }) else {
                throw .invalidMediaStreamIdentification(
                    mediaStreamIdentification
                )
            }
        }
        if let mediaLineIndex, mediaLineIndex != 0 {
            throw .invalidMediaLineIndex(UInt64(mediaLineIndex))
        }
        if let usernameFragment {
            guard usernameFragment.utf8.count >= 4,
                  usernameFragment.utf8.count <= 256,
                  !usernameFragment.contains(where: { $0.isWhitespace }),
                  usernameFragment.utf8.allSatisfy({
                      (0x21...0x7E).contains($0)
                  }) else {
                throw .invalidUsernameFragment(usernameFragment)
            }
        }
        self.candidate = candidate
        self.mediaStreamIdentification = mediaStreamIdentification
        self.mediaLineIndex = mediaLineIndex
        self.usernameFragment = usernameFragment
    }

    /// Serializes the `RTCIceCandidate.toJSON()` field contract.
    public var jsonString: String {
        var output = "{\"candidate\":"
        Self.appendJSONString(candidate.sdpAttribute, to: &output)
        output += ",\"sdpMid\":"
        Self.appendJSONStringOrNull(mediaStreamIdentification, to: &output)
        output += ",\"sdpMLineIndex\":"
        if let mediaLineIndex {
            output += String(mediaLineIndex)
        } else {
            output += "null"
        }
        output += ",\"usernameFragment\":"
        Self.appendJSONStringOrNull(usernameFragment, to: &output)
        output += "}"
        return output
    }

    public static func parse(
        _ json: String
    ) throws(WebRTCSessionDescriptionError) -> WebRTCTrickleICECandidate {
        guard json.utf8.count <= maximumJSONByteCount else {
            throw .inputTooLarge(
                size: json.utf8.count,
                maximum: maximumJSONByteCount
            )
        }
        var cursor = JSONCursor(bytes: Array(json.utf8))
        let fields = try cursor.parseCandidateObject()
        guard let candidateValue = fields.candidate,
              !candidateValue.isEmpty else {
            throw .missingCandidate
        }
        let parsedCandidate = try WebRTCICECandidate.parse(candidateValue)
        if let lineIndex = fields.mediaLineIndex,
           lineIndex > UInt64(UInt16.max) {
            throw .invalidMediaLineIndex(lineIndex)
        }
        return try WebRTCTrickleICECandidate(
            candidate: parsedCandidate,
            mediaStreamIdentification: fields.mediaStreamIdentification,
            mediaLineIndex: fields.mediaLineIndex.map(UInt16.init),
            usernameFragment: fields.usernameFragment
        )
    }

    private static func appendJSONStringOrNull(
        _ value: String?,
        to output: inout String
    ) {
        if let value {
            appendJSONString(value, to: &output)
        } else {
            output += "null"
        }
    }

    private static func appendJSONString(
        _ value: String,
        to output: inout String
    ) {
        output.append("\"")
        for byte in value.utf8 {
            switch byte {
            case 0x22:
                output += "\\\""
            case 0x5C:
                output += "\\\\"
            case 0x08:
                output += "\\b"
            case 0x0C:
                output += "\\f"
            case 0x0A:
                output += "\\n"
            case 0x0D:
                output += "\\r"
            case 0x09:
                output += "\\t"
            case 0x00...0x1F:
                let high = Self.hexDigit(byte >> 4)
                let low = Self.hexDigit(byte & 0x0F)
                output += "\\u00\(high)\(low)"
            default:
                precondition(byte < 0x80)
                output.append(Character(Unicode.Scalar(byte)))
            }
        }
        output.append("\"")
    }

    private static func hexDigit(_ value: UInt8) -> Character {
        Character(Unicode.Scalar(value < 10 ? 0x30 + value : 0x41 + value - 10))
    }
}

private struct CandidateJSONFields {
    var candidate: String?
    var mediaStreamIdentification: String?
    var mediaLineIndex: UInt64?
    var usernameFragment: String?
}

private struct JSONCursor {
    let bytes: [UInt8]
    var index = 0

    mutating func parseCandidateObject(
    ) throws(WebRTCSessionDescriptionError) -> CandidateJSONFields {
        skipWhitespace()
        try consume(0x7B)
        var fields = CandidateJSONFields()
        var seen = Set<String>()
        skipWhitespace()
        if consumeIfPresent(0x7D) {
            throw .missingCandidate
        }

        while true {
            skipWhitespace()
            let key = try parseString()
            guard seen.insert(key).inserted else {
                throw .invalidJSON("Duplicate field: \(key)")
            }
            skipWhitespace()
            try consume(0x3A)
            skipWhitespace()

            switch key {
            case "candidate":
                fields.candidate = try parseNullableString()
            case "sdpMid":
                fields.mediaStreamIdentification = try parseNullableString()
            case "sdpMLineIndex":
                fields.mediaLineIndex = try parseNullableUnsignedInteger()
            case "usernameFragment":
                fields.usernameFragment = try parseNullableString()
            default:
                try skipValue(depth: 0)
            }

            skipWhitespace()
            if consumeIfPresent(0x7D) { break }
            try consume(0x2C)
        }
        skipWhitespace()
        guard index == bytes.count else {
            throw .invalidJSON("Trailing data")
        }
        return fields
    }

    mutating func parseNullableString(
    ) throws(WebRTCSessionDescriptionError) -> String? {
        if consumeLiteral("null") { return nil }
        return try parseString()
    }

    mutating func parseNullableUnsignedInteger(
    ) throws(WebRTCSessionDescriptionError) -> UInt64? {
        if consumeLiteral("null") { return nil }
        let start = index
        while index < bytes.count, (0x30...0x39).contains(bytes[index]) {
            index += 1
        }
        guard index > start else {
            throw .invalidJSON("Expected unsigned integer")
        }
        var value: UInt64 = 0
        for byte in bytes[start..<index] {
            let digit = UInt64(byte - 0x30)
            let (multiplied, multiplicationOverflow) = value
                .multipliedReportingOverflow(by: 10)
            let (added, additionOverflow) = multiplied
                .addingReportingOverflow(digit)
            guard !multiplicationOverflow, !additionOverflow else {
                throw .invalidJSON("Integer overflow")
            }
            value = added
        }
        return value
    }

    mutating func parseString(
    ) throws(WebRTCSessionDescriptionError) -> String {
        try consume(0x22)
        var output: [UInt8] = []
        output.reserveCapacity(64)
        while index < bytes.count {
            let byte = bytes[index]
            index += 1
            switch byte {
            case 0x22:
                guard let value = String(validating: output, as: UTF8.self) else {
                    throw .invalidJSON("Invalid UTF-8 string")
                }
                return value
            case 0x5C:
                try appendEscape(to: &output)
            case 0x00...0x1F:
                throw .invalidJSON("Unescaped control character")
            default:
                output.append(byte)
            }
        }
        throw .invalidJSON("Unterminated string")
    }

    mutating func appendEscape(
        to output: inout [UInt8]
    ) throws(WebRTCSessionDescriptionError) {
        guard index < bytes.count else {
            throw .invalidJSON("Truncated escape")
        }
        let escape = bytes[index]
        index += 1
        switch escape {
        case 0x22, 0x5C, 0x2F:
            output.append(escape)
        case 0x62:
            output.append(0x08)
        case 0x66:
            output.append(0x0C)
        case 0x6E:
            output.append(0x0A)
        case 0x72:
            output.append(0x0D)
        case 0x74:
            output.append(0x09)
        case 0x75:
            let first = try parseUnicodeEscape()
            let scalarValue: UInt32
            if (0xD800...0xDBFF).contains(first) {
                guard index + 2 <= bytes.count,
                      bytes[index] == 0x5C,
                      bytes[index + 1] == 0x75 else {
                    throw .invalidJSON("Missing low surrogate")
                }
                index += 2
                let second = try parseUnicodeEscape()
                guard (0xDC00...0xDFFF).contains(second) else {
                    throw .invalidJSON("Invalid low surrogate")
                }
                scalarValue = 0x10000
                    + ((first - 0xD800) << 10)
                    + (second - 0xDC00)
            } else {
                guard !(0xDC00...0xDFFF).contains(first) else {
                    throw .invalidJSON("Unexpected low surrogate")
                }
                scalarValue = first
            }
            guard let scalar = Unicode.Scalar(scalarValue) else {
                throw .invalidJSON("Invalid Unicode scalar")
            }
            output.append(contentsOf: String(scalar).utf8)
        default:
            throw .invalidJSON("Invalid escape")
        }
    }

    mutating func parseUnicodeEscape(
    ) throws(WebRTCSessionDescriptionError) -> UInt32 {
        guard 4 <= bytes.count - index else {
            throw .invalidJSON("Truncated Unicode escape")
        }
        var value: UInt32 = 0
        for _ in 0..<4 {
            let byte = bytes[index]
            index += 1
            let digit: UInt32
            switch byte {
            case 0x30...0x39:
                digit = UInt32(byte - 0x30)
            case 0x41...0x46:
                digit = UInt32(byte - 0x41 + 10)
            case 0x61...0x66:
                digit = UInt32(byte - 0x61 + 10)
            default:
                throw .invalidJSON("Invalid Unicode escape")
            }
            value = (value << 4) | digit
        }
        return value
    }

    mutating func skipValue(
        depth: Int
    ) throws(WebRTCSessionDescriptionError) {
        guard depth <= 8, index < bytes.count else {
            throw .invalidJSON("Value nesting limit exceeded")
        }
        switch bytes[index] {
        case 0x22:
            _ = try parseString()
        case 0x7B:
            index += 1
            skipWhitespace()
            if consumeIfPresent(0x7D) { return }
            while true {
                _ = try parseString()
                skipWhitespace()
                try consume(0x3A)
                skipWhitespace()
                try skipValue(depth: depth + 1)
                skipWhitespace()
                if consumeIfPresent(0x7D) { return }
                try consume(0x2C)
                skipWhitespace()
            }
        case 0x5B:
            index += 1
            skipWhitespace()
            if consumeIfPresent(0x5D) { return }
            while true {
                try skipValue(depth: depth + 1)
                skipWhitespace()
                if consumeIfPresent(0x5D) { return }
                try consume(0x2C)
                skipWhitespace()
            }
        default:
            let start = index
            while index < bytes.count,
                  bytes[index] != 0x2C,
                  bytes[index] != 0x7D,
                  bytes[index] != 0x5D,
                  !Self.isWhitespace(bytes[index]) {
                index += 1
            }
            guard index > start else {
                throw .invalidJSON("Invalid value")
            }
        }
    }

    mutating func skipWhitespace() {
        while index < bytes.count, Self.isWhitespace(bytes[index]) {
            index += 1
        }
    }

    mutating func consume(
        _ expected: UInt8
    ) throws(WebRTCSessionDescriptionError) {
        guard consumeIfPresent(expected) else {
            throw .invalidJSON("Expected byte \(expected)")
        }
    }

    mutating func consumeIfPresent(_ expected: UInt8) -> Bool {
        guard index < bytes.count, bytes[index] == expected else {
            return false
        }
        index += 1
        return true
    }

    mutating func consumeLiteral(_ value: StaticString) -> Bool {
        let literal = value.withUTF8Buffer { Array($0) }
        guard literal.count <= bytes.count - index,
              bytes[index..<(index + literal.count)].elementsEqual(literal) else {
            return false
        }
        index += literal.count
        return true
    }

    static func isWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }
}
