/// One ICE candidate encoded by SDP and trickle ICE.
public struct WebRTCICECandidate: Sendable, Equatable, Hashable {
    public enum Transport: String, Sendable, Equatable, Hashable {
        case udp
        case tcp
    }

    public enum CandidateType: String, Sendable, Equatable, Hashable {
        case host
        case serverReflexive = "srflx"
        case peerReflexive = "prflx"
        case relay
    }

    public enum TCPType: String, Sendable, Equatable, Hashable {
        case active
        case passive
        case simultaneousOpen = "so"
    }

    public static let maximumSDPByteCount = 4 * 1_024

    public let foundation: String
    public let component: UInt16
    public let transport: Transport
    public let priority: UInt32
    public let address: String
    public let port: UInt16
    public let type: CandidateType
    public let relatedAddress: String?
    public let relatedPort: UInt16?
    public let tcpType: TCPType?

    public init(
        foundation: String,
        component: UInt16 = 1,
        transport: Transport = .udp,
        priority: UInt32,
        address: String,
        port: UInt16,
        type: CandidateType,
        relatedAddress: String? = nil,
        relatedPort: UInt16? = nil,
        tcpType: TCPType? = nil
    ) throws(WebRTCSessionDescriptionError) {
        guard !foundation.isEmpty,
              foundation.utf8.count <= 32,
              !foundation.contains(where: { $0.isWhitespace }),
              foundation.utf8.allSatisfy({ (0x21...0x7E).contains($0) }),
              component > 0,
              !address.isEmpty,
              address.utf8.count <= 255,
              !address.contains(where: { $0.isWhitespace }),
              address.utf8.allSatisfy({ (0x21...0x7E).contains($0) }),
              port > 0 else {
            throw .invalidCandidate("Candidate fields are outside their wire bounds")
        }
        if transport == .tcp, tcpType == nil {
            throw .invalidCandidate("TCP candidates require tcptype")
        }
        if relatedAddress == nil, relatedPort != nil {
            throw .invalidCandidate("Related port requires a related address")
        }
        if let relatedAddress,
           relatedAddress.isEmpty
            || relatedAddress.utf8.count > 255
            || relatedAddress.contains(where: { $0.isWhitespace })
            || !relatedAddress.utf8.allSatisfy({ (0x21...0x7E).contains($0) }) {
            throw .invalidCandidate("Related address is outside its wire bounds")
        }
        if relatedAddress != nil, relatedPort == nil {
            throw .invalidCandidate("Related address requires a related port")
        }
        if transport == .udp, tcpType != nil {
            throw .invalidCandidate("UDP candidates cannot carry tcptype")
        }
        self.foundation = foundation
        self.component = component
        self.transport = transport
        self.priority = priority
        self.address = address
        self.port = port
        self.type = type
        self.relatedAddress = relatedAddress
        self.relatedPort = relatedPort
        self.tcpType = tcpType
    }

    /// The candidate attribute without the SDP `a=` prefix.
    public var sdpAttribute: String {
        var fields = [
            "candidate:\(foundation)",
            String(component),
            transport == .udp ? "UDP" : "TCP",
            String(priority),
            address,
            String(port),
            "typ",
            type.rawValue,
        ]
        if let relatedAddress {
            fields.append("raddr")
            fields.append(relatedAddress)
        }
        if let relatedPort {
            fields.append("rport")
            fields.append(String(relatedPort))
        }
        if let tcpType {
            fields.append("tcptype")
            fields.append(tcpType.rawValue)
        }
        return fields.joined(separator: " ")
    }

    public static func parse(
        _ attribute: String
    ) throws(WebRTCSessionDescriptionError) -> WebRTCICECandidate {
        guard attribute.utf8.count <= maximumSDPByteCount else {
            throw .inputTooLarge(
                size: attribute.utf8.count,
                maximum: maximumSDPByteCount
            )
        }
        let raw = attribute.hasPrefix("a=")
            ? String(attribute.dropFirst(2))
            : attribute
        let fields = raw.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard fields.count >= 8,
              fields[0].hasPrefix("candidate:"),
              fields[6].lowercased() == "typ" else {
            throw .invalidCandidate(attribute)
        }

        let foundation = String(fields[0].dropFirst("candidate:".count))
        guard let component = UInt16(fields[1]) else {
            throw .invalidCandidate(attribute)
        }
        guard let transport = Transport(rawValue: fields[2].lowercased()) else {
            throw .invalidCandidate(attribute)
        }
        guard let priority = UInt32(fields[3]) else {
            throw .invalidPriority(String(fields[3]))
        }
        let address = String(fields[4])
        guard let port = UInt16(fields[5]), port > 0 else {
            throw .invalidPort(String(fields[5]))
        }
        guard let type = CandidateType(rawValue: fields[7].lowercased()) else {
            throw .invalidCandidate(attribute)
        }

        var relatedAddress: String?
        var relatedPort: UInt16?
        var tcpType: TCPType?
        var index = 8
        while index < fields.count {
            let name = fields[index].lowercased()
            guard index + 1 < fields.count else {
                throw .invalidCandidate(attribute)
            }
            let value = fields[index + 1]
            switch name {
            case "raddr":
                relatedAddress = String(value)
            case "rport":
                guard let parsed = UInt16(value), parsed > 0 else {
                    throw .invalidPort(String(value))
                }
                relatedPort = parsed
            case "tcptype":
                guard let parsed = TCPType(rawValue: value.lowercased()) else {
                    throw .invalidCandidate(attribute)
                }
                tcpType = parsed
            default:
                // WebRTC implementations add extension pairs such as
                // generation and network-cost. They do not change the route.
                break
            }
            index += 2
        }

        return try WebRTCICECandidate(
            foundation: foundation,
            component: component,
            transport: transport,
            priority: priority,
            address: address,
            port: port,
            type: type,
            relatedAddress: relatedAddress,
            relatedPort: relatedPort,
            tcpType: tcpType
        )
    }
}
