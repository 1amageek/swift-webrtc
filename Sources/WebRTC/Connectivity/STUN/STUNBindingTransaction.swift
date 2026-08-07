/// One RFC 5389 Binding transaction used to discover a server-reflexive UDP
/// address. The owner creates the request once and must reuse `requestBytes`
/// for every retransmission.
public struct STUNBindingTransaction: Sendable, Equatable {
    public let requestBytes: [UInt8]

    private let transactionID: TransactionID

    public init() {
        self.init(transactionID: SecureRandom.bytes(count: 12))
    }

    init(transactionID bytes: [UInt8]) {
        precondition(bytes.count == 12)
        let transactionID = TransactionID(byteValues: bytes)
        self.transactionID = transactionID
        self.requestBytes = STUNMessage(
            messageType: .bindingRequest,
            transactionID: transactionID
        ).encodeBytes()
    }

    public func parseResponse(
        _ bytes: [UInt8]
    ) throws(STUNBindingTransactionError) -> STUNMappedAddress {
        guard STUNMessage.isSTUN(bytes) else { throw .notSTUN }
        guard bytes.count >= stunHeaderSize else { throw .malformed }
        let declaredLength = Int(UInt16(bytes[2]) << 8 | UInt16(bytes[3]))
        guard bytes.count == stunHeaderSize + declaredLength else {
            throw .malformed
        }

        let response: STUNMessage
        do {
            response = try STUNMessage.decode(from: bytes)
        } catch {
            throw .malformed
        }
        guard response.transactionID == transactionID else {
            throw .transactionMismatch
        }
        if response.messageType == .bindingErrorResponse {
            throw .errorResponse
        }
        guard response.messageType == .bindingSuccessResponse else {
            throw .unexpectedMessageType(response.messageType.rawValue)
        }
        if response.attribute(ofType: .fingerprint) != nil,
           !STUNFingerprint.verify(message: bytes) {
            throw .invalidFingerprint
        }
        guard let attribute = response.attribute(ofType: .xorMappedAddress),
              let mapped = attribute.parseXorMappedAddress(
                  transactionID: transactionID
              ) else {
            throw .missingMappedAddress
        }
        return try STUNMappedAddress(
            addressBytes: mapped.address,
            port: mapped.port
        )
    }
}

public struct STUNMappedAddress: Sendable, Equatable, Hashable {
    public let addressBytes: [UInt8]
    public let port: UInt16

    public init(
        addressBytes: [UInt8],
        port: UInt16
    ) throws(STUNBindingTransactionError) {
        guard addressBytes.count == 4 || addressBytes.count == 16 else {
            throw .invalidAddressLength(addressBytes.count)
        }
        guard port > 0 else { throw .invalidPort }
        self.addressBytes = addressBytes
        self.port = port
    }
}

public enum STUNBindingTransactionError: Error, Sendable, Equatable {
    case notSTUN
    case malformed
    case transactionMismatch
    case unexpectedMessageType(UInt16)
    case errorResponse
    case invalidFingerprint
    case missingMappedAddress
    case invalidAddressLength(Int)
    case invalidPort
}
