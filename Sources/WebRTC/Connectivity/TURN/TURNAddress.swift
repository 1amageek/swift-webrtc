public struct TURNAddress: Sendable, Equatable, Hashable {
    public let addressBytes: [UInt8]
    public let port: UInt16

    public init(
        addressBytes: [UInt8],
        port: UInt16
    ) throws(TURNError) {
        guard addressBytes.count == 4 || addressBytes.count == 16 else {
            throw .invalidAddressLength(addressBytes.count)
        }
        guard port > 0 else { throw .invalidPort }
        self.addressBytes = addressBytes
        self.port = port
    }

    func xorAttribute(
        type: STUNAttributeType,
        transactionID: TransactionID
    ) -> STUNAttribute {
        let mapped = STUNAttribute.xorMappedAddress(
            address: addressBytes,
            port: port,
            transactionID: transactionID
        )
        return STUNAttribute(type: type.rawValue, value: mapped.value)
    }

    static func parse(
        _ attribute: STUNAttribute,
        expectedType: STUNAttributeType,
        transactionID: TransactionID
    ) throws(TURNError) -> TURNAddress {
        guard attribute.type == expectedType.rawValue else {
            throw .malformedMessage
        }
        let mappedAttribute = STUNAttribute(
            type: STUNAttributeType.xorMappedAddress.rawValue,
            value: attribute.value
        )
        guard let mapped = mappedAttribute.parseXorMappedAddress(
            transactionID: transactionID
        ) else {
            throw .malformedMessage
        }
        return try TURNAddress(
            addressBytes: mapped.address,
            port: mapped.port
        )
    }
}
