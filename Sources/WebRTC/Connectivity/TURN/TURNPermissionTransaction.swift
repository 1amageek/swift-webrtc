public struct TURNPermissionTransaction: Sendable, Equatable {
    private let transactionID: TransactionID
    private let authentication: TURNAuthenticationContext
    public let requestBytes: [UInt8]

    init(
        peerAddresses: [TURNAddress],
        authentication: TURNAuthenticationContext
    ) throws(TURNError) {
        guard !peerAddresses.isEmpty else { throw .missingPeerAddress }
        let transactionID = TransactionID(
            byteValues: SecureRandom.bytes(count: 12)
        )

        var uniqueAddresses: [TURNAddress] = []
        var seenAddressBytes = Set<[UInt8]>()
        for address in peerAddresses {
            if seenAddressBytes.insert(address.addressBytes).inserted {
                uniqueAddresses.append(address)
            }
        }
        var attributes = uniqueAddresses.map {
            $0.xorAttribute(
                type: .xorPeerAddress,
                transactionID: transactionID
            )
        }
        attributes.append(contentsOf: authentication.requestAttributes)
        let request = STUNMessage(
            messageType: STUNMessageType(
                method: .createPermission,
                class: .request
            ),
            transactionID: transactionID,
            attributes: attributes
        )

        self.transactionID = transactionID
        self.authentication = authentication
        self.requestBytes = request.encodeWithIntegrityBytes(
            key: authentication.integrityKey
        )
    }

    public func validateResponse(
        _ responseBytes: [UInt8]
    ) throws(TURNError) {
        let response = try TURNWireValidation.decodeExact(
            responseBytes,
            transactionID: transactionID
        )
        let successType = STUNMessageType(
            method: .createPermission,
            class: .successResponse
        )
        if response.messageType == successType {
            try TURNWireValidation.requireIntegrity(
                in: responseBytes,
                context: authentication
            )
            return
        }
        let errorType = STUNMessageType(
            method: .createPermission,
            class: .errorResponse
        )
        guard response.messageType == errorType else {
            throw .unexpectedMessageType(response.messageType.rawValue)
        }
        let serverError = try TURNWireValidation.error(in: response)
        if serverError.code == STUNErrorCode.staleNonce.rawValue {
            throw .staleNonce
        }
        if serverError.code == STUNErrorCode.unauthorized.rawValue {
            throw .authenticationFailed
        }
        throw .serverError(code: serverError.code, reason: serverError.reason)
    }
}
