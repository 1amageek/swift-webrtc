public struct TURNRefreshTransaction: Sendable, Equatable {
    private let transactionID: TransactionID
    private let authentication: TURNAuthenticationContext
    public let requestedLifetimeSeconds: UInt32
    public let requestBytes: [UInt8]

    init(
        lifetimeSeconds: UInt32,
        authentication: TURNAuthenticationContext
    ) {
        let transactionID = TransactionID(
            byteValues: SecureRandom.bytes(count: 12)
        )
        var attributes = [
            TURNWireValidation.uint32Attribute(
                type: .lifetime,
                value: lifetimeSeconds
            ),
        ]
        attributes.append(contentsOf: authentication.requestAttributes)
        let request = STUNMessage(
            messageType: STUNMessageType(
                method: .refresh,
                class: .request
            ),
            transactionID: transactionID,
            attributes: attributes
        )

        self.transactionID = transactionID
        self.authentication = authentication
        self.requestedLifetimeSeconds = lifetimeSeconds
        self.requestBytes = request.encodeWithIntegrityBytes(
            key: authentication.integrityKey
        )
    }

    public func parseResponse(
        _ responseBytes: [UInt8]
    ) throws(TURNError) -> UInt32 {
        let response = try TURNWireValidation.decodeExact(
            responseBytes,
            transactionID: transactionID
        )
        let successType = STUNMessageType(
            method: .refresh,
            class: .successResponse
        )
        if response.messageType == successType {
            try TURNWireValidation.requireIntegrity(
                in: responseBytes,
                context: authentication
            )
            guard let lifetime = try TURNWireValidation.uint32(
                .lifetime,
                in: response
            ) else {
                throw .missingLifetime
            }
            return lifetime
        }
        let errorType = STUNMessageType(
            method: .refresh,
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
