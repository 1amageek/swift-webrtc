public enum TURNAllocationProgress: Sendable, Equatable {
    case sendAuthenticatedRequest([UInt8])
    case allocated(TURNAllocation)
}

public struct TURNAllocationTransaction: Sendable {
    private enum State: Sendable {
        case awaitingChallenge(TransactionID)
        case awaitingAllocation(TransactionID, TURNAuthenticationContext)
        case complete
    }

    private let credentials: TURNCredentials
    private var state: State
    public private(set) var requestBytes: [UInt8]

    public init(credentials: TURNCredentials) {
        let transactionID = TransactionID(
            byteValues: SecureRandom.bytes(count: 12)
        )
        self.credentials = credentials
        self.state = .awaitingChallenge(transactionID)
        self.requestBytes = Self.makeRequest(
            transactionID: transactionID,
            authentication: nil
        )
    }

    public mutating func receive(
        _ responseBytes: [UInt8]
    ) throws(TURNError) -> TURNAllocationProgress {
        switch state {
        case .awaitingChallenge(let transactionID):
            let response = try TURNWireValidation.decodeExact(
                responseBytes,
                transactionID: transactionID
            )
            guard response.messageType == STUNMessageType(
                method: .allocate,
                class: .errorResponse
            ) else {
                throw .unexpectedMessageType(response.messageType.rawValue)
            }
            let serverError = try TURNWireValidation.error(in: response)
            guard serverError.code == STUNErrorCode.unauthorized.rawValue else {
                throw .serverError(
                    code: serverError.code,
                    reason: serverError.reason
                )
            }
            return try authenticate(using: response)

        case .awaitingAllocation(let transactionID, let authentication):
            let response = try TURNWireValidation.decodeExact(
                responseBytes,
                transactionID: transactionID
            )
            let successType = STUNMessageType(
                method: .allocate,
                class: .successResponse
            )
            if response.messageType == successType {
                try TURNWireValidation.requireIntegrity(
                    in: responseBytes,
                    context: authentication
                )
                guard let relayedAttribute = try TURNWireValidation.singleAttribute(
                    .xorRelayedAddress,
                    in: response
                ) else {
                    throw .missingRelayedAddress
                }
                let relayedAddress = try TURNAddress.parse(
                    relayedAttribute,
                    expectedType: .xorRelayedAddress,
                    transactionID: transactionID
                )
                let mappedAddress: TURNAddress?
                if let mappedAttribute = try TURNWireValidation.singleAttribute(
                    .xorMappedAddress,
                    in: response
                ) {
                    mappedAddress = try TURNAddress.parse(
                        mappedAttribute,
                        expectedType: .xorMappedAddress,
                        transactionID: transactionID
                    )
                } else {
                    mappedAddress = nil
                }
                guard let lifetime = try TURNWireValidation.uint32(
                    .lifetime,
                    in: response
                ), lifetime > 0 else {
                    throw .missingLifetime
                }
                let allocation = TURNAllocation(
                    relayedAddress: relayedAddress,
                    mappedAddress: mappedAddress,
                    lifetimeSeconds: lifetime,
                    authentication: authentication
                )
                state = .complete
                return .allocated(allocation)
            }

            let errorType = STUNMessageType(
                method: .allocate,
                class: .errorResponse
            )
            guard response.messageType == errorType else {
                throw .unexpectedMessageType(response.messageType.rawValue)
            }
            let serverError = try TURNWireValidation.error(in: response)
            if serverError.code == STUNErrorCode.staleNonce.rawValue {
                return try authenticate(using: response)
            }
            if serverError.code == STUNErrorCode.unauthorized.rawValue {
                throw .authenticationFailed
            }
            throw .serverError(
                code: serverError.code,
                reason: serverError.reason
            )

        case .complete:
            throw .unexpectedMessageType(0)
        }
    }

    private mutating func authenticate(
        using response: STUNMessage
    ) throws(TURNError) -> TURNAllocationProgress {
        let challenge = try TURNWireValidation.challenge(in: response)
        let authentication = try TURNAuthenticationContext(
            credentials: credentials,
            realm: challenge.realm,
            nonce: challenge.nonce
        )
        let transactionID = TransactionID(
            byteValues: SecureRandom.bytes(count: 12)
        )
        let authenticatedRequest = Self.makeRequest(
            transactionID: transactionID,
            authentication: authentication
        )
        requestBytes = authenticatedRequest
        state = .awaitingAllocation(transactionID, authentication)
        return .sendAuthenticatedRequest(authenticatedRequest)
    }

    private static func makeRequest(
        transactionID: TransactionID,
        authentication: TURNAuthenticationContext?
    ) -> [UInt8] {
        var attributes = [
            STUNAttribute(
                type: STUNAttributeType.requestedTransport.rawValue,
                value: [17, 0, 0, 0]
            ),
        ]
        if let authentication {
            attributes.append(contentsOf: authentication.requestAttributes)
        }
        let request = STUNMessage(
            messageType: STUNMessageType(
                method: .allocate,
                class: .request
            ),
            transactionID: transactionID,
            attributes: attributes
        )
        return authentication.map {
            request.encodeWithIntegrityBytes(key: $0.integrityKey)
        } ?? request.encodeBytes()
    }
}
