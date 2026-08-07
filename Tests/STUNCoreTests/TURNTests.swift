import Testing
@testable import WebRTC

@Suite("TURN wire core")
struct TURNTests {
    @Test("RFC 1321 MD5 vectors used by long-term authentication")
    func md5Vectors() {
        #expect(hex(TURNMD5.hash([])) == "d41d8cd98f00b204e9800998ecf8427e")
        #expect(hex(TURNMD5.hash(Array("abc".utf8))) == "900150983cd24fb0d6963f7d28e17f72")
        #expect(
            hex(TURNMD5.hash(Array("message digest".utf8)))
                == "f96b697d7cb7938d525a2f31aaf161d0"
        )
    }

    @Test("Allocation challenge authenticates and returns relay state")
    func allocationChallenge() throws {
        let credentials = try TURNCredentials(
            username: "turn-user",
            password: "turn-password"
        )
        var transaction = TURNAllocationTransaction(credentials: credentials)
        let initial = try STUNMessage.decode(from: transaction.requestBytes)
        #expect(
            initial.messageType
                == STUNMessageType(method: .allocate, class: .request)
        )
        #expect(initial.attribute(ofType: .requestedTransport)?.value == [17, 0, 0, 0])

        let realm = "swift-webrtc.test"
        let nonce = "nonce-value"
        let challenge = STUNMessage(
            messageType: STUNMessageType(
                method: .allocate,
                class: .errorResponse
            ),
            transactionID: initial.transactionID,
            attributes: [
                .errorCode(401, reason: "Unauthorized"),
                STUNAttribute(type: STUNAttributeType.realm.rawValue, value: Array(realm.utf8)),
                STUNAttribute(type: STUNAttributeType.nonce.rawValue, value: Array(nonce.utf8)),
            ]
        ).encodeBytes()

        let authenticatedBytes: [UInt8]
        switch try transaction.receive(challenge) {
        case .sendAuthenticatedRequest(let bytes):
            authenticatedBytes = bytes
        case .allocated:
            Issue.record("The unauthenticated request must be challenged")
            return
        }
        let authenticated = try STUNMessage.decode(from: authenticatedBytes)
        let context = try TURNAuthenticationContext(
            credentials: credentials,
            realm: realm,
            nonce: nonce
        )
        #expect(
            MessageIntegrity.verifyWithResultBytes(
                message: authenticatedBytes,
                key: context.integrityKey
            ) == .valid
        )

        let relay = try TURNAddress(
            addressBytes: [203, 0, 113, 7],
            port: 54_321
        )
        let mapped = try TURNAddress(
            addressBytes: [198, 51, 100, 2],
            port: 40_000
        )
        let success = STUNMessage(
            messageType: STUNMessageType(
                method: .allocate,
                class: .successResponse
            ),
            transactionID: authenticated.transactionID,
            attributes: [
                relay.xorAttribute(
                    type: .xorRelayedAddress,
                    transactionID: authenticated.transactionID
                ),
                mapped.xorAttribute(
                    type: .xorMappedAddress,
                    transactionID: authenticated.transactionID
                ),
                TURNWireValidation.uint32Attribute(type: .lifetime, value: 600),
            ]
        ).encodeWithIntegrityBytes(key: context.integrityKey)

        switch try transaction.receive(success) {
        case .sendAuthenticatedRequest:
            Issue.record("The authenticated success must complete allocation")
        case .allocated(let allocation):
            #expect(allocation.relayedAddress == relay)
            #expect(allocation.mappedAddress == mapped)
            #expect(allocation.lifetimeSeconds == 600)
        }
    }

    @Test("Send and Data indications preserve peer and payload")
    func dataIndications() throws {
        let allocation = try fixtureAllocation()
        let peer = try TURNAddress(
            addressBytes: [192, 0, 2, 10],
            port: 50_000
        )
        let payload = Array(0..<97).map(UInt8.init)
        let outbound = try allocation.encapsulate(payload, to: peer)
        let encodedOutbound = outbound.encodedBytesForTesting()
        let outboundMessage = try STUNMessage.decode(from: encodedOutbound)
        #expect(
            outboundMessage.messageType
                == STUNMessageType(method: .send, class: .indication)
        )
        #expect(outboundMessage.attribute(ofType: .data)?.value == payload)

        let transactionID = TransactionID(
            byteValues: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        )
        let inbound = STUNMessage(
            messageType: STUNMessageType(method: .data, class: .indication),
            transactionID: transactionID,
            attributes: [
                peer.xorAttribute(
                    type: .xorPeerAddress,
                    transactionID: transactionID
                ),
                STUNAttribute(type: STUNAttributeType.data.rawValue, value: payload),
            ]
        ).encodeBytes()
        let decoded = try allocation.decapsulate(inbound)
        #expect(decoded.peerAddress == peer)
        #expect(decoded.payload == payload)
    }

    @Test("CreatePermission response is integrity protected")
    func permissionResponse() throws {
        let allocation = try fixtureAllocation()
        let peer = try TURNAddress(
            addressBytes: [192, 0, 2, 1],
            port: 50_001
        )
        let permission = try allocation.makePermissionTransaction(for: [peer])
        let request = try STUNMessage.decode(from: permission.requestBytes)
        let success = STUNMessage(
            messageType: STUNMessageType(
                method: .createPermission,
                class: .successResponse
            ),
            transactionID: request.transactionID
        ).encodeWithIntegrityBytes(key: allocation.authentication.integrityKey)
        try permission.validateResponse(success)

        var tampered = success
        tampered[tampered.count - 1] ^= 1
        #expect(throws: TURNError.self) {
            try permission.validateResponse(tampered)
        }
    }

    private func fixtureAllocation() throws -> TURNAllocation {
        let credentials = try TURNCredentials(username: "user", password: "pass")
        let authentication = try TURNAuthenticationContext(
            credentials: credentials,
            realm: "realm",
            nonce: "nonce"
        )
        return TURNAllocation(
            relayedAddress: try TURNAddress(
                addressBytes: [203, 0, 113, 1],
                port: 49_152
            ),
            mappedAddress: nil,
            lifetimeSeconds: 600,
            authentication: authentication
        )
    }

    private func hex(_ bytes: [UInt8]) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var result: [UInt8] = []
        result.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            result.append(digits[Int(byte >> 4)])
            result.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: result, as: UTF8.self)
    }
}
