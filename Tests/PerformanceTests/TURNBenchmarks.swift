import Testing
@testable import WebRTC

@Suite("TURN Benchmarks", .serialized)
struct TURNBenchmarks {
    private static let payloadByteCounts = [1, 1_200, 16_384]

    @Test(
        "Send Indication moves the payload owner without copying bytes",
        .timeLimit(.minutes(1))
    )
    func sendIndicationPayloadOwnerBudget() throws {
        let allocation = try Self.makeAllocation()
        let peerAddress = try Self.makePeerAddress()

        for byteCount in Self.payloadByteCounts {
            let payload = [UInt8](repeating: 0xA5, count: byteCount)
            let inputAddress = Self.storageAddress(payload)
            let datagram = try allocation.encapsulate(
                consume payload,
                to: peerAddress
            )
            let outputAddress = Self.storageAddress(datagram.payload)

            #expect(inputAddress != 0)
            #expect(outputAddress == inputAddress)
            #expect(datagram.payload.count == byteCount)
            #expect(
                datagram.encodedByteCount.isMultiple(of: 4)
            )
            print(
                "TURN send copy budget: payload=\(byteCount) "
                    + "ownerCopies=0 ownerAddress=\(outputAddress)"
            )
        }
    }

    @Test(
        "Data Indication compacts the admitted owner without allocating a second payload",
        .timeLimit(.minutes(1))
    )
    func dataIndicationPayloadOwnerBudget() throws {
        let allocation = try Self.makeAllocation()
        let peerAddress = try Self.makePeerAddress()

        for byteCount in Self.payloadByteCounts {
            let payload = [UInt8](repeating: 0x5A, count: byteCount)
            let datagram = Self.makeDataIndication(
                payload: payload,
                peerAddress: peerAddress
            )
            let inputAddress = Self.storageAddress(datagram)
            let decoded = try allocation.decapsulate(consume datagram)
            let outputAddress = Self.storageAddress(decoded.payload)

            #expect(inputAddress != 0)
            #expect(outputAddress == inputAddress)
            #expect(decoded.peerAddress == peerAddress)
            #expect(decoded.payload == payload)
            print(
                "TURN receive copy budget: payload=\(byteCount) "
                    + "payloadAllocations=0 ownerAddress=\(outputAddress)"
            )
        }
    }

    @Test(
        "TURN Send Indication 1200-byte throughput",
        .timeLimit(.minutes(1))
    )
    func sendIndicationThroughput() throws {
        let allocation = try Self.makeAllocation()
        let peerAddress = try Self.makePeerAddress()
        let template = [UInt8](repeating: 0xC3, count: 1_200)
        var checksum = 0

        let result = try benchmarkThroughput(
            "TURN Send Indication 1200 bytes",
            dataSize: template.count,
            iterations: 10_000,
            warmup: 1_000
        ) {
            let payload = template
            let datagram = try allocation.encapsulate(
                consume payload,
                to: peerAddress
            )
            checksum &+= Int(datagram.prefixBytes[0])
            checksum &+= Int(datagram.payload[0])
            checksum &+= datagram.encodedByteCount
        }

        print(result)
        #expect(checksum != 0)
    }

    private static func makeAllocation() throws -> TURNAllocation {
        let credentials = try TURNCredentials(
            username: "benchmark-user",
            password: "benchmark-password"
        )
        let authentication = try TURNAuthenticationContext(
            credentials: credentials,
            realm: "benchmark.realm",
            nonce: "benchmark-nonce"
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

    private static func makePeerAddress() throws -> TURNAddress {
        try TURNAddress(
            addressBytes: [192, 0, 2, 10],
            port: 50_000
        )
    }

    private static func makeDataIndication(
        payload: [UInt8],
        peerAddress: TURNAddress
    ) -> [UInt8] {
        let transactionID = TransactionID(
            byteValues: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        )
        return STUNMessage(
            messageType: STUNMessageType(
                method: .data,
                class: .indication
            ),
            transactionID: transactionID,
            attributes: [
                peerAddress.xorAttribute(
                    type: .xorPeerAddress,
                    transactionID: transactionID
                ),
                STUNAttribute(
                    type: STUNAttributeType.data.rawValue,
                    value: payload
                ),
            ]
        ).encodeBytes()
    }

    private static func storageAddress(
        _ bytes: borrowing [UInt8]
    ) -> UInt {
        bytes.withUnsafeBufferPointer { buffer in
            buffer.baseAddress.map(UInt.init(bitPattern:)) ?? 0
        }
    }
}
