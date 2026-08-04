import Foundation
import Testing
@testable import WebRTC

@Suite("SCTP Cookie Restart Tests")
struct SCTPCookieRestartTests {
    private typealias Engine = SCTPAssociationEngine

    private let clientTag: UInt32 = 0x1111_1111
    private let serverTag: UInt32 = 0x2222_2222
    private let restartClientTag: UInt32 = 0x3333_3333
    private let restartServerTag: UInt32 = 0x4444_4444

    private func makeEngine(
        initiateTag: UInt32,
        initialTSN: UInt32
    ) -> Engine {
        Engine(
            localPort: 5_000,
            remotePort: 5_000,
            maxInboundStreams: 32,
            maxOutboundStreams: 32,
            initiateTag: initiateTag,
            initialTSN: initialTSN,
            cookieSecretKey: Array(
                repeating: UInt8(truncatingIfNeeded: initiateTag),
                count: 32
            ),
            cookieCrypto: makeSCTPCookieCryptoContext()
        )
    }

    private func establishPair() throws -> (client: Engine, server: Engine) {
        var client = makeEngine(initiateTag: clientTag, initialTSN: 100)
        var server = makeEngine(initiateTag: serverTag, initialTSN: 200)

        let initAck = try #require(server.processPacketWithEvents(
            client.generateInit(),
            nowMillis: 1
        ).responses.first)
        let cookieEcho = try #require(client.processPacketWithEvents(
            initAck,
            nowMillis: 2
        ).responses.first)
        let cookieAck = try #require(server.processPacketWithEvents(
            cookieEcho,
            nowMillis: 3
        ).responses.first)
        _ = try client.processPacketWithEvents(cookieAck, nowMillis: 4)
        return (client, server)
    }

    private func restartCookieEcho(
        server: inout Engine,
        nowMillis: UInt64 = 10
    ) throws -> (client: Engine, cookieEcho: SCTPPacket) {
        var client = makeEngine(
            initiateTag: restartClientTag,
            initialTSN: 300
        )
        let initAck = try #require(server.processPacketWithEvents(
            client.generateInit(),
            nowMillis: nowMillis,
            restartEntropy: SCTPAssociationRestartEntropy(
                initiateTag: restartServerTag,
                initialTSN: 400
            )
        ).responses.first)
        let cookieEcho = try #require(client.processPacketWithEvents(
            initAck,
            nowMillis: nowMillis + 1
        ).responses.first)
        return (client, cookieEcho)
    }

    @Test("Cookie wire format is exact and authenticates restart fields")
    func cookieWireFormatIsExactAndAuthenticated() throws {
        let secret = Array("01234567890123456789012345678901".utf8)
        let cookie = SCTPCookieCore.generate(
            secretKey: secret,
            timestamp: 7,
            peerTag: restartClientTag,
            localTag: restartServerTag,
            localTieTag: serverTag,
            peerTieTag: clientTag,
            localInitialTSN: 400,
            peerInitialTSN: 300,
            peerARWC: 1_048_576,
            outboundStreams: 16,
            inboundStreams: 32,
            extensionFlags: 1,
            localPort: 5_000,
            peerPort: 5_001,
            crypto: makeSCTPCookieCryptoContext()
        )
        let encoded = cookie.encode()

        #expect(encoded.count == SCTPCookieCore.encodedSize)
        #expect(try SCTPCookieCore.decode(from: encoded) == cookie)
        #expect(throws: SCTPWireError.self) {
            _ = try SCTPCookieCore.decode(from: Array(encoded.dropLast()))
        }
        #expect(throws: SCTPWireError.self) {
            _ = try SCTPCookieCore.decode(from: encoded + [0])
        }

        for offset in [32, 36, 40, 44, 46] {
            var tampered = encoded
            tampered[offset] ^= 0x01
            let decoded = try SCTPCookieCore.decode(from: tampered)
            #expect(!decoded.isAuthentic(
                secretKey: secret,
                crypto: makeSCTPCookieCryptoContext()
            ))
        }
    }

    @Test("Authenticated Action A commits only at COOKIE ECHO")
    func actionARestartsOnlyAtCookieEcho() throws {
        var pair = try establishPair()
        _ = try pair.server.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0xAA],
            unordered: false,
            nowMillis: 8
        )
        #expect(pair.server.hasUnacknowledgedData)

        var restart = try restartCookieEcho(server: &pair.server)

        // Receiving the unexpected INIT must leave the old TCB fully usable.
        #expect(pair.server.state == .established)
        #expect(pair.server.hasUnacknowledgedData)
        let oldPeerData = try #require(pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x41],
            unordered: false,
            nowMillis: 12
        ).first)
        let beforeCommit = try pair.server.processPacketWithEvents(
            oldPeerData,
            nowMillis: 13
        )
        #expect(beforeCommit.receivedData.map { $0.data } == [[0x41]])

        let committed = try pair.server.processPacketWithEvents(
            restart.cookieEcho,
            nowMillis: 14
        )
        let cookieAck = try #require(committed.responses.first)
        #expect(committed.events == [.associationRestarted])
        #expect(pair.server.state == .established)
        #expect(!pair.server.hasUnacknowledgedData)

        _ = try restart.client.processPacketWithEvents(cookieAck, nowMillis: 15)
        let restartedData = try #require(restart.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x42],
            unordered: false,
            nowMillis: 16
        ).first)
        let afterCommit = try pair.server.processPacketWithEvents(
            restartedData,
            nowMillis: 17
        )
        #expect(afterCommit.receivedData.map { $0.data } == [[0x42]])

        let staleOldPeerData = try #require(pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x43],
            unordered: false,
            nowMillis: 18
        ).first)
        do {
            _ = try pair.server.processPacketWithEvents(
                staleOldPeerData,
                nowMillis: 19
            )
            Issue.record("Expected the pre-restart verification tag to fail")
        } catch SCTPError.verificationTagMismatch(let expected, let actual) {
            #expect(expected == restartServerTag)
            #expect(actual == serverTag)
        } catch {
            Issue.record("Unexpected stale-peer error: \(error)")
        }
    }

    @Test("Action A in SHUTDOWN ACK SENT returns cause 10 without restart")
    func actionADuringShutdownAckSentReturnsCauseTen() throws {
        var pair = try establishPair()
        let restart = try restartCookieEcho(server: &pair.server)

        let shutdownRequest = try pair.client.requestShutdown(nowMillis: 20)
        let shutdown = try #require(shutdownRequest)
        _ = try pair.server.processPacketWithEvents(shutdown, nowMillis: 21)
        #expect(pair.server.state == .shutdownAckSent)

        let firstRetransmission = try pair.server.pollOutboundPackets(
            nowMillis: 3_021
        ).get()
        #expect(firstRetransmission.first?.chunks.first?.chunkType
            == SCTPChunkType.shutdownAck.rawValue)

        let response = try pair.server.processPacketWithEvents(
            restart.cookieEcho,
            nowMillis: 4_000
        )
        let chunks = response.responses.flatMap(\.chunks)
        #expect(pair.server.state == .shutdownAckSent)
        #expect(chunks.contains {
            $0.chunkType == SCTPChunkType.shutdownAck.rawValue
        })
        #expect(chunks.allSatisfy {
            $0.chunkType != SCTPChunkType.cookieAck.rawValue
        })
        let errorChunk = try #require(chunks.first {
            $0.chunkType == SCTPChunkType.error.rawValue
        })
        _ = try SCTPCookieReceivedWhileShuttingDownErrorCause.decode(
            from: errorChunk
        )

        let beforePreservedDeadline = try pair.server.pollOutboundPackets(
            nowMillis: 9_020
        ).get()
        #expect(beforePreservedDeadline.isEmpty)
        let atPreservedDeadline = try pair.server.pollOutboundPackets(
            nowMillis: 9_021
        ).get()
        #expect(atPreservedDeadline.first?.chunks.first?.chunkType
            == SCTPChunkType.shutdownAck.rawValue)
    }

    @Test("Expired Action D is acknowledged but expired Action A is stale")
    func expirationDependsOnAuthenticatedAction() throws {
        var pair = try establishPair()

        // Build an Action D cookie through the original four-way handshake and
        // replay it after the normal cookie lifetime.
        var duplicateClient = makeEngine(
            initiateTag: 0x5555_5555,
            initialTSN: 500
        )
        var duplicateServer = makeEngine(
            initiateTag: 0x6666_6666,
            initialTSN: 600
        )
        let initAck = try #require(duplicateServer.processPacketWithEvents(
            duplicateClient.generateInit(),
            nowMillis: 1
        ).responses.first)
        let duplicateCookieEcho = try #require(duplicateClient.processPacketWithEvents(
            initAck,
            nowMillis: 2
        ).responses.first)
        _ = try duplicateServer.processPacketWithEvents(
            duplicateCookieEcho,
            nowMillis: 3
        )
        let duplicateResponse = try duplicateServer.processPacketWithEvents(
            duplicateCookieEcho,
            nowMillis: 60_002
        )
        #expect(duplicateResponse.responses.flatMap(\.chunks).contains {
            $0.chunkType == SCTPChunkType.cookieAck.rawValue
        })

        let restart = try restartCookieEcho(server: &pair.server, nowMillis: 10)
        let staleResponse = try pair.server.processPacketWithEvents(
            restart.cookieEcho,
            nowMillis: 60_011
        )
        let staleChunks = staleResponse.responses.flatMap(\.chunks)
        #expect(pair.server.state == .established)
        #expect(staleChunks.allSatisfy {
            $0.chunkType != SCTPChunkType.cookieAck.rawValue
        })
        let staleError = try #require(staleChunks.first {
            $0.chunkType == SCTPChunkType.error.rawValue
        })
        let cause = try SCTPStaleCookieErrorCause.decode(from: staleError)
        #expect(cause.stalenessMicroseconds == 1_000)
    }
}
