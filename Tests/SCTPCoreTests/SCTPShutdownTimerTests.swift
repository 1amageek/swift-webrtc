import Testing
@testable import WebRTC

@Suite("SCTP Graceful Shutdown and T2 Tests")
struct SCTPShutdownTimerTests {
    private typealias Engine = SCTPAssociationEngine

    private func makeEngine(
        initiateTag: UInt32,
        initialTSN: UInt32
    ) -> Engine {
        Engine(
            localPort: 5000,
            remotePort: 5000,
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
        var client = makeEngine(initiateTag: 0x1111_1111, initialTSN: 100)
        var server = makeEngine(initiateTag: 0x2222_2222, initialTSN: 200)

        let initPacket = client.generateInit()
        let initAck = try #require(server.processPacketWithEvents(
            initPacket,
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

    private func firstPacket(
        of type: SCTPChunkType,
        in packets: [SCTPPacket]
    ) -> SCTPPacket? {
        packets.first { packet in
            packet.chunks.contains { $0.chunkType == type.rawValue }
        }
    }

    private func uint32(_ bytes: [UInt8]) -> UInt32? {
        guard bytes.count == 4 else { return nil }
        return UInt32(bytes[0]) << 24
            | UInt32(bytes[1]) << 16
            | UInt32(bytes[2]) << 8
            | UInt32(bytes[3])
    }

    @Test("A drained association emits SHUTDOWN immediately with the latest cumulative TSN")
    func immediateShutdownUsesCurrentCumulativeTSN() throws {
        var pair = try establishPair()

        let requested = try pair.client.requestShutdown(nowMillis: 10)
        let shutdown = try #require(requested)
        let chunk = try #require(shutdown.chunks.first)

        #expect(pair.client.state == .shutdownSent)
        #expect(shutdown.chunks.count == 1)
        #expect(chunk.chunkType == SCTPChunkType.shutdown.rawValue)
        #expect(uint32(chunk.value) == 199)
    }

    @Test("Outstanding DATA drains before exactly one SHUTDOWN is emitted")
    func pendingShutdownWaitsForDataAcknowledgment() throws {
        var pair = try establishPair()
        let dataPacket = try #require(pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x41],
            unordered: false,
            nowMillis: 10
        ).first)

        let pendingRequest = try pair.client.requestShutdown(nowMillis: 11)
        #expect(pendingRequest == nil)
        #expect(pair.client.state == .shutdownPending)
        let prematurePoll = try pair.client.pollOutboundPackets(nowMillis: 12).get()
        #expect(prematurePoll.isEmpty)

        let sack = try #require(firstPacket(
            of: .sack,
            in: pair.server.processPacketWithEvents(
                dataPacket,
                nowMillis: 13
            ).responses
        ))
        let outcome = try pair.client.processPacketOutcome(sack, nowMillis: 14)
        let responses: [SCTPPacket]
        switch outcome {
        case .processed(let result):
            responses = result.responses
        case .closed, .terminal:
            Issue.record("SACK must advance SHUTDOWN-PENDING without closing")
            return
        }

        #expect(pair.client.state == .shutdownSent)
        #expect(responses.flatMap(\.chunks).filter {
            $0.chunkType == SCTPChunkType.shutdown.rawValue
        }.count == 1)
        #expect(!pair.client.hasUnacknowledgedData)
    }

    @Test("T2 retransmits SHUTDOWN at the deadline and applies exponential backoff")
    func shutdownT2Backoff() throws {
        var pair = try establishPair()
        let requested = try pair.client.requestShutdown(nowMillis: 10)
        _ = try #require(requested)

        let beforeFirstDeadline = try pair.client.pollOutboundPackets(
            nowMillis: 3_009
        ).get()
        #expect(beforeFirstDeadline.isEmpty)
        let first = try pair.client.pollOutboundPackets(nowMillis: 3_010).get()
        #expect(first.count == 1)
        #expect(first.first?.chunks.first?.chunkType == SCTPChunkType.shutdown.rawValue)

        let beforeSecondDeadline = try pair.client.pollOutboundPackets(
            nowMillis: 9_009
        ).get()
        #expect(beforeSecondDeadline.isEmpty)
        let second = try pair.client.pollOutboundPackets(nowMillis: 9_010).get()
        #expect(second.count == 1)
        #expect(second.first?.chunks.first?.chunkType == SCTPChunkType.shutdown.rawValue)
    }

    @Test("A valid peer packet restarts T2 without resetting the backed-off RTO")
    func validPeerPacketRestartsT2() throws {
        var pair = try establishPair()
        let requested = try pair.client.requestShutdown(nowMillis: 10)
        _ = try #require(requested)
        _ = try pair.client.pollOutboundPackets(nowMillis: 3_010).get()

        let heartbeatAck = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5000,
            verificationTag: 0x1111_1111,
            chunks: [try SCTPChunk(
                chunkType: SCTPChunkType.heartbeatAck.rawValue,
                value: []
            )]
        )
        _ = try pair.client.processPacketWithEvents(
            heartbeatAck,
            nowMillis: 4_000
        )

        let oldDeadline = try pair.client.pollOutboundPackets(
            nowMillis: 9_010
        ).get()
        #expect(oldDeadline.isEmpty)
        let restarted = try pair.client.pollOutboundPackets(
            nowMillis: 10_000
        ).get()
        #expect(restarted.count == 1)
        #expect(restarted.first?.chunks.first?.chunkType
            == SCTPChunkType.shutdown.rawValue)
    }

    @Test("DATA received in SHUTDOWN-SENT refreshes the cumulative TSN in SHUTDOWN")
    func shutdownSentDataRefreshesCumulativeTSN() throws {
        var pair = try establishPair()
        let requested = try pair.client.requestShutdown(nowMillis: 10)
        _ = try #require(requested)
        let peerPackets = try pair.server.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: [0x42],
            unordered: false,
            nowMillis: 11
        )
        let peerData = try #require(peerPackets.first)

        let result = try pair.client.processPacketWithEvents(
            peerData,
            nowMillis: 12
        )
        let refreshed = try #require(result.responses
            .flatMap(\.chunks)
            .first { $0.chunkType == SCTPChunkType.shutdown.rawValue })

        #expect(result.receivedData.count == 1)
        #expect(uint32(refreshed.value) == 200)
        #expect(pair.client.state == .shutdownSent)
    }

    @Test("T2 retransmits SHUTDOWN ACK while awaiting SHUTDOWN COMPLETE")
    func shutdownAckT2Retransmission() throws {
        var pair = try establishPair()
        let requested = try pair.client.requestShutdown(nowMillis: 10)
        let shutdown = try #require(requested)
        let response = try pair.server.processPacketWithEvents(
            shutdown,
            nowMillis: 11
        )
        let shutdownAck = try #require(firstPacket(of: .shutdownAck, in: response.responses))

        #expect(pair.server.state == .shutdownAckSent)
        #expect(shutdownAck.chunks.count == 1)
        let beforeDeadline = try pair.server.pollOutboundPackets(
            nowMillis: 3_010
        ).get()
        #expect(beforeDeadline.isEmpty)
        let retransmission = try pair.server.pollOutboundPackets(nowMillis: 3_011).get()
        #expect(retransmission.count == 1)
        #expect(retransmission.first?.chunks.first?.chunkType == SCTPChunkType.shutdownAck.rawValue)
    }

    @Test("INIT in SHUTDOWN-ACK-SENT retransmits SHUTDOWN ACK without restarting")
    func initDuringShutdownAckSentDoesNotRestartAssociation() throws {
        var pair = try establishPair()
        let requested = try pair.client.requestShutdown(nowMillis: 10)
        let shutdown = try #require(requested)
        _ = try pair.server.processPacketWithEvents(shutdown, nowMillis: 11)
        #expect(pair.server.state == .shutdownAckSent)

        let restartAttempt = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5000,
            verificationTag: 0,
            chunks: [SCTPInitChunk(
                initiateTag: 0x3333_3333,
                advertisedReceiverWindowCredit: 65_535,
                numberOfOutboundStreams: 32,
                numberOfInboundStreams: 32,
                initialTSN: 300
            ).toChunk()]
        )
        let result = try pair.server.processPacketWithEvents(
            restartAttempt,
            nowMillis: 12
        )

        #expect(pair.server.state == .shutdownAckSent)
        #expect(result.responses.count == 1)
        #expect(result.responses.first?.chunks.count == 1)
        #expect(result.responses.first?.chunks.first?.chunkType
            == SCTPChunkType.shutdownAck.rawValue)
    }

    @Test("Delayed INIT ACK and COOKIE ACK cannot revive SHUTDOWN-SENT")
    func delayedHandshakeChunksDoNotReviveShutdown() throws {
        var pair = try establishPair()
        let requested = try pair.client.requestShutdown(nowMillis: 10)
        _ = try #require(requested)

        let delayedInitAck = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5000,
            verificationTag: 0x1111_1111,
            chunks: [try SCTPChunk(
                chunkType: SCTPChunkType.initAck.rawValue,
                value: []
            )]
        )
        let delayedCookieAck = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5000,
            verificationTag: 0x1111_1111,
            chunks: [try SCTPChunk(
                chunkType: SCTPChunkType.cookieAck.rawValue,
                value: []
            )]
        )

        let first = try pair.client.processPacketWithEvents(
            delayedInitAck,
            nowMillis: 11
        )
        let second = try pair.client.processPacketWithEvents(
            delayedCookieAck,
            nowMillis: 12
        )

        #expect(first.responses.isEmpty)
        #expect(second.responses.isEmpty)
        #expect(pair.client.state == .shutdownSent)
    }

    @Test("Duplicate COOKIE ECHO during shutdown remains Action D")
    func duplicateCookieEchoDuringShutdownIsAcknowledged() throws {
        var client = makeEngine(initiateTag: 0x1111_1111, initialTSN: 100)
        var server = makeEngine(initiateTag: 0x2222_2222, initialTSN: 200)
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

        let shutdownRequest = try client.requestShutdown(nowMillis: 10)
        let shutdown = try #require(shutdownRequest)
        _ = try server.processPacketWithEvents(shutdown, nowMillis: 11)
        #expect(server.state == .shutdownAckSent)

        let replay = try server.processPacketWithEvents(
            cookieEcho,
            nowMillis: 12
        )
        let chunks = replay.responses.flatMap(\.chunks)
        #expect(server.state == .shutdownAckSent)
        #expect(chunks.contains {
            $0.chunkType == SCTPChunkType.cookieAck.rawValue
        })
        #expect(chunks.allSatisfy {
            $0.chunkType != SCTPChunkType.error.rawValue
        })
    }

    @Test("Association shutdown supersedes an outstanding local stream reset")
    func shutdownCancelsOutgoingStreamReset() throws {
        var pair = try establishPair()
        let reset = try pair.client.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 10
        )
        _ = try #require(reset)

        let shutdown = try pair.client.requestShutdown(nowMillis: 11)
        let packet = try #require(shutdown)
        #expect(pair.client.state == .shutdownSent)
        #expect(packet.chunks.first?.chunkType == SCTPChunkType.shutdown.rawValue)

        let timed = try pair.client.pollOutboundPackets(nowMillis: 3_011).get()
        #expect(timed.count == 1)
        #expect(timed.first?.chunks.first?.chunkType == SCTPChunkType.shutdown.rawValue)
        #expect(timed.flatMap(\.chunks).allSatisfy {
            $0.chunkType != SCTPChunkType.reConfig.rawValue
        })
    }

    @Test("The complete graceful handshake closes both associations")
    func gracefulShutdownCompletes() throws {
        var pair = try establishPair()
        let requested = try pair.client.requestShutdown(nowMillis: 10)
        let shutdown = try #require(requested)
        let shutdownAck = try #require(firstPacket(
            of: .shutdownAck,
            in: pair.server.processPacketWithEvents(
                shutdown,
                nowMillis: 11
            ).responses
        ))

        let clientOutcome = try pair.client.processPacketOutcome(
            shutdownAck,
            nowMillis: 12
        )
        let shutdownComplete: SCTPPacket
        switch clientOutcome {
        case .closed(let result):
            shutdownComplete = try #require(firstPacket(
                of: .shutdownComplete,
                in: result.responses
            ))
        case .processed, .terminal:
            Issue.record("SHUTDOWN ACK must cleanly close the initiator")
            return
        }

        let serverOutcome = try pair.server.processPacketOutcome(
            shutdownComplete,
            nowMillis: 13
        )
        guard case .closed = serverOutcome else {
            Issue.record("SHUTDOWN COMPLETE must cleanly close the responder")
            return
        }
        #expect(shutdownComplete.chunks.count == 1)
        #expect(pair.client.state == .closed)
        #expect(pair.server.state == .closed)
    }

    @Test("Crossed SHUTDOWN packets complete simultaneous graceful shutdown")
    func simultaneousShutdownCompletes() throws {
        var pair = try establishPair()
        let requestedByClient = try pair.client.requestShutdown(nowMillis: 10)
        let requestedByServer = try pair.server.requestShutdown(nowMillis: 10)
        let clientShutdown = try #require(requestedByClient)
        let serverShutdown = try #require(requestedByServer)

        let clientAck = try #require(firstPacket(
            of: .shutdownAck,
            in: pair.client.processPacketWithEvents(
                serverShutdown,
                nowMillis: 11
            ).responses
        ))
        let serverAck = try #require(firstPacket(
            of: .shutdownAck,
            in: pair.server.processPacketWithEvents(
                clientShutdown,
                nowMillis: 11
            ).responses
        ))

        let clientOutcome = try pair.client.processPacketOutcome(serverAck, nowMillis: 12)
        let serverOutcome = try pair.server.processPacketOutcome(clientAck, nowMillis: 12)
        guard case .closed(let clientResult) = clientOutcome,
              case .closed(let serverResult) = serverOutcome else {
            Issue.record("Crossed SHUTDOWN ACK packets must close both sides")
            return
        }
        #expect(clientResult.responses.first?.chunks.first?.chunkType
            == SCTPChunkType.shutdownComplete.rawValue)
        #expect(serverResult.responses.first?.chunks.first?.chunkType
            == SCTPChunkType.shutdownComplete.rawValue)
        #expect(pair.client.state == .closed)
        #expect(pair.server.state == .closed)
    }

    @Test("Receiver-side T2 retry exhaustion closes without a T5 guard")
    func shutdownTimeoutClosesAndReleasesOwners() throws {
        var pair = try establishPair()
        let requested = try pair.client.requestShutdown(nowMillis: 0)
        let shutdown = try #require(requested)
        _ = try pair.server.processPacketWithEvents(
            shutdown,
            nowMillis: 11
        )
        #expect(pair.server.state == .shutdownAckSent)
        let retransmissionDeadlines: [UInt64] = [
            3_011,
            9_011,
            21_011,
            45_011,
            93_011,
            153_011,
            213_011,
            273_011,
            333_011,
            393_011,
        ]

        for deadline in retransmissionDeadlines {
            let packets = try pair.server.pollOutboundPackets(
                nowMillis: deadline
            ).get()
            #expect(packets.count == 1)
            #expect(packets.first?.chunks.first?.chunkType
                == SCTPChunkType.shutdownAck.rawValue)
        }

        switch pair.server.pollOutboundPackets(nowMillis: 453_011) {
        case .failure(.shutdownTimeout):
            break
        case .failure(let error):
            Issue.record("Expected shutdownTimeout, got \(error)")
        case .success:
            Issue.record("Expected T2 retry exhaustion")
        }
        #expect(pair.server.state == .closed)
        #expect(pair.server.retainedUserDataByteCount == 0)
        let afterClose = try pair.server.pollOutboundPackets(
            nowMillis: 500_000
        ).get()
        #expect(afterClose.isEmpty)
    }

    @Test("An unrepresentable T2 deadline fails with a typed clock error")
    func overflowingDeadlineFailsExplicitly() {
        do {
            _ = try SCTPShutdownTimerState(
                controlFlight: .shutdown,
                sentMillis: UInt64.max - 100,
                rtoMillis: 200
            )
            Issue.record("Expected the monotonic deadline overflow to fail")
        } catch SCTPError.monotonicClockValueOutOfRange {
            // Expected typed failure.
        } catch {
            Issue.record("Unexpected timer construction error: \(error)")
        }
    }

    @Test("T2 and T5 deadlines are exact and crossed shutdown inherits T5")
    func shutdownDeadlineConstruction() throws {
        let shutdown = try SCTPShutdownTimerState(
            controlFlight: .shutdown,
            sentMillis: 10,
            rtoMillis: 3_000
        )
        let receiverAck = try SCTPShutdownTimerState(
            controlFlight: .shutdownAck,
            sentMillis: 20,
            rtoMillis: 3_000
        )
        let crossedAck = try SCTPShutdownTimerState(
            controlFlight: .shutdownAck,
            sentMillis: 30,
            rtoMillis: 3_000,
            inheritedT5DeadlineMillis: shutdown.t5DeadlineMillis
        )

        #expect(shutdown.t2DeadlineMillis == 3_010)
        #expect(shutdown.t5DeadlineMillis == 300_010)
        #expect(receiverAck.t2DeadlineMillis == 3_020)
        #expect(receiverAck.t5DeadlineMillis == nil)
        #expect(crossedAck.t2DeadlineMillis == 3_030)
        #expect(crossedAck.t5DeadlineMillis == 300_010)
    }

    @Test("Shutdown RTO rejects zero and values above the protocol cap")
    func invalidShutdownRTOFailsExplicitly() {
        for invalidRTO in [UInt64(0), UInt64(60_001)] {
            do {
                _ = try SCTPShutdownTimerState(
                    controlFlight: .shutdown,
                    sentMillis: 0,
                    rtoMillis: invalidRTO
                )
                Issue.record("Expected invalid RTO \(invalidRTO) to fail")
            } catch SCTPError.invalidShutdownRTO(let actual) {
                #expect(actual == invalidRTO)
            } catch {
                Issue.record("Unexpected RTO validation error: \(error)")
            }
        }
    }

    @Test("T2 restart and backoff preserve state when deadline arithmetic fails")
    func timerMutationIsTransactional() throws {
        var timer = try SCTPShutdownTimerState(
            controlFlight: .shutdown,
            sentMillis: 0,
            rtoMillis: 3_000
        )
        try timer.backoff(at: 3_000)
        #expect(timer.retransmitCount == 1)
        #expect(timer.rtoMillis == 6_000)
        #expect(timer.t2DeadlineMillis == 9_000)
        #expect(timer.t5DeadlineMillis == 300_000)

        let restartSnapshot = timer
        do {
            try timer.restart(at: UInt64.max - 5_999)
            Issue.record("Expected restart deadline overflow")
        } catch SCTPError.monotonicClockValueOutOfRange {
            // Expected typed failure.
        } catch {
            Issue.record("Unexpected restart error: \(error)")
        }
        #expect(timer.t2DeadlineMillis == restartSnapshot.t2DeadlineMillis)
        #expect(timer.rtoMillis == restartSnapshot.rtoMillis)
        #expect(timer.retransmitCount == restartSnapshot.retransmitCount)
        #expect(timer.t5DeadlineMillis == restartSnapshot.t5DeadlineMillis)

        let backoffSnapshot = timer
        do {
            try timer.backoff(at: UInt64.max - 11_999)
            Issue.record("Expected backoff deadline overflow")
        } catch SCTPError.monotonicClockValueOutOfRange {
            // Expected typed failure.
        } catch {
            Issue.record("Unexpected backoff error: \(error)")
        }
        #expect(timer.t2DeadlineMillis == backoffSnapshot.t2DeadlineMillis)
        #expect(timer.rtoMillis == backoffSnapshot.rtoMillis)
        #expect(timer.retransmitCount == backoffSnapshot.retransmitCount)
        #expect(timer.t5DeadlineMillis == backoffSnapshot.t5DeadlineMillis)
    }

    @Test("T5 emits one final ABORT at its exact deadline")
    func shutdownGuardDeadlineIsTerminal() throws {
        var pair = try establishPair()
        let requested = try pair.client.requestShutdown(nowMillis: 0)
        _ = try #require(requested)

        guard case .packets = pair.client.pollOutboundPacketsOutcome(
            nowMillis: 299_999
        ) else {
            Issue.record("T5 must not expire before its exact deadline")
            return
        }
        guard case .terminal(let packets, .shutdownGuardTimeout) =
                pair.client.pollOutboundPacketsOutcome(nowMillis: 300_000) else {
            Issue.record("T5 must terminate with its typed guard failure")
            return
        }

        #expect(packets.count == 1)
        #expect(packets.first?.chunks.first?.chunkType
            == SCTPChunkType.abort.rawValue)
        #expect(pair.client.state == .closed)
        #expect(pair.client.retainedUserDataByteCount == 0)
        guard case .packets(let afterClose) =
                pair.client.pollOutboundPacketsOutcome(nowMillis: 300_001) else {
            Issue.record("Closed association must remain quiescent")
            return
        }
        #expect(afterClose.isEmpty)
    }

    @Test("Valid peer traffic restarts T2 but cannot extend T5")
    func peerTrafficDoesNotExtendShutdownGuard() throws {
        var pair = try establishPair()
        let requested = try pair.client.requestShutdown(nowMillis: 0)
        _ = try #require(requested)
        let heartbeatAck = SCTPPacket(
            sourcePort: 5_000,
            destinationPort: 5_000,
            verificationTag: 0x1111_1111,
            chunks: [try SCTPChunk(
                chunkType: SCTPChunkType.heartbeatAck.rawValue,
                value: []
            )]
        )

        _ = try pair.client.processPacketWithEvents(
            heartbeatAck,
            nowMillis: 299_999
        )
        guard case .terminal(let packets, .shutdownGuardTimeout) =
                pair.client.pollOutboundPacketsOutcome(nowMillis: 300_000) else {
            Issue.record("Peer traffic must not extend the absolute T5 guard")
            return
        }
        #expect(packets.first?.chunks.first?.chunkType
            == SCTPChunkType.abort.rawValue)
    }

    @Test("Crossed shutdown carries the initiator T5 into ACK SENT")
    func crossedShutdownPreservesGuardDeadline() throws {
        var pair = try establishPair()
        let requested = try pair.client.requestShutdown(nowMillis: 0)
        _ = try #require(requested)
        let peerRequest = try pair.server.requestShutdown(nowMillis: 299_999)
        let peerShutdown = try #require(peerRequest)
        let response = try pair.client.processPacketWithEvents(
            peerShutdown,
            nowMillis: 299_999
        )

        #expect(pair.client.state == .shutdownAckSent)
        #expect(response.responses.first?.chunks.first?.chunkType
            == SCTPChunkType.shutdownAck.rawValue)
        guard case .terminal(_, .shutdownGuardTimeout) =
                pair.client.pollOutboundPacketsOutcome(nowMillis: 300_000) else {
            Issue.record("Crossed shutdown must preserve the original T5 deadline")
            return
        }
    }

    @Test("Shutdown request failure preserves an outstanding reset transaction")
    func shutdownRequestFailureIsTransactional() throws {
        var pair = try establishPair()
        let resetRequest = try pair.client.requestOutgoingStreamReset(
            .listed([0]),
            nowMillis: 0
        )
        let reset = try #require(resetRequest)
        #expect(reset.chunks.first?.chunkType == SCTPChunkType.reConfig.rawValue)

        do {
            _ = try pair.client.requestShutdown(
                nowMillis: UInt64.max - 299_999
            )
            Issue.record("Expected T5 deadline overflow")
        } catch SCTPError.monotonicClockValueOutOfRange {
            // Expected typed failure.
        } catch {
            Issue.record("Unexpected shutdown request error: \(error)")
        }

        #expect(pair.client.state == .established)
        let retainedReset = try pair.client.pollOutboundPackets(
            nowMillis: UInt64.max - 299_999
        ).get()
        #expect(retainedReset.count == 1)
        #expect(retainedReset.first?.chunks.first?.chunkType
            == SCTPChunkType.reConfig.rawValue)
    }

    @Test("SHUTDOWN ACK closes before an unnecessary T2 restart can overflow")
    func shutdownAckAvoidsPreprocessingTimerMutation() throws {
        var pair = try establishPair()
        let start = UInt64.max - 300_000
        let shutdownRequest = try pair.client.requestShutdown(nowMillis: start)
        let shutdown = try #require(shutdownRequest)
        let serverResponse = try pair.server.processPacketWithEvents(
            shutdown,
            nowMillis: start + 1
        )
        let shutdownAck = try #require(firstPacket(
            of: .shutdownAck,
            in: serverResponse.responses
        ))

        let outcome = try pair.client.processPacketOutcome(
            shutdownAck,
            nowMillis: UInt64.max - 2_999
        )
        guard case .closed(let result) = outcome else {
            Issue.record("SHUTDOWN ACK must close without restarting T2")
            return
        }
        #expect(result.responses.first?.chunks.first?.chunkType
            == SCTPChunkType.shutdownComplete.rawValue)
        #expect(pair.client.state == .closed)
    }

    @Test("An unrepresentable peer ACK timer returns ABORT and typed failure")
    func peerShutdownAckTimerFailureIsTerminal() throws {
        var pair = try establishPair()
        let shutdownRequest = try pair.client.requestShutdown(nowMillis: 0)
        let shutdown = try #require(shutdownRequest)
        let outcome = try pair.server.processPacketOutcome(
            shutdown,
            nowMillis: UInt64.max - 2_999
        )

        guard case .terminal(
            let result,
            .monotonicClockValueOutOfRange
        ) = outcome else {
            Issue.record("ACK timer overflow must be an explicit terminal outcome")
            return
        }
        #expect(result.responses.first?.chunks.first?.chunkType
            == SCTPChunkType.abort.rawValue)
        #expect(pair.server.state == .closed)
    }

    @Test("SHUTDOWN cumulative acknowledgment preserves previous Gap ACK state")
    func shutdownDoesNotTreatMissingGapBlocksAsReneging() throws {
        var state = RetransmissionState(initialTSN: 10)
        let first = SCTPDataChunk(
            tsn: 10,
            streamIdentifier: 0,
            streamSequenceNumber: 0,
            payloadProtocolIdentifier: 53,
            userData: Array(repeating: 0x10, count: 100)
        )
        let second = SCTPDataChunk(
            tsn: 11,
            streamIdentifier: 0,
            streamSequenceNumber: 1,
            payloadProtocolIdentifier: 53,
            userData: Array(repeating: 0x11, count: 100)
        )
        try state.enqueue(first, sentMillis: 0)
        try state.enqueue(second, sentMillis: 0)
        _ = state.acknowledge(
            cumulativeTSN: 9,
            gapBlocks: [(start: 2, end: 2)],
            advertisedReceiverWindowCredit: 1_000,
            receivedMillis: 10
        )

        let outcome = state.acknowledgeShutdown(
            cumulativeTSN: 9,
            receivedMillis: 20
        )
        guard case .applied(let update) = outcome else {
            Issue.record("Expected SHUTDOWN acknowledgment to apply")
            return
        }
        let retransmissions = try state.pendingRetransmissions(
            nowMillis: 20,
            includeExpired: false
        ).get()

        #expect(update.renegedByteCount == 0)
        #expect(state.bytesInFlight == 100)
        #expect(state.retainedPayloadByteCount == 200)
        #expect(retransmissions.isEmpty)
    }

    @Test("Peer ABORT clears DATA ownership and disables every timer poll")
    func abortClearsRetainedOwners() throws {
        var pair = try establishPair()
        _ = try pair.client.sendDataPackets(
            streamID: 0,
            payloadProtocolIdentifier: 53,
            data: Array(repeating: 0x7A, count: 1_024),
            unordered: false,
            nowMillis: 10
        )
        #expect(pair.client.retainedUserDataByteCount == 1_024)

        let abort = SCTPPacket(
            sourcePort: 5000,
            destinationPort: 5000,
            verificationTag: 0x1111_1111,
            chunks: [try SCTPChunk(
                chunkType: SCTPChunkType.abort.rawValue,
                value: []
            )]
        )
        let outcome = try pair.client.processPacketOutcome(abort, nowMillis: 11)
        guard case .terminal(let result, .associationAborted) = outcome else {
            Issue.record("Peer ABORT must preserve its typed terminal cause")
            return
        }

        #expect(result.responses.isEmpty)
        #expect(result.deliveries.isEmpty)
        #expect(pair.client.state == .closed)
        #expect(pair.client.retainedUserDataByteCount == 0)
        #expect(!pair.client.hasUnacknowledgedData)
        let afterAbort = try pair.client.pollOutboundPackets(
            nowMillis: UInt64.max
        ).get()
        #expect(afterAbort.isEmpty)
    }
}
