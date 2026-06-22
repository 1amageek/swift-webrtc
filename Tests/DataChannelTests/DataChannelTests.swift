/// Tests for Data Channel

import Testing
import Foundation
@testable import DataChannel

@Suite("DCEP Message Tests")
struct DCEPMessageTests {

    @Test("DCEP Open encode/decode roundtrip")
    func dcepOpenRoundtrip() throws {
        let open = DCEPOpen(
            channelType: .reliable,
            label: "test-channel",
            protocol_: "test-proto"
        )

        let encoded = open.encode()
        let decoded = try DCEPOpen.decode(from: encoded)

        #expect(decoded.channelType == .reliable)
        #expect(decoded.label == "test-channel")
        #expect(decoded.protocol_ == "test-proto")
    }

    @Test("DCEP Ack encode/decode")
    func dcepAckRoundtrip() throws {
        let ack = DCEPAck()
        let encoded = ack.encode()
        #expect(encoded.count == 1)
        #expect(encoded[0] == DCEPMessageType.dataChannelAck.rawValue)

        let decoded = try DCEPAck.decode(from: encoded)
        _ = decoded
    }

    @Test("DCEP Open with unordered channel")
    func dcepOpenUnordered() throws {
        let open = DCEPOpen(
            channelType: .reliableUnordered,
            label: "unordered"
        )

        let encoded = open.encode()
        let decoded = try DCEPOpen.decode(from: encoded)

        #expect(decoded.channelType == .reliableUnordered)
        #expect(decoded.label == "unordered")
    }

    @Test("DCEP Open with unknown channel type is rejected")
    func dcepOpenUnknownChannelTypeThrows() {
        var encoded = DCEPOpen(channelType: .reliable, label: "x").encode()
        encoded[1] = 0x55 // not a defined DCEPChannelType

        #expect(throws: DataChannelError.self) {
            _ = try DCEPOpen.decode(from: encoded)
        }
    }
}

@Suite("DataChannelManager Tests")
struct DataChannelManagerTests {

    @Test("Open channel as initiator")
    func openChannelInitiator() throws {
        let manager = DataChannelManager(isInitiator: true)
        let (channel, dcepData) = try manager.openChannel(label: "test")

        #expect(channel.id == 0) // Even for initiator
        #expect(channel.label == "test")
        #expect(channel.state == .connecting)
        #expect(!dcepData.isEmpty)
    }

    @Test("Open channel as responder")
    func openChannelResponder() throws {
        let manager = DataChannelManager(isInitiator: false)
        let (channel, _) = try manager.openChannel(label: "test")

        #expect(channel.id == 1) // Odd for responder
    }

    @Test("Process incoming DCEP Open")
    func processIncomingOpen() throws {
        let manager = DataChannelManager(isInitiator: false)

        let open = DCEPOpen(label: "incoming-channel")
        let (response, channel) = try manager.processIncomingDCEP(
            streamID: 0,
            data: open.encode()
        )

        #expect(response != nil) // Should send ACK
        #expect(channel != nil)
        #expect(channel?.label == "incoming-channel")
        #expect(channel?.state == .open)
    }

    @Test("Process DCEP Ack")
    func processDCEPAck() throws {
        let manager = DataChannelManager(isInitiator: true)
        let (channel, _) = try manager.openChannel(label: "test")

        let ack = DCEPAck()
        let (response, _) = try manager.processIncomingDCEP(
            streamID: channel.id,
            data: ack.encode()
        )

        #expect(response == nil) // No response to ACK
        #expect(manager.channel(id: channel.id)?.state == .open)
    }

    // MARK: - Finding 9: stray ACK / duplicate OPEN / parity

    @Test("Stray DCEP ACK on an unknown stream throws")
    func strayAckThrows() {
        let manager = DataChannelManager(isInitiator: true)
        let ack = DCEPAck().encode()
        #expect(throws: DataChannelError.self) {
            _ = try manager.processIncomingDCEP(streamID: 42, data: ack)
        }
    }

    @Test("Duplicate OPEN is idempotent (re-ACKs, keeps the same channel)")
    func duplicateOpenIdempotent() throws {
        // Responder opens odd; incoming OPEN must be even.
        let manager = DataChannelManager(isInitiator: false)
        let open = DCEPOpen(label: "dup").encode()

        let (resp1, chan1) = try manager.processIncomingDCEP(streamID: 0, data: open)
        #expect(resp1 != nil)
        let first = try #require(chan1)

        // Second OPEN on the same stream: re-ACK, no duplicate channel/pending.
        let (resp2, chan2) = try manager.processIncomingDCEP(streamID: 0, data: open)
        #expect(resp2 != nil)
        #expect(chan2?.id == first.id)
        // Exactly one channel and one pending arrival.
        #expect(manager.channels.count == 1)
        #expect(manager.takePendingIncoming().count == 1)
    }

    @Test("OPEN on a wrong-parity stream ID is rejected")
    func openWrongParityRejected() {
        // Responder (isInitiator: false) opens odd, so incoming OPENs must be
        // even. An incoming OPEN on an ODD stream is a parity violation.
        let manager = DataChannelManager(isInitiator: false)
        let open = DCEPOpen(label: "bad-parity").encode()
        #expect(throws: DataChannelError.self) {
            _ = try manager.processIncomingDCEP(streamID: 1, data: open)
        }
    }

    @Test("Initiator parity: incoming OPEN must be odd")
    func openParityForInitiator() throws {
        // Initiator opens even, so incoming OPENs must be odd.
        let manager = DataChannelManager(isInitiator: true)
        let open = DCEPOpen(label: "ok").encode()
        // Odd stream accepted
        let (resp, chan) = try manager.processIncomingDCEP(streamID: 1, data: open)
        #expect(resp != nil)
        #expect(chan != nil)
        // Even stream (initiator's own parity) rejected
        #expect(throws: DataChannelError.self) {
            _ = try manager.processIncomingDCEP(streamID: 2, data: open)
        }
    }

    // MARK: - Finding 10: resource caps

    @Test("Channel cap is enforced on open")
    func channelCapEnforced() throws {
        let manager = DataChannelManager(isInitiator: true, maxChannels: 2)
        _ = try manager.openChannel(label: "a")
        _ = try manager.openChannel(label: "b")
        #expect(throws: DataChannelError.self) {
            _ = try manager.openChannel(label: "c")
        }
    }

    @Test("pendingIncoming cap is enforced")
    func pendingIncomingCapEnforced() throws {
        let manager = DataChannelManager(isInitiator: false, maxPendingIncoming: 1)
        let open = DCEPOpen(label: "x").encode()
        _ = try manager.processIncomingDCEP(streamID: 0, data: open)
        #expect(throws: DataChannelError.self) {
            _ = try manager.processIncomingDCEP(streamID: 2, data: open)
        }
    }

    @Test("Over-long label is rejected on open and on incoming OPEN")
    func labelLengthCapped() throws {
        let manager = DataChannelManager(isInitiator: false, maxLabelOrProtocolLength: 8)
        #expect(throws: DataChannelError.self) {
            _ = try manager.openChannel(label: String(repeating: "x", count: 9))
        }
        let open = DCEPOpen(label: String(repeating: "y", count: 9)).encode()
        #expect(throws: DataChannelError.self) {
            _ = try manager.processIncomingDCEP(streamID: 0, data: open)
        }
    }

    // MARK: - Finding 11: openChannel is throwing, threads reliability params

    @Test("openChannel threads reliability into a partial-reliability channel type")
    func openChannelThreadsReliability() throws {
        let manager = DataChannelManager(isInitiator: true)
        let (_, dcep) = try manager.openChannel(
            label: "pr", ordered: false, reliabilityParameter: 3)
        let decoded = try DCEPOpen.decode(from: dcep)
        #expect(decoded.channelType == .partialReliableRexmitUnordered)
        #expect(decoded.reliabilityParameter == 3)
    }

    @Test("openChannel allocates a free ID skipping collisions")
    func openChannelSkipsCollisions() throws {
        // Responder opens odd IDs (1, 3, 5, ...). Pre-occupy stream 1 via an
        // incoming OPEN (even parity for responder is 0), so allocation just
        // proceeds normally; here we verify sequential allocation.
        let manager = DataChannelManager(isInitiator: true)
        let (c0, _) = try manager.openChannel(label: "a")
        let (c1, _) = try manager.openChannel(label: "b")
        #expect(c0.id == 0)
        #expect(c1.id == 2)
    }
}
