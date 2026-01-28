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
}

@Suite("DataChannelManager Tests")
struct DataChannelManagerTests {

    @Test("Open channel as initiator")
    func openChannelInitiator() {
        let manager = DataChannelManager(isInitiator: true)
        let (channel, dcepData) = manager.openChannel(label: "test")

        #expect(channel.id == 0) // Even for initiator
        #expect(channel.label == "test")
        #expect(channel.state == .connecting)
        #expect(!dcepData.isEmpty)
    }

    @Test("Open channel as responder")
    func openChannelResponder() {
        let manager = DataChannelManager(isInitiator: false)
        let (channel, _) = manager.openChannel(label: "test")

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
        let (channel, _) = manager.openChannel(label: "test")

        let ack = DCEPAck()
        let (response, _) = try manager.processIncomingDCEP(
            streamID: channel.id,
            data: ack.encode()
        )

        #expect(response == nil) // No response to ACK
        #expect(manager.channel(id: channel.id)?.state == .open)
    }
}
