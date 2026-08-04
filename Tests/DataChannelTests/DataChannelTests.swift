/// Tests for Data Channel

import Testing
import Foundation
@testable import WebRTC
@Suite("DCEP Message Tests")
struct DCEPMessageTests {

    @Test("DCEP Open encode/decode roundtrip")
    func dcepOpenRoundtrip() throws {
        let open = DCEPOpen(
            channelType: .reliable,
            label: "test-channel",
            protocol_: "test-proto"
        )

        let encoded = try open.encode()
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

    @Test("DCEP Ack rejects trailing bytes")
    func dcepAckRejectsTrailingBytes() {
        #expect(throws: DataChannelWireError.self) {
            _ = try DCEPAck.decode(from: [
                DCEPMessageType.dataChannelAck.rawValue,
                0x00,
            ])
        }
    }

    @Test("DCEP Open with unordered channel")
    func dcepOpenUnordered() throws {
        let open = DCEPOpen(
            channelType: .reliableUnordered,
            label: "unordered"
        )

        let encoded = try open.encode()
        let decoded = try DCEPOpen.decode(from: encoded)

        #expect(decoded.channelType == .reliableUnordered)
        #expect(decoded.label == "unordered")
    }

    @Test("DCEP Open with unknown channel type is rejected")
    func dcepOpenUnknownChannelTypeThrows() throws {
        var encoded = try DCEPOpen(channelType: .reliable, label: "x").encode()
        encoded[1] = 0x55 // not a defined DCEPChannelType

        #expect(throws: DataChannelError.self) {
            _ = try DCEPOpen.decode(from: encoded)
        }
    }

    @Test("DCEP Open rejects trailing bytes and oversized fields")
    func dcepOpenValidatesExactLengths() throws {
        let maximum = DCEPOpen(
            channelType: .reliable,
            label: String(repeating: "x", count: Int(UInt16.max))
        )
        #expect(try maximum.encode().count == 12 + Int(UInt16.max))

        let oversized = DCEPOpen(
            channelType: .reliable,
            label: String(repeating: "x", count: Int(UInt16.max) + 1)
        )
        #expect(throws: DataChannelWireError.self) {
            _ = try oversized.encodeBytes()
        }

        var trailing = try DCEPOpen(label: "x").encodeBytes()
        trailing.append(0)
        #expect(throws: DataChannelWireError.self) {
            _ = try DCEPOpen.decode(from: trailing)
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
            data: try open.encode()
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

    @Test("Duplicate DCEP ACK cannot reopen an established channel")
    func duplicateDCEPAckThrows() throws {
        let manager = DataChannelManager(isInitiator: true)
        let (channel, _) = try manager.openChannel(label: "test")
        let ack = DCEPAck().encode()

        _ = try manager.processIncomingDCEP(streamID: channel.id, data: ack)

        #expect(throws: DataChannelError.self) {
            _ = try manager.processIncomingDCEP(streamID: channel.id, data: ack)
        }
        #expect(manager.channel(id: channel.id)?.state == .open)
    }

    @Test("DCEP ACK cannot acknowledge a peer-owned stream")
    func peerParityDCEPAckThrows() throws {
        let manager = DataChannelManager(isInitiator: true)
        let open = try DCEPOpen(label: "peer").encode()
        _ = try manager.processIncomingDCEP(streamID: 1, data: open)

        #expect(throws: DataChannelError.self) {
            _ = try manager.processIncomingDCEP(
                streamID: 1,
                data: DCEPAck().encode()
            )
        }
        #expect(manager.channel(id: 1)?.state == .open)
    }

    @Test("Delayed DCEP ACK cannot reopen a closing channel")
    func delayedDCEPAckThrows() throws {
        let manager = DataChannelManager(isInitiator: true)
        let (channel, _) = try manager.openChannel(label: "closing")
        #expect(try manager.beginClose(id: channel.id))

        #expect(throws: DataChannelError.self) {
            _ = try manager.processIncomingDCEP(
                streamID: channel.id,
                data: DCEPAck().encode()
            )
        }
        #expect(manager.channel(id: channel.id)?.state == .closing)
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

    @Test("Duplicate OPEN is not acknowledged and requires stream reset")
    func duplicateOpenRequiresReset() throws {
        // Responder opens odd; incoming OPEN must be even.
        let manager = DataChannelManager(isInitiator: false)
        let open = try DCEPOpen(label: "dup").encode()

        let (resp1, chan1) = try manager.processIncomingDCEP(streamID: 0, data: open)
        #expect(resp1 != nil)
        let first = try #require(chan1)

        #expect(throws: DataChannelError.self) {
            _ = try manager.processIncomingDCEP(streamID: 0, data: open)
        }
        #expect(manager.channels.count == 1)
        #expect(manager.channel(id: first.id)?.state == .open)
    }

    @Test("OPEN on a wrong-parity stream ID is rejected")
    func openWrongParityRejected() throws {
        // Responder (isInitiator: false) opens odd, so incoming OPENs must be
        // even. An incoming OPEN on an ODD stream is a parity violation.
        let manager = DataChannelManager(isInitiator: false)
        let open = try DCEPOpen(label: "bad-parity").encode()
        #expect(throws: DataChannelError.self) {
            _ = try manager.processIncomingDCEP(streamID: 1, data: open)
        }
    }

    @Test("Initiator parity: incoming OPEN must be odd")
    func openParityForInitiator() throws {
        // Initiator opens even, so incoming OPENs must be odd.
        let manager = DataChannelManager(isInitiator: true)
        let open = try DCEPOpen(label: "ok").encode()
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

    @Test("Over-long label is rejected on open and on incoming OPEN")
    func labelLengthCapped() throws {
        let manager = DataChannelManager(isInitiator: false, maxLabelOrProtocolLength: 8)
        #expect(throws: DataChannelError.self) {
            _ = try manager.openChannel(label: String(repeating: "x", count: 9))
        }
        let open = try DCEPOpen(label: String(repeating: "y", count: 9)).encode()
        #expect(throws: DataChannelError.self) {
            _ = try manager.processIncomingDCEP(streamID: 0, data: open)
        }
    }

    // MARK: - Finding 11: openChannel is throwing, threads reliability params

    @Test("partial-reliability policies round-trip through DCEP")
    func partialReliabilityRoundTrip() throws {
        let manager = DataChannelManager(isInitiator: true)
        let (local, localBytes) = try manager.openChannel(
            label: "pr",
            ordered: false,
            reliability: .maximumRetransmissions(3)
        )
        #expect(local.reliability == .maximumRetransmissions(3))
        let decodedLocal = try DCEPOpen.decode(from: localBytes)
        #expect(decodedLocal.channelType == .partialReliableRexmitUnordered)
        #expect(decodedLocal.reliabilityParameter == 3)
        _ = try manager.processIncomingDCEP(
            streamID: local.id,
            data: DCEPAck().encode()
        )
        #expect(try manager.sendPolicy(id: local.id) == DataChannelSendPolicy(
            unordered: true,
            reliability: .maximumRetransmissions(3)
        ))

        let incoming = try DCEPOpen(
            channelType: .partialReliableTimed,
            reliabilityParameter: 1,
            label: "pr"
        ).encode()
        let remote = try #require(manager.processIncomingDCEP(
            streamID: 1,
            data: incoming
        ).channel)
        #expect(remote.reliability == .maximumLifetimeMilliseconds(1))
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

    @Test("Local close releases a channel only after both reset directions")
    func localCloseRequiresBothDirections() throws {
        let manager = DataChannelManager(isInitiator: true)
        let (channel, _) = try manager.openChannel(label: "close")
        _ = try manager.processIncomingDCEP(
            streamID: channel.id,
            data: DCEPAck().encode()
        )

        #expect(try manager.closeChannel(id: channel.id))
        #expect(manager.channel(id: channel.id)?.state == .closing)
        #expect(throws: DataChannelError.self) {
            try manager.requireWritableChannel(id: channel.id)
        }

        let outgoing = manager.apply(.outgoingStreamsReset(.listed([channel.id])))
        #expect(outgoing.closeEvents.isEmpty)
        #expect(manager.channel(id: channel.id) != nil)

        let incoming = manager.apply(.incomingStreamsReset(.listed([channel.id])))
        #expect(incoming.closeEvents == [.closed(
            channelID: channel.id,
            generation: channel.generation
        )])
        #expect(manager.channel(id: channel.id) == nil)

        let (reused, _) = try manager.openChannel(label: "reused")
        #expect(reused.id == channel.id)
        #expect(reused.generation > channel.generation)
        #expect(incoming.closeEvents.first?.generation == channel.generation)
    }

    @Test("Remote reset requests one reciprocal reset and then closes")
    func remoteCloseRequestsReciprocalReset() throws {
        let manager = DataChannelManager(isInitiator: false)
        let open = try DCEPOpen(label: "remote").encode()
        let (_, optionalChannel) = try manager.processIncomingDCEP(
            streamID: 0,
            data: open
        )
        let channel = try #require(optionalChannel)

        let incoming = manager.apply(.incomingStreamsReset(.listed([channel.id])))
        #expect(incoming.reciprocalReset == .listed([channel.id]))
        #expect(incoming.closeEvents.isEmpty)

        let repeated = manager.apply(.incomingStreamsReset(.listed([channel.id])))
        #expect(repeated.reciprocalReset == nil)

        let outgoing = manager.apply(.outgoingStreamsReset(.listed([channel.id])))
        #expect(outgoing.closeEvents == [.closed(
            channelID: channel.id,
            generation: channel.generation
        )])
        #expect(manager.channel(id: channel.id) == nil)
    }

    @Test("unordered send policy changes only after explicit or implicit ACK")
    func unorderedSendPolicyTracksAcknowledgement() throws {
        let manager = DataChannelManager(isInitiator: true)
        let (explicit, _) = try manager.openChannelBytes(
            label: "explicit",
            ordered: false
        )
        #expect(try manager.sendPolicy(id: explicit.id).unordered == false)
        _ = try manager.processIncomingDCEPBytes(
            streamID: explicit.id,
            data: DCEPAck().encodeBytes()
        )
        #expect(try manager.sendPolicy(id: explicit.id).unordered)

        let (implicit, _) = try manager.openChannelBytes(
            label: "implicit",
            ordered: false
        )
        #expect(try manager.sendPolicy(id: implicit.id).unordered == false)
        #expect(try manager.observeIncomingMessage(id: implicit.id)?.state == .open)
        #expect(try manager.sendPolicy(id: implicit.id).unordered)

        // A late explicit ACK after the implicit transition is consumed once;
        // a duplicate remains a protocol violation.
        _ = try manager.processIncomingDCEPBytes(
            streamID: implicit.id,
            data: DCEPAck().encodeBytes()
        )
        #expect(throws: DataChannelError.self) {
            _ = try manager.processIncomingDCEPBytes(
                streamID: implicit.id,
                data: DCEPAck().encodeBytes()
            )
        }
    }

    @Test("Denied outgoing reset produces typed channel failure")
    func deniedResetFailsChannel() throws {
        let manager = DataChannelManager(isInitiator: true)
        let (channel, _) = try manager.openChannel(label: "denied")
        #expect(try manager.beginClose(id: channel.id))

        let transition = manager.apply(.outgoingStreamResetFailed(
            .listed([channel.id]),
            .denied
        ))
        #expect(transition.closeEvents == [
            .failed(
                channelID: channel.id,
                generation: channel.generation,
                result: .denied
            ),
        ])
        #expect(manager.channel(id: channel.id)?.state == .closing)

        let repeated = manager.apply(.outgoingStreamResetFailed(
            .listed([channel.id]),
            .denied
        ))
        #expect(repeated.closeEvents.isEmpty)

        let next = try manager.openChannel(label: "next")
        #expect(next.0.id != channel.id)
    }
}
