import Testing
@testable import WebRTC
@Suite("SCTP Monotonic Clock Tests")
struct SCTPMonotonicClockTests {
    @Test("Injected clock failure is returned by throwing facade operations")
    func throwingFacadePreservesClockFailure() {
        let association = SCTPAssociation(
            clock: FailingSCTPMonotonicClock(code: 17)
        )
        let packet = SCTPPacket(
            sourcePort: 5_000,
            destinationPort: 5_000,
            verificationTag: 0,
            chunks: []
        )

        do {
            _ = try association.processPacketBytes(packet)
            Issue.record("Expected the injected clock failure")
        } catch SCTPError.monotonicClockFailure(let code) {
            #expect(code == 17)
        } catch {
            Issue.record("Unexpected clock failure: \(error)")
        }
        #expect(association.state == .closed)
    }

    @Test("Injected clock failure is returned by Result facade operations")
    func resultFacadePreservesClockFailure() {
        let association = SCTPAssociation(
            clock: FailingSCTPMonotonicClock(code: 23)
        )

        switch association.pollOutboundPackets() {
        case .success:
            Issue.record("Expected the injected clock failure")
        case .failure(.monotonicClockFailure(let code)):
            #expect(code == 23)
        case .failure(let error):
            Issue.record("Unexpected clock failure: \(error)")
        }
        #expect(association.state == .closed)
    }

    @Test("Injected monotonic milliseconds drive the facade success path")
    func fixedClockDrivesSuccessPath() throws {
        let association = SCTPAssociation(
            clock: FixedSCTPMonotonicClock(milliseconds: 42)
        )

        let packets = try association.pollOutboundPackets().get()

        #expect(packets.isEmpty)
        #expect(association.state == .closed)
    }
}

private struct FailingSCTPMonotonicClock: SCTPMonotonicClock {
    let code: UInt32

    func currentMilliseconds() throws(SCTPError) -> UInt64 {
        throw .monotonicClockFailure(code: code)
    }
}

private struct FixedSCTPMonotonicClock: SCTPMonotonicClock {
    let milliseconds: UInt64

    func currentMilliseconds() throws(SCTPError) -> UInt64 {
        milliseconds
    }
}
