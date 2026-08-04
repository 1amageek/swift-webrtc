@testable import WebRTCMedia
@testable import WebRTC
import Testing

@Suite("H.264 RTP sender session")
struct H264RTPSenderSessionTests {
    private enum SinkFailure: Error, Equatable, Sendable {
        case rejected
    }

    @Test("FU-A packets receive wrapping sequences and one 90 kHz timestamp")
    func fragmentationSequenceAndTimestamp() throws {
        let session = try session(initialSequenceNumber: .max, initialTimestamp: 123)
        let accessUnit: [UInt8] = [0x65, 1, 2, 3, 4, 5]
        let ranges = [0..<accessUnit.count]
        let noExtension: [UInt8] = []
        var packets: [[UInt8]] = []

        let result: Result<H264RTPSendReport, H264RTPSendError<SinkFailure>> =
            session.sendAccessUnit(
                accessUnit.span,
                nalUnitRanges: ranges.span,
                captureTimeNanoseconds: 1_000_000_000,
                extensionProfile: nil,
                extensionData: noExtension.span
            ) { packet in
                packets.append(packet)
                return .success(())
            }
        let report = try result.get()

        #expect(report.packetCount == 3)
        #expect(report.firstSequenceNumber == .max)
        #expect(report.lastSequenceNumber == 1)
        #expect(report.timestamp == 123)

        let parser = RFC3550RTPPacketParser()
        let layouts = try packets.map { try parser.layout(in: $0.span) }
        #expect(layouts.map(\.fixedHeader.sequenceNumber) == [.max, 0, 1])
        #expect(layouts.allSatisfy { $0.fixedHeader.timestamp == 123 })
        #expect(layouts.map(\.fixedHeader.marker) == [false, false, true])

        var secondPackets: [[UInt8]] = []
        let secondResult: Result<H264RTPSendReport, H264RTPSendError<SinkFailure>> =
            session.sendAccessUnit(
                accessUnit.span,
                nalUnitRanges: ranges.span,
                captureTimeNanoseconds: 2_000_000_000,
                extensionProfile: nil,
                extensionData: noExtension.span
            ) { packet in
                secondPackets.append(packet)
                return .success(())
            }
        let secondReport = try secondResult.get()
        #expect(secondReport.firstSequenceNumber == 2)
        #expect(secondReport.timestamp == 90_123)
    }

    @Test("Sink failure stops emission and reserved sequences remain burned")
    func sinkFailureStopsAndBurnsReservation() throws {
        let session = try session(initialSequenceNumber: 10, initialTimestamp: 20)
        let accessUnit: [UInt8] = [0x65, 1, 2, 3, 4, 5]
        let ranges = [0..<accessUnit.count]
        let noExtension: [UInt8] = []
        var attemptCount = 0

        let failed: Result<H264RTPSendReport, H264RTPSendError<SinkFailure>> =
            session.sendAccessUnit(
                accessUnit.span,
                nalUnitRanges: ranges.span,
                captureTimeNanoseconds: 100,
                extensionProfile: nil,
                extensionData: noExtension.span
            ) { _ in
                attemptCount += 1
                return attemptCount == 2 ? .failure(.rejected) : .success(())
            }
        #expect(failed == .failure(.sink(.rejected, sentPacketCount: 1)))
        #expect(attemptCount == 2)

        let oneNAL: [UInt8] = [0x61]
        let oneRange = [0..<1]
        var nextPacket: [UInt8]?
        let next: Result<H264RTPSendReport, H264RTPSendError<SinkFailure>> =
            session.sendAccessUnit(
                oneNAL.span,
                nalUnitRanges: oneRange.span,
                captureTimeNanoseconds: 101,
                extensionProfile: nil,
                extensionData: noExtension.span
            ) { packet in
                nextPacket = packet
                return .success(())
            }
        _ = try next.get()
        let packet = try #require(nextPacket)
        let layout = try RFC3550RTPPacketParser().layout(in: packet.span)
        #expect(layout.fixedHeader.sequenceNumber == 13)
    }

    @Test("A decreasing capture time fails before sequence reservation")
    func decreasingCaptureTimeFails() throws {
        let session = try session(initialSequenceNumber: 40, initialTimestamp: 50)
        let accessUnit: [UInt8] = [0x61]
        let ranges = [0..<1]
        let noExtension: [UInt8] = []

        let first: Result<H264RTPSendReport, H264RTPSendError<SinkFailure>> =
            session.sendAccessUnit(
                accessUnit.span,
                nalUnitRanges: ranges.span,
                captureTimeNanoseconds: 500,
                extensionProfile: nil,
                extensionData: noExtension.span
            ) { _ in .success(()) }
        _ = try first.get()

        var sinkCalled = false
        let decreasing: Result<H264RTPSendReport, H264RTPSendError<SinkFailure>> =
            session.sendAccessUnit(
                accessUnit.span,
                nalUnitRanges: ranges.span,
                captureTimeNanoseconds: 499,
                extensionProfile: nil,
                extensionData: noExtension.span
            ) { _ in
                sinkCalled = true
                return .success(())
            }
        #expect(decreasing == .failure(.sender(.decreasingCaptureTime(
            previous: 500,
            current: 499
        ))))
        #expect(!sinkCalled)

        var acceptedPacket: [UInt8]?
        let next: Result<H264RTPSendReport, H264RTPSendError<SinkFailure>> =
            session.sendAccessUnit(
                accessUnit.span,
                nalUnitRanges: ranges.span,
                captureTimeNanoseconds: 500,
                extensionProfile: nil,
                extensionData: noExtension.span
            ) { packet in
                acceptedPacket = packet
                return .success(())
            }
        _ = try next.get()
        let packet = try #require(acceptedPacket)
        let layout = try RFC3550RTPPacketParser().layout(in: packet.span)
        #expect(layout.fixedHeader.sequenceNumber == 41)
    }

    @Test("Reentrant emission is rejected without releasing the active send")
    func reentrantEmissionIsRejected() throws {
        let session = try session(initialSequenceNumber: 10, initialTimestamp: 20)
        let accessUnit: [UInt8] = [0x65, 1, 2, 3, 4, 5]
        let ranges = [0..<accessUnit.count]
        let invalidAccessUnit: [UInt8] = [0x80]
        let oneNAL: [UInt8] = [0x61]
        let oneRange = [0..<1]
        let noExtension: [UInt8] = []
        var invalidNestedResult: Result<
            H264RTPSendReport,
            H264RTPSendError<SinkFailure>
        >?
        var validNestedResult: Result<
            H264RTPSendReport,
            H264RTPSendError<SinkFailure>
        >?

        let outer: Result<H264RTPSendReport, H264RTPSendError<SinkFailure>> =
            session.sendAccessUnit(
                accessUnit.span,
                nalUnitRanges: ranges.span,
                captureTimeNanoseconds: 100,
                extensionProfile: nil,
                extensionData: noExtension.span
            ) { _ in
                guard invalidNestedResult == nil else {
                    return .success(())
                }
                invalidNestedResult = session.sendAccessUnit(
                    invalidAccessUnit.span,
                    nalUnitRanges: oneRange.span,
                    captureTimeNanoseconds: 100,
                    extensionProfile: nil,
                    extensionData: noExtension.span
                ) { _ in .success(()) }
                validNestedResult = session.sendAccessUnit(
                    oneNAL.span,
                    nalUnitRanges: oneRange.span,
                    captureTimeNanoseconds: 100,
                    extensionProfile: nil,
                    extensionData: noExtension.span
                ) { _ in .success(()) }
                return .success(())
            }

        #expect(try outer.get().packetCount == 3)
        #expect(invalidNestedResult == .failure(.sender(.h264Payload(.forbiddenBitSet))))
        #expect(validNestedResult == .failure(.sender(.sendInProgress)))

        var nextPacket: [UInt8]?
        let next: Result<H264RTPSendReport, H264RTPSendError<SinkFailure>> =
            session.sendAccessUnit(
                oneNAL.span,
                nalUnitRanges: oneRange.span,
                captureTimeNanoseconds: 101,
                extensionProfile: nil,
                extensionData: noExtension.span
            ) { packet in
                nextPacket = packet
                return .success(())
            }
        _ = try next.get()
        let packet = try #require(nextPacket)
        let layout = try RFC3550RTPPacketParser().layout(in: packet.span)
        #expect(layout.fixedHeader.sequenceNumber == 13)
    }

    @Test("Header and SRTP overhead must leave payload capacity")
    func insufficientCapacityFails() throws {
        let configuration = try H264RTPSenderConfiguration(
            payloadType: 96,
            synchronizationSource: 1,
            maximumDatagramByteCount: 22,
            protectionTrailerByteCount: 10,
            initialSequenceNumber: 0,
            initialTimestamp: 0
        )
        let session = H264RTPSenderSession(configuration: configuration)
        let accessUnit: [UInt8] = [0x61]
        let ranges = [0..<1]
        let noExtension: [UInt8] = []

        let result: Result<H264RTPSendReport, H264RTPSendError<SinkFailure>> =
            session.sendAccessUnit(
                accessUnit.span,
                nalUnitRanges: ranges.span,
                captureTimeNanoseconds: 0,
                extensionProfile: nil,
                extensionData: noExtension.span
            ) { _ in .success(()) }
        #expect(result == .failure(.sender(.insufficientDatagramCapacity(
            headerAndTrailerByteCount: 22,
            maximumDatagramByteCount: 22
        ))))
    }

    @Test("Access-unit packet limit fails before reservation or sink emission")
    func accessUnitPacketLimitFailsTransactionally() throws {
        let configuration = try H264RTPSenderConfiguration(
            payloadType: 96,
            synchronizationSource: 7,
            maximumDatagramByteCount: 26,
            protectionTrailerByteCount: 10,
            maximumPacketsPerAccessUnit: 2,
            initialSequenceNumber: 10,
            initialTimestamp: 20
        )
        let session = H264RTPSenderSession(configuration: configuration)
        let accessUnit: [UInt8] = [0x65, 1, 2, 3, 4, 5]
        let ranges = [0..<accessUnit.count]
        let noExtension: [UInt8] = []
        var sinkCalled = false

        let result: Result<H264RTPSendReport, H264RTPSendError<SinkFailure>> =
            session.sendAccessUnit(
                accessUnit.span,
                nalUnitRanges: ranges.span,
                captureTimeNanoseconds: 0,
                extensionProfile: nil,
                extensionData: noExtension.span
            ) { _ in
                sinkCalled = true
                return .success(())
            }
        #expect(result == .failure(.sender(.accessUnitPacketLimitExceeded(
            minimumActual: 3,
            maximum: 2
        ))))
        #expect(!sinkCalled)

        let oneNAL: [UInt8] = [0x61]
        let oneRange = [0..<1]
        var acceptedPacket: [UInt8]?
        let next: Result<H264RTPSendReport, H264RTPSendError<SinkFailure>> =
            session.sendAccessUnit(
                oneNAL.span,
                nalUnitRanges: oneRange.span,
                captureTimeNanoseconds: 0,
                extensionProfile: nil,
                extensionData: noExtension.span
            ) { packet in
                acceptedPacket = packet
                return .success(())
            }
        _ = try next.get()
        let packet = try #require(acceptedPacket)
        let layout = try RFC3550RTPPacketParser().layout(in: packet.span)
        #expect(layout.fixedHeader.sequenceNumber == 10)
    }

    @Test("Consuming sink retains packet storage while appending reserved trailer")
    func consumingSinkRetainsPacketStorage() throws {
        let session = try session(initialSequenceNumber: 1, initialTimestamp: 2)
        let accessUnit: [UInt8] = [0x61, 1, 2]
        let ranges = [0..<accessUnit.count]
        let noExtension: [UInt8] = []
        var retainedStorage = false

        let result: Result<H264RTPSendReport, H264RTPSendError<SinkFailure>> =
            session.sendAccessUnit(
                accessUnit.span,
                nalUnitRanges: ranges.span,
                captureTimeNanoseconds: 0,
                extensionProfile: nil,
                extensionData: noExtension.span
            ) { packet in
                var protectedPacket = consume packet
                let addressBefore = protectedPacket.withUnsafeBufferPointer {
                    UInt(bitPattern: $0.baseAddress)
                }
                for _ in 0..<10 {
                    protectedPacket.append(0)
                }
                let addressAfter = protectedPacket.withUnsafeBufferPointer {
                    UInt(bitPattern: $0.baseAddress)
                }
                retainedStorage = addressBefore == addressAfter
                return .success(())
            }
        _ = try result.get()
        #expect(retainedStorage)
    }

    @Test("Packet reservation cannot span RTP half-sequence-space")
    func packetReservationLimitIsValidated() {
        #expect(throws: H264RTPSenderError.invalidMaximumPacketsPerAccessUnit(
            actual: H264RTPSenderConfiguration.largestSequenceSafePacketCount + 1
        )) {
            _ = try H264RTPSenderConfiguration(
                payloadType: 96,
                synchronizationSource: 1,
                protectionTrailerByteCount: 10,
                maximumPacketsPerAccessUnit:
                    H264RTPSenderConfiguration.largestSequenceSafePacketCount + 1,
                initialSequenceNumber: 0,
                initialTimestamp: 0
            )
        }
    }

    @Test("Unsupported interleaved mode fails during configuration")
    func interleavedModeFailsDuringConfiguration() {
        #expect(throws: H264RTPSenderError.unsupportedPacketizationMode(
            .interleaved
        )) {
            _ = try H264RTPSenderConfiguration(
                payloadType: 96,
                synchronizationSource: 1,
                packetizationMode: .interleaved,
                protectionTrailerByteCount: 10,
                initialSequenceNumber: 0,
                initialTimestamp: 0
            )
        }
    }

    private func session(
        initialSequenceNumber: UInt16,
        initialTimestamp: UInt32
    ) throws -> H264RTPSenderSession {
        let configuration = try H264RTPSenderConfiguration(
            payloadType: 96,
            synchronizationSource: 7,
            maximumDatagramByteCount: 26,
            protectionTrailerByteCount: 10,
            initialSequenceNumber: initialSequenceNumber,
            initialTimestamp: initialTimestamp
        )
        return H264RTPSenderSession(configuration: configuration)
    }
}
