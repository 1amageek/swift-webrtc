import NetworkingCore
import WebRTC
import Synchronization

/// Thread-safe sequence and 90 kHz clock owner for one H.264 RTP stream.
public final class H264RTPSenderSession: H264RTPAccessUnitSending, Sendable {
    public let configuration: H264RTPSenderConfiguration

    private let state: Mutex<State>
    private let packetizer = RFC6184H264Packetizer()
    private let assembler = RFC6184H264RTPPacketAssembler()
    private let headerEncoder = RFC3550RTPHeaderEncoder()

    public init(configuration: H264RTPSenderConfiguration) {
        self.configuration = configuration
        self.state = Mutex(State(
            nextSequenceNumber: configuration.initialSequenceNumber,
            timestampAnchor: configuration.initialTimestamp
        ))
    }

    public func sendAccessUnit<SinkFailure>(
        _ accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>,
        captureTimeNanoseconds: UInt64,
        extensionProfile: UInt16?,
        extensionData: Span<UInt8>,
        sink: (consuming [UInt8]) -> Result<Void, SinkFailure>
    ) -> Result<H264RTPSendReport, H264RTPSendError<SinkFailure>>
    where SinkFailure: Error & Sendable {
        let maximumPayloadByteCount: Int
        do {
            maximumPayloadByteCount = try availablePayloadByteCount(
                extensionProfile: extensionProfile,
                extensionData: extensionData
            )
        } catch {
            return .failure(.sender(error))
        }
        var plannedPacketCount = 0
        do {
            _ = try packetizer.traversePackets(
                in: accessUnit,
                nalUnitRanges: nalUnitRanges,
                mode: configuration.packetizationMode,
                maximumPayloadByteCount: maximumPayloadByteCount
            ) { _ in
                plannedPacketCount += 1
                if plannedPacketCount > configuration.maximumPacketsPerAccessUnit {
                    return .stop
                }
                return .proceed
            }
        } catch {
            return .failure(.sender(.h264Payload(error)))
        }
        guard plannedPacketCount <= configuration.maximumPacketsPerAccessUnit else {
            return .failure(.sender(.accessUnitPacketLimitExceeded(
                minimumActual: plannedPacketCount,
                maximum: configuration.maximumPacketsPerAccessUnit
            )))
        }

        let reservation: Reservation
        do {
            reservation = try state.withLock { state throws(H264RTPSenderError) in
                try state.reserve(
                    packetCount: plannedPacketCount,
                    captureTimeNanoseconds: captureTimeNanoseconds
                )
            }
        } catch {
            return .failure(.sender(error))
        }
        defer {
            state.withLock { state in
                state.finishSend()
            }
        }

        var emittedPacketCount = 0
        var sentPacketCount = 0
        var plaintextByteCount = 0
        var emissionFailure: H264RTPSendError<SinkFailure>?

        do {
            _ = try packetizer.traversePackets(
                in: accessUnit,
                nalUnitRanges: nalUnitRanges,
                mode: configuration.packetizationMode,
                maximumPayloadByteCount: maximumPayloadByteCount
            ) { layout in
                guard emissionFailure == nil else { return .stop }
                guard emittedPacketCount < reservation.packetCount else {
                    emissionFailure = senderFailure(
                        .packetCountMismatch(
                            expected: reservation.packetCount,
                            actual: emittedPacketCount + 1
                        ),
                        sentPacketCount: sentPacketCount
                    )
                    return .stop
                }

                let sequenceNumber = reservation.firstSequenceNumber
                    &+ UInt16(truncatingIfNeeded: emittedPacketCount)
                let packetResult = assembledPacket(
                    header: H264RTPPacketHeader(
                        payloadType: configuration.payloadType,
                        sequenceNumber: sequenceNumber,
                        timestamp: reservation.timestamp,
                        synchronizationSource: configuration.synchronizationSource,
                        contributingSources: configuration.contributingSources
                    ),
                    payloadLayout: layout,
                    accessUnit: accessUnit,
                    nalUnitRanges: nalUnitRanges,
                    extensionProfile: extensionProfile,
                    extensionData: extensionData,
                    maximumDatagramByteCount:
                        configuration.maximumDatagramByteCount,
                    protectionTrailerByteCount:
                        configuration.protectionTrailerByteCount
                )
                let packet: [UInt8]
                switch consume packetResult {
                case .success(let assembledPacket):
                    packet = assembledPacket
                case .failure(let failure):
                    emissionFailure = senderFailure(
                        .packetAssembly(failure),
                        sentPacketCount: sentPacketCount
                    )
                    return .stop
                }

                emittedPacketCount += 1
                let (nextByteCount, byteCountOverflow) =
                    plaintextByteCount.addingReportingOverflow(packet.count)
                guard !byteCountOverflow else {
                    emissionFailure = senderFailure(
                        .byteCountOverflow,
                        sentPacketCount: sentPacketCount
                    )
                    return .stop
                }
                plaintextByteCount = nextByteCount

                switch sink(consume packet) {
                case .success:
                    sentPacketCount += 1
                    return .proceed
                case .failure(let failure):
                    emissionFailure = .sink(
                        failure,
                        sentPacketCount: sentPacketCount
                    )
                    return .stop
                }
            }
        } catch {
            return .failure(senderFailure(
                .h264Payload(error),
                sentPacketCount: sentPacketCount
            ))
        }

        if let emissionFailure {
            return .failure(emissionFailure)
        }
        guard emittedPacketCount == reservation.packetCount else {
            return .failure(senderFailure(
                .packetCountMismatch(
                    expected: reservation.packetCount,
                    actual: emittedPacketCount
                ),
                sentPacketCount: sentPacketCount
            ))
        }

        return .success(H264RTPSendReport(
            packetCount: sentPacketCount,
            plaintextByteCount: plaintextByteCount,
            firstSequenceNumber: reservation.firstSequenceNumber,
            lastSequenceNumber: reservation.firstSequenceNumber
                &+ UInt16(truncatingIfNeeded: reservation.packetCount - 1),
            timestamp: reservation.timestamp
        ))
    }

    private func availablePayloadByteCount(
        extensionProfile: UInt16?,
        extensionData: Span<UInt8>
    ) throws(H264RTPSenderError) -> Int {
        let header = RTPOutboundHeader(
            marker: false,
            payloadType: configuration.payloadType,
            sequenceNumber: configuration.initialSequenceNumber,
            timestamp: configuration.initialTimestamp,
            synchronizationSource: configuration.synchronizationSource,
            contributingSources: configuration.contributingSources
        )
        let headerByteCount: Int
        do {
            headerByteCount = try headerEncoder.headerByteCount(
                header,
                extensionProfile: extensionProfile,
                extensionData: extensionData
            )
        } catch {
            throw .rtpHeader(error)
        }
        let (overhead, overflow) = headerByteCount.addingReportingOverflow(
            configuration.protectionTrailerByteCount
        )
        guard !overflow,
              overhead < configuration.maximumDatagramByteCount else {
            throw .insufficientDatagramCapacity(
                headerAndTrailerByteCount: overflow ? Int.max : overhead,
                maximumDatagramByteCount: configuration.maximumDatagramByteCount
            )
        }
        return configuration.maximumDatagramByteCount - overhead
    }

    private func assembledPacket(
        header: H264RTPPacketHeader,
        payloadLayout: H264RTPPacketizationLayout,
        accessUnit: Span<UInt8>,
        nalUnitRanges: Span<Range<Int>>,
        extensionProfile: UInt16?,
        extensionData: Span<UInt8>,
        maximumDatagramByteCount: Int,
        protectionTrailerByteCount: Int
    ) -> Result<[UInt8], H264RTPPacketError> {
        do {
            return .success(try assembler.packet(
                header: header,
                payloadLayout: payloadLayout,
                accessUnit: accessUnit,
                nalUnitRanges: nalUnitRanges,
                extensionProfile: extensionProfile,
                extensionData: extensionData,
                maximumDatagramByteCount: maximumDatagramByteCount,
                protectionTrailerByteCount: protectionTrailerByteCount
            ))
        } catch {
            return .failure(error)
        }
    }

    private func senderFailure<SinkFailure>(
        _ failure: H264RTPSenderError,
        sentPacketCount: Int
    ) -> H264RTPSendError<SinkFailure>
    where SinkFailure: Error & Sendable {
        if sentPacketCount == 0 {
            return .sender(failure)
        }
        return .senderAfterPartialDelivery(
            failure,
            sentPacketCount: sentPacketCount
        )
    }

    private struct State: Sendable {
        var nextSequenceNumber: UInt16
        let timestampAnchor: UInt32
        var captureTimeAnchor: UInt64?
        var previousCaptureTime: UInt64?
        var isSending = false

        mutating func reserve(
            packetCount: Int,
            captureTimeNanoseconds: UInt64
        ) throws(H264RTPSenderError) -> Reservation {
            guard !isSending else {
                throw .sendInProgress
            }
            if let previousCaptureTime,
               captureTimeNanoseconds < previousCaptureTime {
                throw .decreasingCaptureTime(
                    previous: previousCaptureTime,
                    current: captureTimeNanoseconds
                )
            }
            let anchor: UInt64
            if let captureTimeAnchor {
                anchor = captureTimeAnchor
            } else {
                captureTimeAnchor = captureTimeNanoseconds
                anchor = captureTimeNanoseconds
            }

            let elapsed = captureTimeNanoseconds - anchor
            let wholeSeconds = UInt32(truncatingIfNeeded: elapsed / 1_000_000_000)
            let remainingNanoseconds = elapsed % 1_000_000_000
            let fractionalTicks = UInt32(
                (remainingNanoseconds * 90_000) / 1_000_000_000
            )
            let timestamp = timestampAnchor
                &+ (wholeSeconds &* 90_000)
                &+ fractionalTicks
            let firstSequenceNumber = nextSequenceNumber
            nextSequenceNumber &+= UInt16(truncatingIfNeeded: packetCount)
            previousCaptureTime = captureTimeNanoseconds
            isSending = true

            return Reservation(
                firstSequenceNumber: firstSequenceNumber,
                timestamp: timestamp,
                packetCount: packetCount
            )
        }

        mutating func finishSend() {
            isSending = false
        }
    }

    private struct Reservation: Sendable {
        let firstSequenceNumber: UInt16
        let timestamp: UInt32
        let packetCount: Int
    }
}
