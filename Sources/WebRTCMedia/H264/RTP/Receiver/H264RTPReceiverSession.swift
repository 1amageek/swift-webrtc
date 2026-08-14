import NetworkingCore
import WebRTC
import Synchronization

/// Thread-safe bounded receiver state for one negotiated H.264 RTP stream.
public final class H264RTPReceiverSession: H264RTPPacketReceiving, Sendable {
    public let configuration: H264RTPReceiverConfiguration

    private let state = Mutex(State())
    private let payloadParser = RFC6184H264PayloadParser()
    private let rtpParser = RFC3550RTPPacketParser()

    public init(configuration: H264RTPReceiverConfiguration) {
        self.configuration = configuration
    }

    public func receive<SinkFailure>(
        _ packet: consuming [UInt8],
        layout: RTPPacketLayout,
        arrivalTimeNanoseconds: UInt64,
        sink: (consuming H264RTPAccessUnit) -> Result<Void, SinkFailure>
    ) -> Result<H264RTPReceiveReport, H264RTPReceiveError<SinkFailure>>
    where SinkFailure: Error & Sendable {
        let preparedPacket: BufferedPacket
        do {
            preparedPacket = try makeValidatedPacket(
                packet,
                layout: layout,
                arrivalTimeNanoseconds: arrivalTimeNanoseconds
            )
        } catch {
            return .failure(.receiver(error))
        }

        let firstStep: ProcessingStep
        do {
            firstStep = try state.withLock { state throws(ReceiverProcessingFailure) in
                try state.startAccepting(
                    preparedPacket,
                    configuration: configuration
                )
            }
        } catch {
            return .failure(Self.receiveError(from: error))
        }
        return deliver(firstStep, sink: sink)
    }

    public func advanceTime<SinkFailure>(
        to timeNanoseconds: UInt64,
        sink: (consuming H264RTPAccessUnit) -> Result<Void, SinkFailure>
    ) -> Result<H264RTPReceiveReport, H264RTPReceiveError<SinkFailure>>
    where SinkFailure: Error & Sendable {
        let firstStep: ProcessingStep
        do {
            firstStep = try state.withLock { state throws(ReceiverProcessingFailure) in
                try state.startAdvancingTime(
                    to: timeNanoseconds,
                    configuration: configuration
                )
            }
        } catch {
            return .failure(Self.receiveError(from: error))
        }
        return deliver(firstStep, sink: sink)
    }

    private func makeValidatedPacket(
        _ packet: consuming [UInt8],
        layout: RTPPacketLayout,
        arrivalTimeNanoseconds: UInt64
    ) throws(H264RTPReceiverError) -> BufferedPacket {
        guard layout.packetLength == packet.count else {
            throw .packetOwnerByteCountMismatch(
                expected: layout.packetLength,
                actual: packet.count
            )
        }
        let reparsedLayout: RTPPacketLayout
        do {
            reparsedLayout = try rtpParser.layout(in: packet.span)
        } catch {
            throw .rtpWire(error)
        }
        guard reparsedLayout == layout else {
            throw .packetLayoutOwnerMismatch
        }
        guard packet.count <= configuration.maximumPacketByteCount else {
            throw .packetExceedsMaximum(
                actual: packet.count,
                maximum: configuration.maximumPacketByteCount
            )
        }
        let fixedHeader = layout.fixedHeader
        guard fixedHeader.payloadType == configuration.payloadType else {
            throw .unexpectedPayloadType(
                expected: configuration.payloadType,
                actual: fixedHeader.payloadType
            )
        }
        guard fixedHeader.synchronizationSource == configuration.synchronizationSource else {
            throw .unexpectedSynchronizationSource(
                expected: configuration.synchronizationSource,
                actual: fixedHeader.synchronizationSource
            )
        }
        guard layout.payloadRange.lowerBound >= 0,
              layout.payloadRange.upperBound <= packet.count else {
            throw .invalidPayloadRange
        }

        let payloadLayout: H264RTPPayloadLayout
        do {
            payloadLayout = try payloadParser.layout(
                in: packet.span.extracting(layout.payloadRange),
                mode: configuration.packetizationMode
            )
        } catch {
            throw .h264Payload(error)
        }
        return BufferedPacket(
            bytes: packet,
            rtpLayout: layout,
            h264Layout: payloadLayout,
            arrivalTimeNanoseconds: arrivalTimeNanoseconds
        )
    }

    private func deliver<SinkFailure>(
        _ firstStep: consuming ProcessingStep,
        sink: (consuming H264RTPAccessUnit) -> Result<Void, SinkFailure>
    ) -> Result<H264RTPReceiveReport, H264RTPReceiveError<SinkFailure>>
    where SinkFailure: Error & Sendable {
        var step = firstStep
        while true {
            switch step {
            case .finished(let report):
                return .success(report)

            case .deliver(let plan):
                let reconstructedByteCount = plan.outputByteCount
                let accessUnit = plan.materialized(
                    format: configuration.accessUnitFormat
                )
                switch sink(consume accessUnit) {
                case .success:
                    do {
                        step = try state.withLock {
                            state throws(ReceiverProcessingFailure) in
                            try state.resumeAfterDelivery(
                                reconstructedByteCount: reconstructedByteCount,
                                configuration: configuration
                            )
                        }
                    } catch {
                        return .failure(Self.receiveError(from: error))
                    }

                case .failure(let failure):
                    let effects = state.withLock { state in
                        state.abortAfterSinkFailure(
                            reconstructedByteCount: reconstructedByteCount
                        )
                    }
                    return .failure(.sink(failure, effects: effects))
                }
            }
        }
    }

    private static func receiveError<SinkFailure>(
        from failure: ReceiverProcessingFailure
    ) -> H264RTPReceiveError<SinkFailure>
    where SinkFailure: Error & Sendable {
        guard let effects = failure.effects else {
            return .receiver(failure.cause)
        }
        return .receiverAfterProgress(failure.cause, effects: effects)
    }
}

private struct BufferedPacket: Sendable {
    let bytes: [UInt8]
    let rtpLayout: RTPPacketLayout
    let h264Layout: H264RTPPayloadLayout
    let arrivalTimeNanoseconds: UInt64

    var sequenceNumber: UInt16 { rtpLayout.fixedHeader.sequenceNumber }
    var timestamp: UInt32 { rtpLayout.fixedHeader.timestamp }
    var marker: Bool { rtpLayout.fixedHeader.marker }
}

private struct ReceiverProcessingFailure: Error, Sendable {
    let cause: H264RTPReceiverError
    let effects: H264RTPReceiveReport?
}

private enum ProcessingStep: Sendable {
    case deliver(H264RTPAccessUnitPlan)
    case finished(H264RTPReceiveReport)
}

private enum StateProgress: Sendable {
    case deliver(H264RTPAccessUnitPlan)
    case idle
}

private struct OperationEffects: Sendable {
    var disposition: H264RTPPacketDisposition
    var deliveredAccessUnitCount = 0
    var declaredLostPacketCount = 0
    var discardedAccessUnitCount = 0
    var discardedPacketCount = 0
    var discardedPacketByteCount: UInt64 = 0
    var reconstructedByteCount: UInt64 = 0

    mutating func promoteDisposition(
        _ candidate: H264RTPPacketDisposition
    ) {
        if Self.priority(of: candidate) > Self.priority(of: disposition) {
            disposition = candidate
        }
    }

    private static func priority(
        of disposition: H264RTPPacketDisposition
    ) -> Int {
        switch disposition {
        case .processed, .clockAdvanced:
            return 0
        case .buffered, .duplicateOrLate:
            return 1
        case .accessUnitTimedOut:
            return 2
        case .resynchronized:
            return 3
        }
    }
}

private struct TimestampQuarantine: Sendable {
    let timestamp: UInt32
    var wasAlreadyCounted: Bool
    var observedPacket = false
}

private enum OrderedPacketResult: Sendable {
    case consumed
    case completed(H264RTPAccessUnitPlan, consumedPacket: Bool)
}

private struct State: Sendable {
    private var expectedSequenceNumber: UInt16?
    private var expectedExtendedSequenceNumber: UInt64?
    private var reorderPackets = H264RTPReorderPacketIndex<BufferedPacket>()
    private var gapStartedAtNanoseconds: UInt64?
    private var gapExpectedSequenceNumber: UInt16?
    private var lastObservedTimeNanoseconds: UInt64?
    private var accessUnit: H264RTPAccessUnitAssembly?
    private var deferredOrderedPacket: BufferedPacket?
    private var quarantine: TimestampQuarantine?
    private var completedTimestamp: UInt32?
    private var mustQuarantineNextTimestamp = false
    private var alreadyCountedQuarantineTimestamp: UInt32?
    private var mustFlushQueueAfterFailure = false
    private var operation: OperationEffects?

    mutating func startAccepting(
        _ packet: consuming BufferedPacket,
        configuration: H264RTPReceiverConfiguration
    ) throws(ReceiverProcessingFailure) -> ProcessingStep {
        guard operation == nil else {
            throw ReceiverProcessingFailure(
                cause: .receiveInProgress,
                effects: nil
            )
        }
        operation = OperationEffects(disposition: .processed)

        do {
            try observeTime(packet.arrivalTimeNanoseconds)
            if mustQuarantineNextTimestamp {
                quarantine = TimestampQuarantine(
                    timestamp: packet.timestamp,
                    wasAlreadyCounted:
                        alreadyCountedQuarantineTimestamp == packet.timestamp
                )
                mustQuarantineNextTimestamp = false
                alreadyCountedQuarantineTimestamp = nil
            }
            let progress = try acceptAfterAdvancingDeadlines(
                packet,
                configuration: configuration
            )
            return try finishedStep(
                after: progress,
                configuration: configuration
            )
        } catch {
            throw terminateAfterProcessingFailure(
                error,
                damagedTimestamp: nil
            )
        }
    }

    mutating func startAdvancingTime(
        to timeNanoseconds: UInt64,
        configuration: H264RTPReceiverConfiguration
    ) throws(ReceiverProcessingFailure) -> ProcessingStep {
        guard operation == nil else {
            throw ReceiverProcessingFailure(
                cause: .receiveInProgress,
                effects: nil
            )
        }
        operation = OperationEffects(disposition: .clockAdvanced)

        do throws(H264RTPReceiverError) {
            try observeTime(timeNanoseconds)
            let progress = try settleExpiredState(configuration: configuration)
            return finishOrDeliver(progress)
        } catch {
            throw terminateAfterProcessingFailure(error, damagedTimestamp: nil)
        }
    }

    mutating func resumeAfterDelivery(
        reconstructedByteCount: Int,
        configuration: H264RTPReceiverConfiguration
    ) throws(ReceiverProcessingFailure) -> ProcessingStep {
        guard operation != nil else {
            throw ReceiverProcessingFailure(
                cause: .receiveInProgress,
                effects: nil
            )
        }
        operation?.deliveredAccessUnitCount += 1
        operation?.reconstructedByteCount += UInt64(reconstructedByteCount)

        do {
            let progress = try processAvailablePacket(
                configuration: configuration
            )
            return try finishedStep(
                after: progress,
                configuration: configuration
            )
        } catch {
            throw terminateAfterProcessingFailure(error, damagedTimestamp: nil)
        }
    }

    mutating func abortAfterSinkFailure(
        reconstructedByteCount: Int
    ) -> H264RTPReceiveReport {
        operation?.reconstructedByteCount += UInt64(reconstructedByteCount)
        operation?.discardedAccessUnitCount += 1

        if accessUnit != nil {
            accessUnit = nil
            operation?.discardedAccessUnitCount += 1
        }
        discardQueuedPackets()
        expectedSequenceNumber = nil
        expectedExtendedSequenceNumber = nil
        quarantine = nil
        completedTimestamp = nil
        mustQuarantineNextTimestamp = true
        alreadyCountedQuarantineTimestamp = nil

        let effects = report()
        operation = nil
        return effects
    }

    private mutating func acceptAfterAdvancingDeadlines(
        _ packet: consuming BufferedPacket,
        configuration: H264RTPReceiverConfiguration
    ) throws(H264RTPReceiverError) -> StateProgress {
        if try gapHasExpired(
            at: packet.arrivalTimeNanoseconds,
            maximumDelay: configuration.maximumReorderDelayNanoseconds
        ) {
            return try admitForExpiredGap(
                packet,
                configuration: configuration
            )
        }

        try expireActiveAccessUnitIfNeeded(
            at: packet.arrivalTimeNanoseconds,
            configuration: configuration
        )
        return try acceptDuringOperation(
            packet,
            configuration: configuration
        )
    }

    /// Admits only packets that remain useful after the current gap deadline.
    /// The missing expected packet is already late at the exact deadline and is
    /// deliberately not retained. A later packet may join the bounded reorder
    /// owner set before recovery so contiguous data is not discarded needlessly.
    private mutating func admitForExpiredGap(
        _ packet: consuming BufferedPacket,
        configuration: H264RTPReceiverConfiguration
    ) throws(H264RTPReceiverError) -> StateProgress {
        guard let expectedSequenceNumber else {
            return try acceptDuringOperation(
                packet,
                configuration: configuration
            )
        }
        let distance = Self.forwardDistance(
            from: expectedSequenceNumber,
            to: packet.sequenceNumber
        )
        guard distance > 0, distance < 32_768 else {
            return .idle
        }
        guard !reorderPackets.contains(sequenceNumber: packet.sequenceNumber) else {
            return .idle
        }

        let (nextByteCount, byteOverflow) =
            reorderPackets.byteCount.addingReportingOverflow(packet.bytes.count)
        let exceedsWindow = distance > configuration.maximumReorderPacketCount
        let exceedsCount =
            reorderPackets.count >= configuration.maximumReorderPacketCount
        let exceedsBytes = byteOverflow
            || nextByteCount > configuration.maximumReorderByteCount
        if exceedsWindow || exceedsCount || exceedsBytes {
            return try recoverAdmissionPressure(
                packet,
                distance: distance,
                configuration: configuration
            )
        }

        try insertBuffered(packet)
        return .idle
    }

    /// Advances every deadline observable at the current monotonic time until
    /// the state reaches a fixpoint or an access unit must leave the mutex for
    /// delivery. Re-entry after delivery resumes the same convergence loop.
    private mutating func settleExpiredState(
        configuration: H264RTPReceiverConfiguration
    ) throws(H264RTPReceiverError) -> StateProgress {
        guard let observationTime = lastObservedTimeNanoseconds else {
            throw .integerOverflow
        }
        while true {
            updateGapAfterProgress()
            if try gapHasExpired(
                at: observationTime,
                maximumDelay: configuration.maximumReorderDelayNanoseconds
            ) {
                switch try recoverExpiredGap(configuration: configuration) {
                case .deliver(let plan):
                    return .deliver(plan)
                case .idle:
                    continue
                }
            }

            if try expireActiveAccessUnitIfNeeded(
                at: observationTime,
                configuration: configuration
            ) {
                continue
            }
            return .idle
        }
    }

    @discardableResult
    private mutating func expireActiveAccessUnitIfNeeded(
        at timeNanoseconds: UInt64,
        configuration: H264RTPReceiverConfiguration
    ) throws(H264RTPReceiverError) -> Bool {
        guard let active = accessUnit else { return false }
        let (elapsed, underflow) = timeNanoseconds
            .subtractingReportingOverflow(active.startedAtNanoseconds)
        guard !underflow else { throw .integerOverflow }
        guard elapsed > configuration.maximumAccessUnitDurationNanoseconds else {
            return false
        }

        let discarded = beginQuarantine(
            nextPacketTimestamp: active.timestamp
        )
        operation?.discardedAccessUnitCount += discarded
        operation?.promoteDisposition(.accessUnitTimedOut)
        return true
    }

    private mutating func acceptDuringOperation(
        _ packet: consuming BufferedPacket,
        configuration: H264RTPReceiverConfiguration
    ) throws(H264RTPReceiverError) -> StateProgress {
        guard deferredOrderedPacket == nil else {
            // A deferred packet exists only while an access unit is being
            // delivered. Public re-entry is rejected before reaching here.
            throw .receiveInProgress
        }
        guard let expectedSequenceNumber else {
            self.expectedSequenceNumber = packet.sequenceNumber
            self.expectedExtendedSequenceNumber = 0
            return try processAvailablePacket(
                startingWith: packet,
                configuration: configuration
            )
        }

        let distance = Self.forwardDistance(
            from: expectedSequenceNumber,
            to: packet.sequenceNumber
        )
        if distance == 0 {
            return try processAvailablePacket(
                startingWith: packet,
                configuration: configuration
            )
        }
        guard distance < 32_768 else {
            operation?.promoteDisposition(.duplicateOrLate)
            return .idle
        }
        guard !reorderPackets.contains(sequenceNumber: packet.sequenceNumber) else {
            operation?.promoteDisposition(.duplicateOrLate)
            return .idle
        }

        let (nextByteCount, byteOverflow) =
            reorderPackets.byteCount.addingReportingOverflow(packet.bytes.count)
        let exceedsWindow = distance > configuration.maximumReorderPacketCount
        let exceedsCount =
            reorderPackets.count >= configuration.maximumReorderPacketCount
        let exceedsBytes = byteOverflow
            || nextByteCount > configuration.maximumReorderByteCount
        if exceedsWindow || exceedsCount || exceedsBytes {
            return try recoverAdmissionPressure(
                packet,
                distance: distance,
                configuration: configuration
            )
        }

        let arrivalTimeNanoseconds = packet.arrivalTimeNanoseconds
        try insertBuffered(packet)
        updateGapAfterProgress(fallbackTimeNanoseconds: arrivalTimeNanoseconds)
        operation?.promoteDisposition(.buffered)
        return .idle
    }

    private mutating func recoverAdmissionPressure(
        _ incomingPacket: consuming BufferedPacket,
        distance incomingDistance: Int,
        configuration: H264RTPReceiverConfiguration
    ) throws(H264RTPReceiverError) -> StateProgress {
        guard expectedSequenceNumber != nil,
              let expectedExtendedSequenceNumber else {
            throw .integerOverflow
        }
        let incomingExtendedSequenceNumber = try extendedSequenceNumber(
            distance: incomingDistance
        )
        let earliestExisting = reorderPackets.earliestMetadata()
        let existingDistance: Int?
        if let earliestExisting {
            let (distance, underflow) = earliestExisting.extendedSequenceNumber
                .subtractingReportingOverflow(expectedExtendedSequenceNumber)
            guard !underflow, distance <= UInt64(Int.max) else {
                throw .integerOverflow
            }
            existingDistance = Int(distance)
        } else {
            existingDistance = nil
        }

        let recoveryPacket: BufferedPacket
        let recoveryExtendedSequenceNumber: UInt64
        let lostPacketCount: Int
        if let earliestExisting,
           let existingDistance,
           existingDistance < incomingDistance,
           let buffered = reorderPackets.remove(
                sequenceNumber: earliestExisting.sequenceNumber
           ) {
            recoveryPacket = buffered.packet
            recoveryExtendedSequenceNumber = buffered.extendedSequenceNumber
            lostPacketCount = existingDistance
            try makeRoomAndInsert(
                incomingPacket,
                configuration: configuration
            )
        } else {
            recoveryPacket = incomingPacket
            recoveryExtendedSequenceNumber = incomingExtendedSequenceNumber
            lostPacketCount = incomingDistance
        }

        operation?.promoteDisposition(.resynchronized)
        operation?.declaredLostPacketCount += lostPacketCount
        let discardedAccessUnitCount = beginQuarantine(
            nextPacketTimestamp: recoveryPacket.timestamp
        )
        operation?.discardedAccessUnitCount += discardedAccessUnitCount
        self.expectedSequenceNumber = recoveryPacket.sequenceNumber
        self.expectedExtendedSequenceNumber = recoveryExtendedSequenceNumber
        return try processAvailablePacket(
            startingWith: recoveryPacket,
            configuration: configuration
        )
    }

    private mutating func recoverExpiredGap(
        configuration: H264RTPReceiverConfiguration
    ) throws(H264RTPReceiverError) -> StateProgress {
        guard let expectedExtendedSequenceNumber,
              let indexedPacket = reorderPackets.removeEarliest() else {
            gapStartedAtNanoseconds = nil
            gapExpectedSequenceNumber = nil
            return .idle
        }

        let (distance, underflow) = indexedPacket.extendedSequenceNumber
            .subtractingReportingOverflow(expectedExtendedSequenceNumber)
        guard !underflow, distance <= UInt64(Int.max) else {
            throw .integerOverflow
        }
        let lostPacketCount = Int(distance)
        let packet = indexedPacket.packet
        operation?.promoteDisposition(.resynchronized)
        operation?.declaredLostPacketCount += lostPacketCount
        let discardedAccessUnitCount = beginQuarantine(
            nextPacketTimestamp: packet.timestamp
        )
        operation?.discardedAccessUnitCount += discardedAccessUnitCount
        self.expectedSequenceNumber = packet.sequenceNumber
        self.expectedExtendedSequenceNumber =
            indexedPacket.extendedSequenceNumber
        return try processAvailablePacket(
            startingWith: packet,
            configuration: configuration
        )
    }

    private mutating func processAvailablePacket(
        startingWith firstPacket: consuming BufferedPacket? = nil,
        configuration: H264RTPReceiverConfiguration
    ) throws(H264RTPReceiverError) -> StateProgress {
        var packet = firstPacket ?? takeDeferredPacket()
        if packet == nil {
            packet = try takeExpectedBufferedPacket()
        }

        while let currentPacket = packet {
            let result: OrderedPacketResult
            do {
                result = try processOrderedPacket(
                    currentPacket,
                    configuration: configuration
                )
            } catch {
                try advanceExpectedSequence(
                    after: currentPacket.sequenceNumber
                )
                let discardedAccessUnitCount =
                    beginProcessingFailureQuarantine(
                    nextPacketTimestamp: currentPacket.timestamp
                )
                operation?.discardedAccessUnitCount += discardedAccessUnitCount
                mustFlushQueueAfterFailure = true
                throw error
            }

            switch result {
            case .consumed:
                try advanceExpectedSequence(
                    after: currentPacket.sequenceNumber
                )
                packet = try takeExpectedBufferedPacket()

            case .completed(let plan, let consumedPacket):
                if consumedPacket {
                    try advanceExpectedSequence(
                        after: currentPacket.sequenceNumber
                    )
                } else {
                    deferredOrderedPacket = currentPacket
                }
                updateGapAfterProgress()
                return .deliver(plan)
            }
        }

        updateGapAfterProgress()
        return .idle
    }

    private mutating func processOrderedPacket(
        _ packet: borrowing BufferedPacket,
        configuration: H264RTPReceiverConfiguration
    ) throws(H264RTPReceiverError) -> OrderedPacketResult {
        if var quarantine {
            guard quarantine.timestamp != packet.timestamp else {
                quarantine.observedPacket = true
                self.quarantine = quarantine
                return .consumed
            }
            if quarantine.observedPacket, !quarantine.wasAlreadyCounted {
                operation?.discardedAccessUnitCount += 1
            }
            self.quarantine = nil
        }

        if let completedTimestamp {
            guard completedTimestamp != packet.timestamp else {
                throw .packetAfterMarkerForCompletedTimestamp(
                    timestamp: packet.timestamp
                )
            }
            self.completedTimestamp = nil
        }

        if let previous = accessUnit,
           previous.timestamp != packet.timestamp {
            accessUnit = nil
            if previous.activeFragment == nil, previous.hasNALUnits {
                self.completedTimestamp = previous.timestamp
                return .completed(
                    previous.completedPlan(),
                    consumedPacket: false
                )
            }
            operation?.discardedAccessUnitCount += 1
        }

        if accessUnit == nil {
            accessUnit = H264RTPAccessUnitAssembly(
                timestamp: packet.timestamp,
                synchronizationSource:
                    packet.rtpLayout.fixedHeader.synchronizationSource,
                firstSequenceNumber: packet.sequenceNumber,
                startedAtNanoseconds: packet.arrivalTimeNanoseconds
            )
        }
        guard var assembly = accessUnit else {
            throw .integerOverflow
        }
        // Release the stored Array references before mutation so packet-owner
        // and metadata arrays remain uniquely referenced and never trigger COW.
        accessUnit = nil

        let processing = Result { () throws(H264RTPReceiverError) -> OrderedPacketResult in
            // Reordered packets retain their original arrival time. When an
            // earlier sequence arrives after a later packet, assembly starts at
            // the current observation time and then drains that older buffered
            // packet. Duration is therefore measured against the monotonic
            // receiver clock, never the buffered packet's historical time.
            guard let observationTime = lastObservedTimeNanoseconds else {
                throw .integerOverflow
            }
            let (elapsed, underflow) = observationTime
                .subtractingReportingOverflow(assembly.startedAtNanoseconds)
            guard !underflow else { throw .integerOverflow }
            guard elapsed <= configuration.maximumAccessUnitDurationNanoseconds else {
                throw .accessUnitAssemblyTimedOut(
                    elapsed: elapsed,
                    maximum: configuration.maximumAccessUnitDurationNanoseconds
                )
            }

            let ownerIndex = try assembly.beginPacket(
                sequenceNumber: packet.sequenceNumber,
                owner: packet.bytes,
                maximumPacketCount: configuration.maximumPacketsPerAccessUnit,
                maximumRetainedInputByteCount:
                    configuration.maximumAccessUnitInputByteCount
            )
            let payloadBase = packet.rtpLayout.payloadRange.lowerBound

            switch packet.h264Layout.structure {
            case .singleNALUnit(let nalUnit):
                guard assembly.activeFragment == nil else {
                    throw .fragmentationUnitInterrupted
                }
                try assembly.appendCompleteNALUnit(
                    header: nalUnit.header,
                    ownerIndex: ownerIndex,
                    range: try absoluteRange(
                        nalUnit.range,
                        base: payloadBase
                    ),
                    format: configuration.accessUnitFormat,
                    maximumByteCount: configuration.maximumAccessUnitByteCount,
                    maximumNALUnitCount:
                        configuration.maximumNALUnitsPerAccessUnit
                )

            case .singleTimeAggregationPacketA(let aggregation):
                guard assembly.activeFragment == nil else {
                    throw .fragmentationUnitInterrupted
                }
                let payload = packet.bytes.span.extracting(
                    packet.rtpLayout.payloadRange
                )
                var appendFailure: H264RTPReceiverError?
                let traversal = Result { () throws(H264RTPPayloadError) in
                    try aggregation.forEachNALUnit(in: payload) { nalUnit in
                        guard appendFailure == nil else { return }
                        let appended = Result { () throws(H264RTPReceiverError) in
                            try assembly.appendCompleteNALUnit(
                                header: nalUnit.header,
                                ownerIndex: ownerIndex,
                                range: try absoluteRange(
                                    nalUnit.range,
                                    base: payloadBase
                                ),
                                format: configuration.accessUnitFormat,
                                maximumByteCount:
                                    configuration.maximumAccessUnitByteCount,
                                maximumNALUnitCount:
                                    configuration.maximumNALUnitsPerAccessUnit
                            )
                        }
                        if case .failure(let error) = appended {
                            appendFailure = error
                        }
                    }
                }
                if case .failure(let error) = traversal {
                    throw .h264Payload(error)
                }
                if let appendFailure {
                    throw appendFailure
                }

            case .fragmentationUnitA(let fragment):
                let range = try absoluteRange(
                    fragment.fragmentRange,
                    base: payloadBase
                )
                if fragment.isStart {
                    guard assembly.activeFragment == nil else {
                        throw .fragmentationUnitInterrupted
                    }
                    try assembly.startFragmentedNALUnit(
                        header: fragment.originalNALUnitHeader,
                        ownerIndex: ownerIndex,
                        range: range,
                        format: configuration.accessUnitFormat,
                        maximumByteCount:
                            configuration.maximumAccessUnitByteCount,
                        maximumNALUnitCount:
                            configuration.maximumNALUnitsPerAccessUnit
                    )
                } else {
                    try assembly.appendFragment(
                        header: fragment.originalNALUnitHeader,
                        ownerIndex: ownerIndex,
                        range: range,
                        isEnd: fragment.isEnd,
                        format: configuration.accessUnitFormat,
                        maximumByteCount:
                            configuration.maximumAccessUnitByteCount
                    )
                }
            }

            if packet.marker {
                guard assembly.activeFragment == nil else {
                    throw .markerBeforeFragmentationUnitEnd
                }
                completedTimestamp = assembly.timestamp
                return .completed(
                    assembly.completedPlan(),
                    consumedPacket: true
                )
            }
            accessUnit = assembly
            return .consumed
        }
        switch processing {
        case .success(let result):
            return result
        case .failure(let error):
            // Restore the partially-mutated owner solely so the common failure
            // path can account for and discard it exactly once.
            accessUnit = assembly
            throw error
        }
    }

    private func absoluteRange(
        _ relative: Range<Int>,
        base: Int
    ) throws(H264RTPReceiverError) -> Range<Int> {
        let (lower, lowerOverflow) =
            base.addingReportingOverflow(relative.lowerBound)
        let (upper, upperOverflow) =
            base.addingReportingOverflow(relative.upperBound)
        guard !lowerOverflow, !upperOverflow else {
            throw .integerOverflow
        }
        return lower..<upper
    }

    private mutating func observeTime(
        _ timeNanoseconds: UInt64
    ) throws(H264RTPReceiverError) {
        if let previous = lastObservedTimeNanoseconds,
           timeNanoseconds < previous {
            throw .decreasingArrivalTime(previous: previous, current: timeNanoseconds)
        }
        lastObservedTimeNanoseconds = timeNanoseconds
    }

    private mutating func beginQuarantine(
        nextPacketTimestamp: UInt32
    ) -> Int {
        let activeTimestamp = accessUnit?.timestamp
        let previousQuarantine = quarantine
        var discarded = accessUnit == nil ? 0 : 1
        if let previousQuarantine,
           previousQuarantine.timestamp != nextPacketTimestamp,
           previousQuarantine.observedPacket,
           !previousQuarantine.wasAlreadyCounted {
            discarded += 1
        }
        accessUnit = nil
        completedTimestamp = nil
        let continuesPreviousQuarantine =
            previousQuarantine?.timestamp == nextPacketTimestamp
        quarantine = TimestampQuarantine(
            timestamp: nextPacketTimestamp,
            wasAlreadyCounted:
                (discarded > 0 && activeTimestamp == nextPacketTimestamp)
                    || (continuesPreviousQuarantine
                        && previousQuarantine?.wasAlreadyCounted == true),
            observedPacket:
                continuesPreviousQuarantine
                    && previousQuarantine?.observedPacket == true
        )
        return discarded
    }

    private mutating func beginProcessingFailureQuarantine(
        nextPacketTimestamp: UInt32
    ) -> Int {
        let discarded = beginQuarantine(
            nextPacketTimestamp: nextPacketTimestamp
        )
        quarantine?.observedPacket = true
        if discarded == 0 {
            quarantine?.wasAlreadyCounted = true
            return 1
        }
        return discarded
    }

    private mutating func makeRoomAndInsert(
        _ packet: consuming BufferedPacket,
        configuration: H264RTPReceiverConfiguration
    ) throws(H264RTPReceiverError) {
        while reorderPackets.count >= configuration.maximumReorderPacketCount
            || cannotBuffer(
                additionalByteCount: packet.bytes.count,
                maximumByteCount: configuration.maximumReorderByteCount
            ) {
            guard let discarded = reorderPackets.removeFarthest() else {
                break
            }
            operation?.discardedPacketCount += 1
            operation?.discardedPacketByteCount += UInt64(
                discarded.packet.bytes.count
            )
        }
        try insertBuffered(packet)
    }

    private func cannotBuffer(
        additionalByteCount: Int,
        maximumByteCount: Int
    ) -> Bool {
        let (candidate, overflow) =
            reorderPackets.byteCount.addingReportingOverflow(additionalByteCount)
        return overflow || candidate > maximumByteCount
    }

    private mutating func insertBuffered(
        _ packet: consuming BufferedPacket
    ) throws(H264RTPReceiverError) {
        guard let expectedSequenceNumber else { throw .integerOverflow }
        let distance = Self.forwardDistance(
            from: expectedSequenceNumber,
            to: packet.sequenceNumber
        )
        guard distance > 0, distance < 32_768 else {
            throw .integerOverflow
        }
        let extended = try extendedSequenceNumber(distance: distance)
        let sequenceNumber = packet.sequenceNumber
        let arrivalTimeNanoseconds = packet.arrivalTimeNanoseconds
        let byteCount = packet.bytes.count
        reorderPackets.insert(
            packet,
            sequenceNumber: sequenceNumber,
            extendedSequenceNumber: extended,
            arrivalTimeNanoseconds: arrivalTimeNanoseconds,
            byteCount: byteCount
        )
    }

    private func extendedSequenceNumber(
        distance: Int
    ) throws(H264RTPReceiverError) -> UInt64 {
        guard let expectedExtendedSequenceNumber else {
            throw .integerOverflow
        }
        let (extended, overflow) = expectedExtendedSequenceNumber
            .addingReportingOverflow(UInt64(distance))
        guard !overflow else { throw .integerOverflow }
        return extended
    }

    private mutating func takeExpectedBufferedPacket(
    ) throws(H264RTPReceiverError) -> BufferedPacket? {
        guard let expectedSequenceNumber else { return nil }
        guard let indexedPacket = reorderPackets.remove(
            sequenceNumber: expectedSequenceNumber
        ) else {
            return nil
        }
        guard indexedPacket.extendedSequenceNumber
                == expectedExtendedSequenceNumber else {
            throw .integerOverflow
        }
        return indexedPacket.packet
    }

    private mutating func advanceExpectedSequence(
        after sequenceNumber: UInt16
    ) throws(H264RTPReceiverError) {
        guard expectedSequenceNumber == sequenceNumber,
              let expectedExtendedSequenceNumber else {
            throw .integerOverflow
        }
        let (nextExtended, overflow) = expectedExtendedSequenceNumber
            .addingReportingOverflow(1)
        guard !overflow else { throw .integerOverflow }
        self.expectedSequenceNumber = sequenceNumber &+ 1
        self.expectedExtendedSequenceNumber = nextExtended
    }

    private mutating func takeDeferredPacket() -> BufferedPacket? {
        let packet = deferredOrderedPacket
        deferredOrderedPacket = nil
        return packet
    }

    private mutating func discardQueuedPackets() {
        if let deferredOrderedPacket {
            operation?.discardedPacketCount += 1
            operation?.discardedPacketByteCount += UInt64(
                deferredOrderedPacket.bytes.count
            )
            self.deferredOrderedPacket = nil
        }
        operation?.discardedPacketCount += reorderPackets.count
        operation?.discardedPacketByteCount += UInt64(reorderPackets.byteCount)
        reorderPackets.removeAll(keepingCapacity: true)
        gapStartedAtNanoseconds = nil
        gapExpectedSequenceNumber = nil
    }

    private func gapHasExpired(
        at timeNanoseconds: UInt64,
        maximumDelay: UInt64
    ) throws(H264RTPReceiverError) -> Bool {
        guard deferredOrderedPacket == nil,
              gapExpectedSequenceNumber == expectedSequenceNumber,
              let gapStartedAtNanoseconds else {
            return false
        }
        let (elapsed, underflow) = timeNanoseconds
            .subtractingReportingOverflow(gapStartedAtNanoseconds)
        guard !underflow else { throw .integerOverflow }
        return elapsed >= maximumDelay
    }

    private mutating func updateGapAfterProgress(
        fallbackTimeNanoseconds: UInt64? = nil
    ) {
        guard deferredOrderedPacket == nil,
              let expectedSequenceNumber,
              !reorderPackets.isEmpty,
              !reorderPackets.contains(
                sequenceNumber: expectedSequenceNumber
              ) else {
            gapStartedAtNanoseconds = nil
            gapExpectedSequenceNumber = nil
            return
        }
        guard gapExpectedSequenceNumber != expectedSequenceNumber
                || gapStartedAtNanoseconds == nil else {
            return
        }

        // Scan only when a different missing sequence becomes visible. Keeping
        // the witness paired with that sequence avoids both inherited deadlines
        // and an O(n²) scan during marker-per-packet bursts.
        let earliestWitness = reorderPackets
            .earliestArrivalTimeNanoseconds()
        gapExpectedSequenceNumber = expectedSequenceNumber
        gapStartedAtNanoseconds = earliestWitness
            ?? fallbackTimeNanoseconds
            ?? lastObservedTimeNanoseconds
    }

    private mutating func finishedStep(
        after progress: consuming StateProgress,
        configuration: H264RTPReceiverConfiguration
    ) throws(H264RTPReceiverError) -> ProcessingStep {
        switch progress {
        case .deliver(let plan):
            return .deliver(plan)
        case .idle:
            return finishOrDeliver(
                try settleExpiredState(configuration: configuration)
            )
        }
    }

    private mutating func finishOrDeliver(
        _ progress: consuming StateProgress
    ) -> ProcessingStep {
        switch progress {
        case .deliver(let plan):
            return .deliver(plan)
        case .idle:
            return finishOperation()
        }
    }

    private mutating func terminateAfterProcessingFailure(
        _ cause: H264RTPReceiverError,
        damagedTimestamp: UInt32?
    ) -> ReceiverProcessingFailure {
        if let damagedTimestamp {
            let discardedAccessUnitCount = beginQuarantine(
                nextPacketTimestamp: damagedTimestamp
            )
            operation?.discardedAccessUnitCount += discardedAccessUnitCount
        }
        if mustFlushQueueAfterFailure {
            alreadyCountedQuarantineTimestamp = quarantine?.timestamp
            discardQueuedPackets()
            expectedSequenceNumber = nil
            expectedExtendedSequenceNumber = nil
            quarantine = nil
            completedTimestamp = nil
            mustQuarantineNextTimestamp = true
            mustFlushQueueAfterFailure = false
        }
        let effects = report()
        operation = nil
        return ReceiverProcessingFailure(cause: cause, effects: effects)
    }

    private mutating func finishOperation() -> ProcessingStep {
        let effects = report()
        operation = nil
        return .finished(effects)
    }

    private func report() -> H264RTPReceiveReport {
        let effects = operation ?? OperationEffects(disposition: .processed)
        return H264RTPReceiveReport(
            disposition: effects.disposition,
            deliveredAccessUnitCount: effects.deliveredAccessUnitCount,
            declaredLostPacketCount: effects.declaredLostPacketCount,
            discardedAccessUnitCount: effects.discardedAccessUnitCount,
            discardedPacketCount: effects.discardedPacketCount,
            discardedPacketByteCount: effects.discardedPacketByteCount,
            reconstructedByteCount: effects.reconstructedByteCount,
            bufferedPacketCount:
                reorderPackets.count
                    + (deferredOrderedPacket == nil ? 0 : 1),
            bufferedByteCount:
                UInt64(reorderPackets.byteCount)
                    + UInt64(deferredOrderedPacket?.bytes.count ?? 0)
        )
    }

    @inline(__always)
    private static func forwardDistance(from: UInt16, to: UInt16) -> Int {
        Int(to &- from)
    }
}
