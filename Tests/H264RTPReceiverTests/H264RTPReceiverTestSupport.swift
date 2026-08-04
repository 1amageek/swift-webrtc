@testable import WebRTCMedia
@testable import WebRTC
import Synchronization

let receiverTestSynchronizationSource: UInt32 = 0x0102_0304

enum ReceiverTestSinkError: Error, Sendable, Equatable {
    case rejected
}

struct H264RTPReceiverTestSupport {
    func receiver(
        accessUnitFormat: H264RTPAccessUnitFormat = .annexB(startCodeByteCount: 4),
        maximumPacketByteCount: Int = 1_200,
        maximumAccessUnitByteCount: Int = 1_024,
        maximumAccessUnitInputByteCount: Int = 4_096,
        maximumAccessUnitDurationNanoseconds: UInt64 = 500_000_000,
        maximumPacketsPerAccessUnit: Int = 2_048,
        maximumNALUnitsPerAccessUnit: Int = 512,
        maximumReorderPacketCount: Int = 64,
        maximumReorderByteCount: Int = 4_096,
        maximumReorderDelayNanoseconds: UInt64 = 50_000_000
    ) throws -> H264RTPReceiverSession {
        H264RTPReceiverSession(configuration: try H264RTPReceiverConfiguration(
            payloadType: 96,
            synchronizationSource: receiverTestSynchronizationSource,
            accessUnitFormat: accessUnitFormat,
            maximumPacketByteCount: maximumPacketByteCount,
            maximumAccessUnitByteCount: maximumAccessUnitByteCount,
            maximumAccessUnitInputByteCount: maximumAccessUnitInputByteCount,
            maximumAccessUnitDurationNanoseconds:
                maximumAccessUnitDurationNanoseconds,
            maximumPacketsPerAccessUnit: maximumPacketsPerAccessUnit,
            maximumNALUnitsPerAccessUnit: maximumNALUnitsPerAccessUnit,
            maximumReorderPacketCount: maximumReorderPacketCount,
            maximumReorderByteCount: maximumReorderByteCount,
            maximumReorderDelayNanoseconds: maximumReorderDelayNanoseconds
        ))
    }

    func packet(
        sequenceNumber: UInt16,
        timestamp: UInt32,
        marker: Bool,
        payload: [UInt8],
        payloadType: UInt8 = 96,
        synchronizationSource: UInt32 = receiverTestSynchronizationSource,
        contributingSources: [UInt32] = [],
        extensionProfile: UInt16? = nil,
        extensionData: [UInt8] = [],
        paddingByteCount: Int = 0
    ) throws -> (bytes: [UInt8], layout: RTPPacketLayout) {
        var bytes: [UInt8] = []
        try RFC3550RTPHeaderEncoder().appendHeader(
            RTPOutboundHeader(
                marker: marker,
                payloadType: payloadType,
                sequenceNumber: sequenceNumber,
                timestamp: timestamp,
                synchronizationSource: synchronizationSource,
                contributingSources: contributingSources
            ),
            extensionProfile: extensionProfile,
            extensionData: extensionData.span,
            to: &bytes
        )
        bytes.append(contentsOf: payload)
        if paddingByteCount > 0 {
            bytes[0] |= 0x20
            if paddingByteCount > 1 {
                bytes.append(contentsOf: repeatElement(
                    0,
                    count: paddingByteCount - 1
                ))
            }
            bytes.append(UInt8(paddingByteCount))
        }
        let layout = try RFC3550RTPPacketParser().layout(in: bytes.span)
        return (bytes, layout)
    }
}

final class AccessUnitCollector: Sendable {
    private struct Storage: Sendable {
        var values: [H264RTPAccessUnit] = []
        var inputStorageAddresses: [UInt] = []
    }

    private let storage = Mutex(Storage())

    var values: [H264RTPAccessUnit] {
        storage.withLock { $0.values }
    }

    var inputStorageAddresses: [UInt] {
        storage.withLock { $0.inputStorageAddresses }
    }

    func accept(
        _ accessUnit: consuming H264RTPAccessUnit
    ) -> Result<Void, ReceiverTestSinkError> {
        let address = accessUnit.bytes.withUnsafeBufferPointer { buffer in
            buffer.baseAddress.map { UInt(bitPattern: $0) } ?? 0
        }
        let ownedAccessUnit = consume accessUnit
        storage.withLock { state in
            state.inputStorageAddresses.append(address)
            state.values.append(ownedAccessUnit)
        }
        return .success(())
    }
}
