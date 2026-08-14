import WebRTCMedia
import NetworkingTime
import SSLASN1
import SSLX509
import Synchronization
import WebRTC
import _Concurrency

enum WebRTCPlatformIntegrationProbeError: Error {
    case certificateEncodingFailed
    case certificateRejected
    case mediaConfigurationRejected
    case connectionRejected
    case connectionStartFailed
    case handshakeFailed
    case unexpectedConnectionState
    case transportFailureContractFailed
    case timerControllerFailed
    case timerCancellationFailed
    case timerHeartbeatFailed
    case timerCompletionFailed
    case h264ByteStreamParsingFailed
    case h264PacketizationFailed
    case h264EncodingFailed
    case h264ParsingFailed
    case h264AssemblyFailed
    case h264SenderConfigurationRejected
    case h264SendFailed
    case h264ReceiverConfigurationRejected
    case h264ReceiveFailed
    case h264RoundTripMismatch
}

private enum WebRTCPlatformIntegrationProbeSinkError: Error, Sendable {
    case rejected
}

@main
enum WebRTCPlatformIntegrationProbe {
    static func main() async throws(WebRTCPlatformIntegrationProbeError) {
        let clientCertificate = try provisionedCertificate(clockSeconds: 1_750_000_000)
        let serverCertificate = try provisionedCertificate(clockSeconds: 1_750_000_001)
        let mediaConfiguration = try configuredMedia()
        try verifyTypedTransportFailure(certificate: clientCertificate)
        try await verifyTimerCooperation()
        let pair = try PortableMediaConnectionPair(
            clientCertificate: clientCertificate,
            serverCertificate: serverCertificate,
            mediaConfiguration: mediaConfiguration
        )
        defer { pair.close() }

        try pair.completeHandshake()
        guard pair.client.state == .connected,
              pair.server.state == .connected,
              pair.client.isMediaReady,
              pair.server.isMediaReady else {
            throw .unexpectedConnectionState
        }

        try verifyH264PayloadPath(pair: pair)
        print("WebRTC portable DTLS-SRTP H264 round-trip probe passed")
    }

    private static func verifyTimerCooperation(
    ) async throws(WebRTCPlatformIntegrationProbeError) {
        let state = PortableTimerCooperationState()
        let startGate = PortableAsyncGate()
        let timer = WebRTCTimer.platformDefault
        let sleeper = Task {
            state.beginSleeping()
            startGate.open()
            let wasCancelled: Bool
            do {
                let now = try timer.now()
                let deadline = try now.advanced(byNanoseconds: 2_000_000_000)
                try await timer.sleep(until: deadline)
                wasCancelled = false
            } catch {
                wasCancelled = true
            }
            state.finishSleeping()
            return wasCancelled
        }
        let controller = Task {
            await startGate.wait()
            for _ in 0..<8 {
                state.recordCooperativeBeat()
                await Task.yield()
            }
            sleeper.cancel()
            return true
        }

        let controllerCompleted = await controller.value
        let cancellationObserved = await sleeper.value
        let snapshot = state.snapshot
        guard controllerCompleted else { throw .timerControllerFailed }
        guard cancellationObserved else { throw .timerCancellationFailed }
        guard snapshot.cooperativeBeatCount > 0 else {
            throw .timerHeartbeatFailed
        }
        guard !snapshot.isSleeping else { throw .timerCompletionFailed }
    }

    private static func verifyTypedTransportFailure(
        certificate: WebRTCCertificate
    ) throws(WebRTCPlatformIntegrationProbeError) {
        let connection: WebRTCConnection
        do {
            connection = try WebRTCConnection.asClient(
                certificate: certificate,
                remoteFingerprint: certificate.fingerprint,
                sendHandler: { _ in .failure(.backpressured) }
            )
        } catch {
            throw .connectionRejected
        }
        defer { connection.close() }

        let result = Result { () throws(WebRTCError) in
            try connection.start()
        }
        guard case .failure(.datagramSendFailed(.backpressured)) = result,
              connection.state.isTerminal,
              let terminalFailure = connection.terminalFailure,
              case .datagramSendFailed(.backpressured) = terminalFailure else {
            throw .transportFailureContractFailed
        }
    }

    private static func provisionedCertificate(
        clockSeconds: Int64
    ) throws(WebRTCPlatformIntegrationProbeError) -> WebRTCCertificate {
        do {
            let generated = try WebRTCCertificate.generateSelfSigned(
                clock: PortableCertificateClock(seconds: clockSeconds)
            )
            return try WebRTCCertificate(
                derEncoded: generated.derEncoded,
                rawPrivateKey: generated.rawPrivateKey
            )
        } catch {
            throw .certificateRejected
        }
    }

    private static func configuredMedia(
    ) throws(WebRTCPlatformIntegrationProbeError) -> WebRTCMediaConfiguration {
        do {
            return try WebRTCMediaConfiguration(rtpPayloadTypes: [96])
        } catch {
            throw .mediaConfigurationRejected
        }
    }

    private static func verifyH264PayloadPath(
        pair: PortableMediaConnectionPair
    ) throws(WebRTCPlatformIntegrationProbeError) {
        let accessUnit: [UInt8] = [0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33]
        let nalUnitRanges: [Range<Int>]
        do {
            nalUnitRanges = try H264ByteStreamParser().nalUnitRanges(
                in: accessUnit.span,
                format: .annexB
            )
        } catch {
            throw .h264ByteStreamParsingFailed
        }
        let packetizer = RFC6184H264Packetizer()
        var emittedLayout: H264RTPPacketizationLayout?
        var emittedCount = 0

        do {
            try packetizer.forEachPacket(
                in: accessUnit.span,
                nalUnitRanges: nalUnitRanges.span,
                mode: .nonInterleaved,
                maximumPayloadByteCount: 1_200
            ) { layout in
                if emittedCount == 0 {
                    emittedLayout = layout
                }
                emittedCount += 1
            }
        } catch {
            throw .h264PacketizationFailed
        }
        guard emittedCount == 1, let emittedLayout else {
            throw .h264RoundTripMismatch
        }

        var payload: [UInt8] = []
        do {
            try RFC6184H264PayloadEncoder().appendPayload(
                emittedLayout,
                from: accessUnit.span,
                nalUnitRanges: nalUnitRanges.span,
                to: &payload
            )
        } catch {
            throw .h264EncodingFailed
        }
        guard nalUnitRanges.count == 1,
              payload == Array(accessUnit[nalUnitRanges[0]]) else {
            throw .h264RoundTripMismatch
        }

        let parsed: H264RTPPayloadLayout
        do {
            parsed = try RFC6184H264PayloadParser().layout(
                in: payload.span,
                mode: .nonInterleaved
            )
        } catch {
            throw .h264ParsingFailed
        }
        guard case .singleNALUnit(let nalUnit) = parsed.structure,
              nalUnit.range == 0..<payload.count,
              nalUnit.header.rawValue == accessUnit[nalUnitRanges[0].lowerBound] else {
            throw .h264RoundTripMismatch
        }

        let noExtension: [UInt8] = []
        let senderConfiguration: H264RTPSenderConfiguration
        do {
            senderConfiguration = try H264RTPSenderConfiguration(
                payloadType: 96,
                synchronizationSource: 1,
                maximumDatagramByteCount: 1_200,
                protectionTrailerByteCount:
                    WebRTCMediaProtectionProfile.aes128CMHMACSHA180
                        .rtpProtectionTrailerByteCount,
                initialSequenceNumber: 1,
                initialTimestamp: 90_000
            )
        } catch {
            throw .h264SenderConfigurationRejected
        }
        let receiverConfiguration: H264RTPReceiverConfiguration
        do {
            receiverConfiguration = try H264RTPReceiverConfiguration(
                payloadType: 96,
                synchronizationSource: 1,
                maximumPacketByteCount: 1_200,
                maximumAccessUnitByteCount: 1_200,
                maximumAccessUnitInputByteCount: 1_200,
                maximumReorderByteCount: 1_200
            )
        } catch {
            throw .h264ReceiverConfigurationRejected
        }
        let receiver = H264RTPReceiverSession(
            configuration: receiverConfiguration
        )
        let receipt = PortableMediaReceipt()
        pair.server.setRTPHandler { packet in
            receipt.receive(packet, with: receiver)
        }

        let sender = H264RTPSenderSession(configuration: senderConfiguration)
        let sendResult: Result<
            H264RTPSendReport,
            H264RTPSendError<WebRTCPlatformIntegrationProbeSinkError>
        > = sender.sendAccessUnit(
            accessUnit.span,
            nalUnitRanges: nalUnitRanges.span,
            captureTimeNanoseconds: 1_000_000_000,
            extensionProfile: nil,
            extensionData: noExtension.span
        ) { packet in
            do {
                try pair.client.sendRTP(consume packet)
                return .success(())
            } catch {
                return .failure(.rejected)
            }
        }
        let sendReport: H264RTPSendReport
        switch sendResult {
        case .success(let report):
            sendReport = report
        case .failure:
            throw .h264SendFailed
        }
        guard sendReport.packetCount == 1,
              sendReport.firstSequenceNumber == 1,
              sendReport.lastSequenceNumber == 1,
              sendReport.timestamp == 90_000 else {
            throw .h264RoundTripMismatch
        }

        try pair.deliverClientDatagramsToServer()
        let snapshot = receipt.snapshot
        guard !snapshot.failed,
              snapshot.deliveredAccessUnitCount == 1,
              snapshot.reconstructedByteCount == UInt64(accessUnit.count),
              snapshot.accessUnit == accessUnit else {
            throw .h264RoundTripMismatch
        }
    }

}

private struct PortableCertificateClock: WebRTCCertificateClock {
    let seconds: Int64

    func nowUnixSeconds() -> Int64? { seconds }
}

private final class PortableMediaConnectionPair: Sendable {
    let client: WebRTCConnection
    let server: WebRTCConnection

    private let clientOutbox: PortableDatagramOutbox
    private let serverOutbox: PortableDatagramOutbox

    init(
        clientCertificate: WebRTCCertificate,
        serverCertificate: WebRTCCertificate,
        mediaConfiguration: WebRTCMediaConfiguration
    ) throws(WebRTCPlatformIntegrationProbeError) {
        let clientOutbox = PortableDatagramOutbox()
        let serverOutbox = PortableDatagramOutbox()
        self.clientOutbox = clientOutbox
        self.serverOutbox = serverOutbox

        do {
            self.client = try WebRTCConnection.asClient(
                certificate: clientCertificate,
                remoteFingerprint: serverCertificate.fingerprint,
                mediaConfiguration: mediaConfiguration,
                sendHandler: { [clientOutbox] datagram in
                    clientOutbox.accept(datagram)
                }
            )
            self.server = try WebRTCConnection.asServer(
                certificate: serverCertificate,
                remoteFingerprint: clientCertificate.fingerprint,
                mediaConfiguration: mediaConfiguration,
                sendHandler: { [serverOutbox] datagram in
                    serverOutbox.accept(datagram)
                }
            )
        } catch {
            throw .connectionRejected
        }
    }

    func completeHandshake(
    ) throws(WebRTCPlatformIntegrationProbeError) {
        do {
            try server.start()
            try client.start()
        } catch {
            throw .connectionStartFailed
        }

        for _ in 0..<32 {
            do {
                for datagram in clientOutbox.drain() {
                    try server.receive(datagram)
                }
                for datagram in serverOutbox.drain() {
                    try client.receive(datagram)
                }
            } catch {
                throw .handshakeFailed
            }

            if client.isMediaReady,
               server.isMediaReady,
               client.state == .connected,
               server.state == .connected,
               clientOutbox.isEmpty,
               serverOutbox.isEmpty {
                return
            }
        }
        throw .handshakeFailed
    }

    func deliverClientDatagramsToServer(
    ) throws(WebRTCPlatformIntegrationProbeError) {
        let datagrams = clientOutbox.drain()
        guard !datagrams.isEmpty else { throw .h264SendFailed }
        do {
            for datagram in datagrams {
                try server.receive(datagram)
            }
        } catch {
            throw .h264ReceiveFailed
        }
    }

    func close() {
        client.close()
        server.close()
    }
}

private final class PortableAsyncGate: Sendable {
    private struct State: Sendable {
        var isOpen = false
        var waiter: CheckedContinuation<Void, Never>?
    }

    private let state = Mutex(State())

    func open() {
        let waiter = state.withLock {
            state -> CheckedContinuation<Void, Never>? in
            guard !state.isOpen else { return nil }
            state.isOpen = true
            let waiter = state.waiter
            state.waiter = nil
            return waiter
        }
        waiter?.resume()
    }

    func wait() async {
        await withCheckedContinuation { continuation in
            let resumeImmediately = state.withLock { state -> Bool in
                if state.isOpen {
                    return true
                }
                precondition(
                    state.waiter == nil,
                    "Portable async gate permits one waiter"
                )
                state.waiter = continuation
                return false
            }
            if resumeImmediately {
                continuation.resume()
            }
        }
    }
}

private final class PortableDatagramOutbox: Sendable {
    private let datagrams = Mutex<[[UInt8]]>([])

    var isEmpty: Bool {
        datagrams.withLock { $0.isEmpty }
    }

    func accept(
        _ datagram: [UInt8]
    ) -> Result<Void, WebRTCDatagramSendFailure> {
        datagrams.withLock { $0.append(datagram) }
        return .success(())
    }

    func drain() -> [[UInt8]] {
        datagrams.withLock { pending in
            var drained: [[UInt8]] = []
            swap(&drained, &pending)
            return drained
        }
    }
}

private final class PortableTimerCooperationState: Sendable {
    struct Snapshot: Sendable {
        var isSleeping = false
        var cooperativeBeatCount = 0
    }

    private let state = Mutex(Snapshot())

    var snapshot: Snapshot {
        state.withLock { $0 }
    }

    func beginSleeping() {
        state.withLock { $0.isSleeping = true }
    }

    func recordCooperativeBeat() {
        state.withLock { state in
            if state.isSleeping {
                state.cooperativeBeatCount += 1
            }
        }
    }

    func finishSleeping() {
        state.withLock { $0.isSleeping = false }
    }
}

private final class PortableMediaReceipt: Sendable {
    struct Snapshot: Sendable {
        let failed: Bool
        let accessUnit: [UInt8]?
        let deliveredAccessUnitCount: Int
        let reconstructedByteCount: UInt64
    }

    private struct State: Sendable {
        var failed = false
        var accessUnit: [UInt8]?
        var deliveredAccessUnitCount = 0
        var reconstructedByteCount: UInt64 = 0
        var nextArrivalTimeNanoseconds: UInt64 = 1_000_000_000
    }

    private let state = Mutex(State())

    var snapshot: Snapshot {
        state.withLock { state in
            Snapshot(
                failed: state.failed,
                accessUnit: state.accessUnit,
                deliveredAccessUnitCount: state.deliveredAccessUnitCount,
                reconstructedByteCount: state.reconstructedByteCount
            )
        }
    }

    func receive(
        _ packet: consuming WebRTCRTPPacket,
        with receiver: H264RTPReceiverSession
    ) {
        let arrivalTime = state.withLock { state -> UInt64 in
            let current = state.nextArrivalTimeNanoseconds
            state.nextArrivalTimeNanoseconds &+= 1
            return current
        }
        let result = receiver.receive(
            packet.bytes,
            layout: packet.layout,
            arrivalTimeNanoseconds: arrivalTime
        ) { accessUnit -> Result<
            Void,
            WebRTCPlatformIntegrationProbeSinkError
        > in
            self.state.withLock { $0.accessUnit = accessUnit.bytes }
            return .success(())
        }

        state.withLock { state in
            switch result {
            case .success(let report):
                state.deliveredAccessUnitCount += report.deliveredAccessUnitCount
                state.reconstructedByteCount += report.reconstructedByteCount
            case .failure:
                state.failed = true
            }
        }
    }
}
