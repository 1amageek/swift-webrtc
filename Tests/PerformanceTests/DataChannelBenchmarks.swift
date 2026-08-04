/// DataChannel Performance Benchmarks
///
/// Measures performance of data channel operations.

import Testing
import Foundation
@testable import WebRTC

@Suite("DataChannel Benchmarks")
struct DataChannelBenchmarks {

    // MARK: - DCEP Encoding/Decoding

    @Test("Benchmark: DCEP Open encoding")
    func benchmarkDCEPOpenEncode() throws {
        let open = DCEPOpen(
            channelType: .reliable,
            priority: 0,
            reliabilityParameter: 0,
            label: "test-channel",
            protocol_: ""
        )

        let result = try benchmark("DCEPOpen.encode", iterations: 10000) {
            _ = try open.encode()
        }
        print(result)
    }

    @Test("Benchmark: DCEP Open decoding")
    func benchmarkDCEPOpenDecode() throws {
        let open = DCEPOpen(
            channelType: .reliable,
            label: "test-channel"
        )
        let encoded = try open.encode()

        let result = try benchmark("DCEPOpen.decode", iterations: 10000) {
            _ = try DCEPOpen.decode(from: encoded)
        }
        print(result)
    }

    @Test("Benchmark: DCEP Open with long label")
    func benchmarkDCEPOpenLongLabel() throws {
        let longLabel = String(repeating: "channel-", count: 100) // 800 chars
        let open = DCEPOpen(
            channelType: .reliable,
            label: longLabel,
            protocol_: "my-protocol"
        )
        let encoded = try open.encode()

        let result = try benchmark("DCEPOpen.decode (long label)", iterations: 10000) {
            _ = try DCEPOpen.decode(from: encoded)
        }
        print(result)
        print("  Message size: \(encoded.count) bytes")
    }

    // MARK: - Channel Manager

    @Test("Benchmark: Channel open")
    func benchmarkChannelOpen() throws {
        // Allow enough stream IDs for warmup + measured iterations.
        let manager = DataChannelManager(isInitiator: true, maxChannels: .max)

        var i = 0
        let result = try benchmark("DataChannelManager.openChannel", iterations: 10000) {
            _ = try manager.openChannel(label: "channel-\(i)")
            i += 1
        }
        print(result)
    }

    @Test("Benchmark: Process incoming DCEP")
    func benchmarkProcessDCEP() throws {
        // Raise the channel cap high enough for the measured iteration count.
        let manager = DataChannelManager(
            isInitiator: false,
            maxChannels: .max
        )
        let open = DCEPOpen(channelType: .reliable, label: "test")
        let encoded = try open.encode()

        // Incoming OPENs must use even stream IDs (responder opens odd).
        var streamID: UInt16 = 0
        let result = try benchmark("DataChannelManager.processIncomingDCEP", iterations: 10000) {
            _ = try manager.processIncomingDCEP(streamID: streamID, data: encoded)
            streamID += 2
        }
        print(result)
    }

    @Test("Benchmark: Channel lookup")
    func benchmarkChannelLookup() throws {
        let manager = DataChannelManager(isInitiator: true)

        // Create 100 channels
        for i in 0..<100 {
            _ = try manager.openChannel(label: "channel-\(i)")
        }

        let result = benchmark("DataChannelManager.channel(id:)", iterations: 100000) {
            _ = manager.channel(id: 50) // Middle channel
        }
        print(result)
    }
}
