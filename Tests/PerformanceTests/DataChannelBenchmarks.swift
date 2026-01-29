/// DataChannel Performance Benchmarks
///
/// Measures performance of data channel operations.

import Testing
import Foundation
@testable import DataChannel
@testable import SCTPCore

@Suite("DataChannel Benchmarks")
struct DataChannelBenchmarks {

    // MARK: - DCEP Encoding/Decoding

    @Test("Benchmark: DCEP Open encoding")
    func benchmarkDCEPOpenEncode() {
        let open = DCEPOpen(
            channelType: .reliable,
            priority: 0,
            reliabilityParameter: 0,
            label: "test-channel",
            protocol_: ""
        )

        let result = benchmark("DCEPOpen.encode", iterations: 10000) {
            _ = open.encode()
        }
        print(result)
    }

    @Test("Benchmark: DCEP Open decoding")
    func benchmarkDCEPOpenDecode() throws {
        let open = DCEPOpen(
            channelType: .reliable,
            label: "test-channel"
        )
        let encoded = open.encode()

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
        let encoded = open.encode()

        let result = try benchmark("DCEPOpen.decode (long label)", iterations: 10000) {
            _ = try DCEPOpen.decode(from: encoded)
        }
        print(result)
        print("  Message size: \(encoded.count) bytes")
    }

    // MARK: - Channel Manager

    @Test("Benchmark: Channel open")
    func benchmarkChannelOpen() {
        let manager = DataChannelManager(isInitiator: true)

        var i = 0
        let result = benchmark("DataChannelManager.openChannel", iterations: 10000) {
            _ = manager.openChannel(label: "channel-\(i)")
            i += 1
        }
        print(result)
    }

    @Test("Benchmark: Process incoming DCEP")
    func benchmarkProcessDCEP() throws {
        let manager = DataChannelManager(isInitiator: false)
        let open = DCEPOpen(channelType: .reliable, label: "test")
        let encoded = open.encode()

        var streamID: UInt16 = 0
        let result = try benchmark("DataChannelManager.processIncomingDCEP", iterations: 10000) {
            _ = try manager.processIncomingDCEP(streamID: streamID, data: encoded)
            streamID += 2
        }
        print(result)
    }

    @Test("Benchmark: Channel lookup")
    func benchmarkChannelLookup() {
        let manager = DataChannelManager(isInitiator: true)

        // Create 100 channels
        for i in 0..<100 {
            _ = manager.openChannel(label: "channel-\(i)")
        }

        let result = benchmark("DataChannelManager.channel(id:)", iterations: 100000) {
            _ = manager.channel(id: 50) // Middle channel
        }
        print(result)
    }
}
