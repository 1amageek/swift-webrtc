/// Benchmark Utilities
///
/// Simple benchmarking utilities for measuring performance.

import Foundation

/// Benchmark result containing timing statistics
public struct BenchmarkResult: CustomStringConvertible {
    public let name: String
    public let iterations: Int
    public let totalTime: Duration
    public let averageTime: Duration
    public let minTime: Duration
    public let maxTime: Duration
    public let throughput: Double? // operations per second

    public var description: String {
        var result = """
        \(name):
          Iterations: \(iterations)
          Total:      \(totalTime.formatted())
          Average:    \(averageTime.formatted())
          Min:        \(minTime.formatted())
          Max:        \(maxTime.formatted())
        """
        if let throughput {
            result += "\n  Throughput: \(String(format: "%.2f", throughput)) ops/sec"
        }
        return result
    }
}

/// Run a benchmark with the specified number of iterations
/// - Parameters:
///   - name: Benchmark name for reporting
///   - iterations: Number of iterations to run
///   - warmup: Number of warmup iterations (not measured)
///   - setup: Optional setup closure called before each iteration
///   - operation: The operation to benchmark
/// - Returns: BenchmarkResult with timing statistics
@discardableResult
public func benchmark(
    _ name: String,
    iterations: Int = 1000,
    warmup: Int = 100,
    setup: (() -> Void)? = nil,
    operation: () throws -> Void
) rethrows -> BenchmarkResult {
    // Warmup
    for _ in 0..<warmup {
        setup?()
        try operation()
    }

    var times: [Duration] = []
    times.reserveCapacity(iterations)

    let clock = ContinuousClock()

    for _ in 0..<iterations {
        setup?()
        let start = clock.now
        try operation()
        let elapsed = clock.now - start
        times.append(elapsed)
    }

    let totalTime = times.reduce(Duration.zero, +)
    let averageTime = totalTime / iterations
    let minTime = times.min() ?? .zero
    let maxTime = times.max() ?? .zero

    let averageSeconds = Double(averageTime.components.seconds) +
                         Double(averageTime.components.attoseconds) / 1e18
    let throughput = averageSeconds > 0 ? 1.0 / averageSeconds : nil

    return BenchmarkResult(
        name: name,
        iterations: iterations,
        totalTime: totalTime,
        averageTime: averageTime,
        minTime: minTime,
        maxTime: maxTime,
        throughput: throughput
    )
}

/// Run a benchmark that processes data with throughput measurement
/// - Parameters:
///   - name: Benchmark name
///   - dataSize: Size of data processed per iteration (bytes)
///   - iterations: Number of iterations
///   - operation: The operation to benchmark
/// - Returns: BenchmarkResult with throughput in MB/s
@discardableResult
public func benchmarkThroughput(
    _ name: String,
    dataSize: Int,
    iterations: Int = 1000,
    warmup: Int = 100,
    operation: () throws -> Void
) rethrows -> BenchmarkResult {
    let result = try benchmark(name, iterations: iterations, warmup: warmup, operation: operation)

    let totalBytes = dataSize * iterations
    let totalSeconds = Double(result.totalTime.components.seconds) +
                       Double(result.totalTime.components.attoseconds) / 1e18
    let mbPerSecond = totalSeconds > 0 ? Double(totalBytes) / totalSeconds / 1_000_000 : 0

    print("\(name): \(String(format: "%.2f", mbPerSecond)) MB/s")
    return result
}

extension Duration {
    func formatted() -> String {
        let totalNanos = Double(components.seconds) * 1e9 + Double(components.attoseconds) / 1e9
        if totalNanos < 1000 {
            return String(format: "%.2f ns", totalNanos)
        } else if totalNanos < 1_000_000 {
            return String(format: "%.2f µs", totalNanos / 1000)
        } else if totalNanos < 1_000_000_000 {
            return String(format: "%.2f ms", totalNanos / 1_000_000)
        } else {
            return String(format: "%.2f s", totalNanos / 1_000_000_000)
        }
    }
}
