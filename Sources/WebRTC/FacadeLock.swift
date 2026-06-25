/// The facade's value-protecting lock — `Synchronization.Mutex` on host, an
/// `Atomic`-spinlock box under Embedded (where `Synchronization.Mutex` is
/// unavailable).
///
/// `WebRTCConnection` / `WebRTCEndpoint` / `WebRTCListener` are
/// `final class & Sendable` orchestrators that hold their mutable state behind
/// this lock so their public methods are `Sendable`-safe. The underlying value
/// types (state machine, ICE agent, SCTP association, channel manager) hold no
/// lock; the facade serialises every mutation here.
///
/// Host: `FacadeLock<V>` IS `Synchronization.Mutex<V>` (same `init(_:)` and
/// `withLock { … }` surface, including the throwing overload).
///
/// Embedded: `Mutex` is not provided by `Synchronization`, so `FacadeLock<V>` is a
/// `final class` holding the value behind a tiny test-and-test-and-set spinlock over
/// `Atomic<Bool>`. `nonisolated(unsafe)` on the storage (NOT `@unchecked Sendable`)
/// confines the unsafety to the storage member; the spinlock provides the mutual
/// exclusion that makes the access safe. Embedded targets are typically single- or
/// few-threaded, so contention is negligible; correctness (not throughput) is the goal.
///
/// This mirrors swift-tls / swift-mDNS / swift-swim's `FacadeLock` byte-for-byte so
/// the whole P2P stack shares one lock story.

#if !hasFeature(Embedded)
import Synchronization

/// On host the facade lock is the standard `Synchronization.Mutex`.
typealias FacadeLock<Value> = Mutex<Value>

#else
import Synchronization

/// Embedded facade lock: an `Atomic<Bool>` spinlock guarding the stored value.
final class FacadeLock<Value>: Sendable {
    private let locked = Atomic<Bool>(false)
    private nonisolated(unsafe) var value: Value

    init(_ value: Value) {
        self.value = value
    }

    /// Runs `body` with exclusive access to the protected value.
    func withLock<R>(_ body: (inout Value) -> R) -> R {
        // Test-and-test-and-set acquire.
        while true {
            if locked.compareExchange(
                expected: false, desired: true, ordering: .acquiring
            ).exchanged {
                break
            }
        }
        defer { locked.store(false, ordering: .releasing) }
        return body(&value)
    }

    /// Runs a throwing `body` with exclusive access to the protected value.
    ///
    /// Mirrors `Synchronization.Mutex.withLock`'s rethrowing surface so the
    /// orchestrators' `throws`ing critical sections compile identically on both
    /// builds.
    func withLock<R, E: Error>(_ body: (inout Value) throws(E) -> R) throws(E) -> R {
        while true {
            if locked.compareExchange(
                expected: false, desired: true, ordering: .acquiring
            ).exchanged {
                break
            }
        }
        defer { locked.store(false, ordering: .releasing) }
        return try body(&value)
    }
}
#endif
