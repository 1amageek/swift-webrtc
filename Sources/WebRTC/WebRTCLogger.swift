/// The facade's logger seam.
///
/// The facade addresses logging through `WebRTCLogger` so builds that do not
/// carry the `swift-log` dependency retain the same call-site surface:
///
///   Native:          WebRTCLogger = Logging.Logger
///   WASI/Embedded:   WebRTCLogger = a no-op shim with the same surface
///
/// Both expose `debug` / `info` / `warning` / `error` taking an
/// `@autoclosure () -> String`, so every `logger.debug("…")` call site compiles
/// unchanged in every build and the message is never evaluated by the no-op
/// implementation (the closure is dropped). The shim has a labelled initialiser
/// matching `Logger(label:)` so call sites construct it identically.
///
/// This mirrors swift-mDNS's `MDNSLogger` seam so the whole P2P stack shares one
/// logging story.

#if canImport(Logging)
import Logging

/// On Native platforms the facade logger is the standard `swift-log` `Logger`.
/// The typealias is `public` so it surfaces in the public initialisers exactly
/// as `Logger` did before the seam was introduced.
public typealias WebRTCLogger = Logger

#else

/// WASI / Embedded no-op logger with the same `debug/info/warning/error`
/// surface as `swift-log`'s `Logger`. Messages are never evaluated.
public struct WebRTCLogger: Sendable {
    public init(label: String) {}
    @inline(__always) public func debug(_ message: @autoclosure () -> String) {}
    @inline(__always) public func info(_ message: @autoclosure () -> String) {}
    @inline(__always) public func warning(_ message: @autoclosure () -> String) {}
    @inline(__always) public func error(_ message: @autoclosure () -> String) {}
}
#endif
