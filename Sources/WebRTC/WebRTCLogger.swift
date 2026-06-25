/// The facade's logger seam.
///
/// `swift-log`'s `Logging.Logger` is host-only (it imports Foundation), so the
/// facade addresses logging through `WebRTCLogger`:
///
///   host:     WebRTCLogger = Logging.Logger   (the real logger)
///   Embedded: WebRTCLogger = a no-op shim with the same surface
///
/// Both expose `debug` / `info` / `warning` / `error` taking an
/// `@autoclosure () -> String`, so every `logger.debug("…")` call site compiles
/// unchanged in both builds and the message is never evaluated under Embedded
/// (the closure is dropped). The Embedded shim has a labelled initialiser
/// matching `Logger(label:)` so call sites that construct a default logger
/// compile identically.
///
/// This mirrors swift-mDNS's `MDNSLogger` seam so the whole P2P stack shares one
/// logging story.

#if !hasFeature(Embedded)
import Logging

/// On host the facade logger is the standard `swift-log` `Logger`. The typealias
/// is `public` so it surfaces in the public initialisers exactly as `Logger`
/// did before the seam was introduced (binary- and source-compatible: `Logger`
/// IS `WebRTCLogger` on host).
public typealias WebRTCLogger = Logger

#else

/// Embedded no-op logger: the same `debug/info/warning/error` surface as
/// `swift-log`'s `Logger`, evaluating to nothing. Present only so logging call
/// sites type-check under Embedded; messages are never evaluated.
public struct WebRTCLogger: Sendable {
    public init(label: String) {}
    @inline(__always) public func debug(_ message: @autoclosure () -> String) {}
    @inline(__always) public func info(_ message: @autoclosure () -> String) {}
    @inline(__always) public func warning(_ message: @autoclosure () -> String) {}
    @inline(__always) public func error(_ message: @autoclosure () -> String) {}
}
#endif
