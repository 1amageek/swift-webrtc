/// Fragment Assembler (RFC 4960 Section 6.9) — error-bridging adapter.
///
/// This is the host-side adapter over the Embedded-clean value type
/// ``SCTPWireCore/FragmentReassembler``. The core does all reassembly accounting
/// over `[UInt8]` payloads and throws the typed ``SCTPWireCore/SCTPStateError``;
/// this wrapper restores the historical surface by bridging that error back to
/// ``SCTPError`` so existing call sites (and the test suite) keep catching
/// `SCTPError`. Payloads remain `[UInt8]` on ``AssembledMessage`` and bridge to
/// `Data` at the consumption boundary via the `[UInt8] == Data` overloads.
///
/// Host-only: this `Data`/`SCTPError`-bridging surface exists for the historical
/// public API and the test suite. The Embedded path drives
/// `SCTPWireCore.FragmentReassembler` directly, so this wrapper is gated out of
/// the Embedded build.

#if !hasFeature(Embedded) && !os(WASI)
import Foundation

/// Reassembles fragmented messages.
///
/// A thin caller-driven wrapper around ``SCTPWireCore/FragmentReassembler`` that
/// bridges the core's typed `SCTPStateError` to the historical `SCTPError`.
struct FragmentAssembler: Sendable {
    /// The Embedded-clean reassembly state.
    private var state: FragmentReassembler

    init() {
        self.state = FragmentReassembler()
    }

    /// Configurable initializer (primarily for tests exercising the byte cap).
    init(maxBufferedBytes: Int) {
        self.state = FragmentReassembler(maxBufferedBytes: maxBufferedBytes)
    }

    /// Process a DATA chunk and return any complete messages.
    /// - Throws: `SCTPError.receiveBufferExceeded` if the peer exceeds reassembly
    ///   or reordering buffer limits.
    mutating func process(chunk: SCTPDataChunk) throws -> [AssembledMessage] {
        do {
            return try state.process(chunk: chunk)
        } catch {
            throw error.asSCTPError
        }
    }

    /// Total payload bytes currently held in reassembly and reorder buffers.
    var bufferedBytes: Int { state.bufferedBytes }

    /// Number of pending fragment groups.
    var pendingCount: Int { state.pendingCount }

    /// Garbage-collect abandoned incomplete fragment groups by TSN age.
    mutating func cleanup(currentTSN: UInt32) {
        state.cleanup(currentTSN: currentTSN)
    }

    /// Reset state for a stream.
    mutating func resetStream(_ streamID: UInt16) {
        state.resetStream(streamID)
    }
}

#endif
