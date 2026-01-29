# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Build
swift build

# Run all tests (use timeout to prevent hangs)
timeout 60 swift test

# Run tests for a specific module
timeout 30 swift test --filter STUNCoreTests
timeout 30 swift test --filter ICELiteTests
timeout 30 swift test --filter SCTPCoreTests
timeout 30 swift test --filter DataChannelTests
timeout 30 swift test --filter WebRTCTests
```

## Architecture

This is a pure Swift WebRTC data channel implementation with no C/C++ dependencies. The protocol stack is:

```
UDP → STUN / ICE Lite → DTLS 1.2 → SCTP → Data Channels
```

### Module Hierarchy

```
WebRTC (top-level API)
├── STUNCore      - STUN message encoding/decoding (RFC 5389)
├── ICELite       - Server-side ICE connectivity checks (RFC 8445)
├── SCTPCore      - SCTP association and stream management (RFC 4960)
├── DataChannel   - Data channel lifecycle and DCEP messages (RFC 8831)
└── DTLSCore/DTLSRecord (external: swift-tls)
```

### Key Classes

- **WebRTCEndpoint** (`Sources/WebRTC/WebRTCEndpoint.swift`) - Entry point. Creates connections and listeners. Owns the DTLS certificate.

- **WebRTCConnection** (`Sources/WebRTC/WebRTCConnection.swift`) - Integrates the full protocol stack. Demultiplexes STUN/DTLS by first byte, handles ICE, DTLS handshake, SCTP association, and data channel management.

- **ICELiteAgent** (`Sources/ICELite/ICELiteAgent.swift`) - Responds to ICE connectivity checks. Server-side only (no active candidate gathering).

- **SCTPAssociation** (`Sources/SCTPCore/SCTPAssociation.swift`) - Manages SCTP state machine, TSN tracking, and stream sequence numbers.

- **DataChannelManager** (`Sources/DataChannel/DataChannel.swift`) - Handles DCEP (Data Channel Establishment Protocol) open/ack messages.

### Design Principles

- **Transport-agnostic**: Callers provide a `SendHandler` closure for outgoing data and call `receive(_:)` for incoming. No UDP socket binding inside the library.

- **Sendable + Mutex**: All public types are `Sendable`. Thread safety uses `Synchronization.Mutex<T>` (not actors for high-frequency internal state).

- **AsyncStream for incoming channels**: `WebRTCConnection.incomingChannels` provides an async stream. The class must call `continuation.finish()` on close to prevent hangs.

### Protocol Demultiplexing

`WebRTCConnection.receive(_:)` demultiplexes by first byte (RFC 5764 §5.1.2):
- `20-63`: DTLS record
- `0-3` (and `isSTUN` check): STUN message
