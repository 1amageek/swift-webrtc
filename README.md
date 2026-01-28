# swift-webrtc

A pure Swift implementation of WebRTC data channels.

Built entirely from scratch — no C/C++ WebRTC library dependency. Implements the full protocol stack required for WebRTC Direct data channel communication:

```
UDP → STUN / ICE Lite → DTLS 1.2 → SCTP → Data Channels
```

## Requirements

- Swift 6.2+
- macOS 15+ / iOS 18+ / tvOS 18+ / watchOS 11+ / visionOS 2+

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/1amageek/swift-webrtc.git", from: "0.0.1"),
]
```

## Architecture

The library is split into independent modules:

| Module | Description | RFC |
|---|---|---|
| **STUNCore** | STUN message encoding/decoding, MESSAGE-INTEGRITY, FINGERPRINT | [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) |
| **ICELite** | ICE Lite agent for server-side connectivity checks | [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445) |
| **SCTPCore** | SCTP association, chunk encoding/decoding, stream management | [RFC 4960](https://datatracker.ietf.org/doc/html/rfc4960) |
| **DataChannel** | Data channel lifecycle, DCEP (open/ack) messages | [RFC 8831](https://datatracker.ietf.org/doc/html/rfc8831) |
| **WebRTC** | Top-level API integrating all layers | — |

DTLS is provided by [swift-tls](https://github.com/1amageek/swift-tls).

## Usage

### Creating an endpoint

```swift
import WebRTC

let endpoint = try WebRTCEndpoint.create()
print(endpoint.localFingerprint.sdpFormat)
```

### Client

```swift
let connection = try endpoint.connect(
    remoteFingerprint: remoteFingerprint,
    sendHandler: { data in
        // Send raw bytes over UDP
    }
)

connection.setRemoteICECredentials(ufrag: remoteUfrag, password: remotePassword)
try connection.start()

let channel = try connection.openDataChannel(label: "data")
try connection.send(payload, on: channel.id)
```

### Server

```swift
let listener = try endpoint.listen()

for await connection in listener.connections {
    try connection.start()

    for await channel in connection.incomingChannels {
        print("Channel opened: \(channel.label)")
    }
}
```

## Design

- **Transport-agnostic** — Callers provide a `SendHandler` closure and feed incoming bytes via `receive(_:)`. This allows integration with any UDP transport.
- **Sendable** — All public types conform to `Sendable`. Thread safety is achieved using `Mutex<T>`.
- **Modular** — Each protocol layer is a standalone library that can be used independently.

## License

MIT
