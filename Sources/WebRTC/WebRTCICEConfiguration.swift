/// ICE behavior installed on one WebRTC connection.
///
/// The configuration owns credentials and role selection only. UDP routing,
/// signaling policy, and protocol-specific credential conventions remain the
/// responsibility of the caller.
public struct WebRTCICEConfiguration: Sendable, Equatable {
    enum Role: Sendable, Equatable {
        case prevalidated
        case lite
        case controlling
    }

    let role: Role
    let credentials: ICECredentials

    /// A datagram path whose peer reachability has already been established by
    /// an external transport contract. This mode exists for explicitly managed
    /// transports; Internet-facing WebRTC should use ICE Lite or controlling ICE.
    public static var prevalidated: WebRTCICEConfiguration {
        WebRTCICEConfiguration(
            role: .prevalidated,
            credentials: ICECredentials()
        )
    }

    /// Creates a controlled ICE Lite configuration that answers checks.
    public static func lite(
        credentials: ICECredentials
    ) -> WebRTCICEConfiguration {
        WebRTCICEConfiguration(role: .lite, credentials: credentials)
    }

    /// Creates a controlling ICE configuration that initiates checks.
    public static func controlling(
        credentials: ICECredentials
    ) -> WebRTCICEConfiguration {
        WebRTCICEConfiguration(role: .controlling, credentials: credentials)
    }
}
