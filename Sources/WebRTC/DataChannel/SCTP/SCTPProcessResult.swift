
/// One ordered application delivery produced while processing an SCTP packet.
///
/// Reset boundaries are semantically significant: messages before the boundary,
/// the reset event, and held messages released after the boundary must not be
/// flattened into separate arrays that lose their relative order.
enum SCTPAssociationDelivery: Sendable {
    case message(SCTPReceivedMessage)
    case event(SCTPAssociationEvent)
}

/// The complete result of processing one SCTP packet.
struct SCTPProcessResult: Sendable {
    let responses: [SCTPPacket]
    let deliveries: [SCTPAssociationDelivery]

    init(
        responses: [SCTPPacket],
        deliveries: [SCTPAssociationDelivery]
    ) {
        self.responses = responses
        self.deliveries = deliveries
    }

    /// Compatibility projection for callers that do not consume reset events.
    var receivedData: [SCTPReceivedMessage] {
        var messages: [SCTPReceivedMessage] = []
        messages.reserveCapacity(deliveries.count)
        for delivery in deliveries {
            if case .message(let message) = delivery {
                messages.append(message)
            }
        }
        return messages
    }

    var events: [SCTPAssociationEvent] {
        var events: [SCTPAssociationEvent] = []
        events.reserveCapacity(deliveries.count)
        for delivery in deliveries {
            if case .event(let event) = delivery {
                events.append(event)
            }
        }
        return events
    }
}
