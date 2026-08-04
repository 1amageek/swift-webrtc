/// Dynamically allocated ring storage with a fixed DataChannel event limit.
///
/// Removing an event clears its slot immediately, releasing the event and its
/// payload owner even when producers keep the queue continuously non-empty.
/// Moving event values during growth retains existing payload COW storage and
/// never materializes payload bytes.
struct WebRTCDataChannelEventQueue: Sendable {
    private var storage: [WebRTCDataChannelEvent?]
    private var headIndex = 0
    private(set) var count = 0
    let maximumCount: Int

    init(maximumCount: Int, initialCapacity: Int = 16) {
        precondition(maximumCount > 0)
        precondition(initialCapacity > 0)
        self.maximumCount = maximumCount
        self.storage = Array(
            repeating: nil,
            count: min(maximumCount, initialCapacity)
        )
    }

    var allocatedSlotCount: Int { storage.count }

    mutating func append(_ event: WebRTCDataChannelEvent) -> Bool {
        guard count < maximumCount else { return false }
        growIfNeeded()
        let index = (headIndex + count) % storage.count
        storage[index] = event
        count += 1
        return true
    }

    mutating func append(
        contentsOf events: [WebRTCDataChannelEvent]
    ) -> Bool {
        guard events.count <= maximumCount - count else { return false }
        for event in events {
            precondition(append(event))
        }
        return true
    }

    mutating func popFirst() -> WebRTCDataChannelEvent? {
        guard count > 0 else { return nil }
        let event = storage[headIndex]
        storage[headIndex] = nil
        headIndex = (headIndex + 1) % storage.count
        count -= 1
        if count == 0 {
            headIndex = 0
        }
        return event
    }

    mutating func drain() -> [WebRTCDataChannelEvent] {
        var events: [WebRTCDataChannelEvent] = []
        events.reserveCapacity(count)
        while let event = popFirst() {
            events.append(event)
        }
        return events
    }

    mutating func removeAll(keepingCapacity: Bool = false) {
        if keepingCapacity {
            for index in storage.indices {
                storage[index] = nil
            }
        } else {
            storage = Array(
                repeating: nil,
                count: min(maximumCount, 16)
            )
        }
        headIndex = 0
        count = 0
    }

    private mutating func growIfNeeded() {
        guard count == storage.count,
              storage.count < maximumCount else { return }
        let doubled = storage.count.multipliedReportingOverflow(by: 2)
        let proposed = doubled.overflow
            ? maximumCount
            : doubled.partialValue
        let newCapacity = min(
            maximumCount,
            max(storage.count + 1, proposed)
        )
        var replacement = Array<WebRTCDataChannelEvent?>(
            repeating: nil,
            count: newCapacity
        )
        for offset in 0..<count {
            let sourceIndex = (headIndex + offset) % storage.count
            replacement[offset] = storage[sourceIndex]
            storage[sourceIndex] = nil
        }
        storage = replacement
        headIndex = 0
    }
}
