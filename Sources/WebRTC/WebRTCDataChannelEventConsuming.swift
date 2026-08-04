/// The sole ordered reader for one WebRTC connection's DataChannel events.
///
/// A consumer owns exactly one underlying iterator. Copying the protocol
/// existential preserves that same owner instead of creating another iterator.
public protocol WebRTCDataChannelEventConsuming: AnyObject, Sendable {
    /// Waits for the next ordered OPEN, DATA, or CLOSE event.
    ///
    /// Only one suspended read may exist at a time. Concurrent reads fail
    /// explicitly instead of dividing events between competing callers. A
    /// clean connection close returns `nil`; a failed connection throws its
    /// authoritative `WebRTCError` rather than normalizing failure to closure.
    func next()
        async throws(WebRTCError) -> WebRTCDataChannelEvent?

    /// Abandons every buffered event and terminates future reads.
    ///
    /// The consumer releases its payload budget exactly once for each discarded
    /// event. Owners that stop reading before terminal drain must call this
    /// method so queued payload storage is not retained until connection release.
    func discardRemainingEvents()
}
