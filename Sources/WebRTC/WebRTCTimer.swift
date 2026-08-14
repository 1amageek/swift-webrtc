import NetworkingTime

#if canImport(WASILibc)
import NetworkingWASI
typealias WebRTCDefaultTimer = WASIAsyncTimer
#elseif hasFeature(Embedded)
import NetworkingPOSIX
typealias WebRTCDefaultTimer = POSIXAsyncTimer
#else
typealias WebRTCDefaultTimer = ContinuousAsyncTimer
#endif

extension Duration {
    /// Whole non-negative nanoseconds with saturating arithmetic.
    var facadeNanoseconds: UInt64 {
        let (seconds, attoseconds) = components
        let positiveSeconds = UInt64(max(0, seconds))
        let (secondNanoseconds, multipliedOverflow) = positiveSeconds
            .multipliedReportingOverflow(by: 1_000_000_000)
        guard !multipliedOverflow else { return UInt64.max }
        let fractionalNanoseconds = UInt64(max(0, attoseconds) / 1_000_000_000)
        let (result, addedOverflow) = secondNanoseconds
            .addingReportingOverflow(fractionalNanoseconds)
        return addedOverflow ? UInt64.max : result
    }
}
