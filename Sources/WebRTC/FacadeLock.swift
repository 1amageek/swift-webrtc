import Synchronization

/// The facade's value-protecting lock.
///
/// Native, WASM, and Embedded builds use the same storage and isolation
/// contract. Target-specific mutex behavior belongs to the linked Swift
/// platform implementation, not this framework layer.
typealias FacadeLock<Value> = Mutex<Value>
