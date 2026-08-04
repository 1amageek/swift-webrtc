/// A set of SCTP streams selected for reconfiguration.
///
/// RFC 6525 encodes an empty stream list as "all streams". Keeping that case
/// symbolic avoids allocating an array containing every possible stream ID.
struct SCTPStreamSelection: Sendable, Equatable {
    private enum Storage: Sendable, Equatable {
        case all
        case listed([UInt16])
    }

    private let storage: Storage

    private init(storage: Storage) {
        self.storage = storage
    }

    static let all = Self(storage: .all)

    /// Select specific streams. Empty input is canonicalized to `.all`, matching
    /// the RFC wire meaning, and duplicate IDs are removed in ascending order.
    static func listed(_ streamIDs: [UInt16]) -> Self {
        guard !streamIDs.isEmpty else { return .all }
        return Self(storage: .listed(Array(Set(streamIDs)).sorted()))
    }

    init(wireStreamIDs: [UInt16]) {
        self = wireStreamIDs.isEmpty ? .all : .listed(wireStreamIDs)
    }

    var wireStreamIDs: [UInt16] {
        switch storage {
        case .all:
            []
        case .listed(let streamIDs):
            streamIDs
        }
    }

    func contains(_ streamID: UInt16) -> Bool {
        switch storage {
        case .all:
            true
        case .listed(let streamIDs):
            streamIDs.contains(streamID)
        }
    }
}
