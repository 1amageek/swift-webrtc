/// Result codes for an SCTP stream reconfiguration response (RFC 6525 §4.4).
///
/// This is a raw-value struct rather than a closed enum so a future result code
/// remains observable without being collapsed into a generic decode failure.
public struct SCTPReconfigurationResult: RawRepresentable, Sendable, Equatable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    public static let successNothingToDo = Self(rawValue: 0)
    public static let successPerformed = Self(rawValue: 1)
    public static let denied = Self(rawValue: 2)
    public static let errorWrongSSN = Self(rawValue: 3)
    public static let errorRequestAlreadyInProgress = Self(rawValue: 4)
    public static let errorBadSequenceNumber = Self(rawValue: 5)
    public static let inProgress = Self(rawValue: 6)

    public var isSuccess: Bool {
        self == .successNothingToDo || self == .successPerformed
    }
}
