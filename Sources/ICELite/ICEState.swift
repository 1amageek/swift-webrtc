/// ICE State (RFC 8445)

import Foundation

/// ICE connection state
public enum ICEState: Sendable, Equatable {
    /// Initial state
    case new

    /// Connectivity checks are in progress
    case checking

    /// A valid pair has been found
    case connected

    /// ICE processing completed
    case completed

    /// ICE failed — no valid pair found
    case failed

    /// Connection closed
    case closed
}
