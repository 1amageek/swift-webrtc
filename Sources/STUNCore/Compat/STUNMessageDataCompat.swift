/// `Data`-based convenience surface for the moved `STUNMessage` type, plus the
/// crypto-bearing `encodeWithIntegrity`.
///
/// Host-only: the `Data` surface is gated out of the Embedded build, which uses
/// the `[UInt8]` core primitives (`STUNMessage.encodeWithIntegrityBytes`,
/// `isSTUN([UInt8])`, `decode(from: [UInt8])`) directly.

#if !hasFeature(Embedded)
import Foundation
import STUNWireCore

extension STUNMessage {
    // MARK: - Defaulted convenience inits (random transaction ID)

    /// Creates a STUN message with a random transaction ID by default.
    public init(
        messageType: STUNMessageType,
        attributes: [STUNAttribute] = []
    ) {
        self.init(
            messageType: messageType,
            transactionID: .random(),
            attributes: attributes
        )
    }

    // MARK: - Binding Request (random transaction ID)

    /// Create a Binding Request
    public static func bindingRequest(
        username: String? = nil,
        priority: UInt32? = nil,
        useCandidate: Bool = false,
        iceControlling: UInt64? = nil,
        iceControlled: UInt64? = nil
    ) -> STUNMessage {
        var attrs: [STUNAttribute] = []

        if let username {
            attrs.append(.username(username))
        }
        if let priority {
            attrs.append(.priority(priority))
        }
        if useCandidate {
            attrs.append(.useCandidate())
        }
        if let tiebreaker = iceControlling {
            attrs.append(.iceControlling(tiebreaker: tiebreaker))
        }
        if let tiebreaker = iceControlled {
            attrs.append(.iceControlled(tiebreaker: tiebreaker))
        }

        return STUNMessage(
            messageType: .bindingRequest,
            transactionID: .random(),
            attributes: attrs
        )
    }

    /// Create a Binding Success Response from a `Data` address.
    public static func bindingSuccessResponse(
        transactionID: TransactionID,
        address: Data,
        port: UInt16
    ) -> STUNMessage {
        bindingSuccessResponse(
            transactionID: transactionID,
            address: [UInt8](address),
            port: port
        )
    }

    // MARK: - Data encoding

    /// Encode the STUN message to wire format as `Data`.
    public func encode() -> Data {
        Data(encodeBytes())
    }

    /// Check if these `Data` bytes are a STUN message.
    public static func isSTUN(_ data: Data) -> Bool {
        // Index relative to startIndex: the caller may pass a Data slice
        // (non-zero startIndex). Normalize to a zero-based array.
        isSTUN([UInt8](data))
    }

    /// Decode a STUN message from `Data` wire format.
    public static func decode(from input: Data) throws -> STUNMessage {
        // `[UInt8](input)` is always zero-based, so a Data slice with a non-zero
        // startIndex is normalized here (matching the historical behaviour).
        do {
            return try decode(from: [UInt8](input))
        } catch {
            try error.rethrowUnwrapped()
        }
    }

    // MARK: - Encode with MESSAGE-INTEGRITY and FINGERPRINT (crypto, adapter-side)

    /// Encode with MESSAGE-INTEGRITY and FINGERPRINT (`Data` surface).
    /// - Parameter key: The HMAC-SHA1 key (ICE password)
    /// - Returns: Encoded message with integrity and fingerprint
    ///
    /// Delegates to the Embedded-clean `[UInt8]` implementation
    /// (``encodeWithIntegrityBytes(key:)``) so both surfaces stay byte-identical.
    public func encodeWithIntegrity(key: Data) -> Data {
        Data(encodeWithIntegrityBytes(key: [UInt8](key)))
    }
}

// MARK: - STUNFingerprint (Data surface)

extension STUNFingerprint {
    /// Compute FINGERPRINT value over `Data`.
    public static func compute(data: Data) -> Data {
        Data(compute(data: [UInt8](data)))
    }

    /// Verify FINGERPRINT in a `Data` STUN message.
    public static func verify(message input: Data) -> Bool {
        // Normalize a possible Data slice to a zero-based array.
        verify(message: [UInt8](input))
    }
}

#endif
