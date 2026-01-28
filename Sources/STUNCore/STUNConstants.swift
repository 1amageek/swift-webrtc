/// STUN Constants (RFC 5389)

import Foundation

/// STUN magic cookie value
public let stunMagicCookie: UInt32 = 0x2112A442

/// STUN message header size (20 bytes)
public let stunHeaderSize = 20

/// STUN attribute header size (4 bytes: type + length)
public let stunAttributeHeaderSize = 4

/// STUN message type class
public enum STUNClass: UInt16, Sendable {
    case request = 0x0000
    case indication = 0x0010
    case successResponse = 0x0100
    case errorResponse = 0x0110
}

/// STUN message type method
public enum STUNMethod: UInt16, Sendable {
    case binding = 0x0001
}

/// STUN attribute types
public enum STUNAttributeType: UInt16, Sendable {
    // Comprehension-required
    case mappedAddress = 0x0001
    case username = 0x0006
    case messageIntegrity = 0x0008
    case errorCode = 0x0009
    case unknownAttributes = 0x000A
    case realm = 0x0014
    case nonce = 0x0015
    case xorMappedAddress = 0x0020

    // Comprehension-optional
    case software = 0x8022
    case alternateServer = 0x8023
    case fingerprint = 0x8028

    // ICE attributes
    case priority = 0x0024
    case useCandidate = 0x0025
    case iceControlled = 0x8029
    case iceControlling = 0x802A
}

/// STUN error codes
public enum STUNErrorCode: UInt16, Sendable {
    case tryAlternate = 300
    case badRequest = 400
    case unauthorized = 401
    case unknownAttribute = 420
    case staleNonce = 438
    case serverError = 500
    case roleConflict = 487
}
