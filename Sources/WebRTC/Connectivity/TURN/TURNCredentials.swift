public struct TURNCredentials: Sendable, Equatable, Hashable {
    public static let maximumFieldByteCount = 512

    public let username: String
    public let password: String

    public init(
        username: String,
        password: String
    ) throws(TURNError) {
        guard !username.isEmpty,
              !password.isEmpty,
              username.utf8.count <= Self.maximumFieldByteCount,
              password.utf8.count <= Self.maximumFieldByteCount,
              !username.utf8.contains(0),
              !password.utf8.contains(0) else {
            throw .invalidCredential
        }
        self.username = username
        self.password = password
    }
}
