struct TURNAuthenticationContext: Sendable, Equatable {
    let credentials: TURNCredentials
    let realm: String
    let nonce: String
    let integrityKey: [UInt8]

    init(
        credentials: TURNCredentials,
        realm: String,
        nonce: String
    ) throws(TURNError) {
        guard !realm.isEmpty,
              !nonce.isEmpty,
              realm.utf8.count <= TURNCredentials.maximumFieldByteCount,
              nonce.utf8.count <= TURNCredentials.maximumFieldByteCount,
              !realm.utf8.contains(0),
              !nonce.utf8.contains(0) else {
            throw .missingAuthenticationChallenge
        }
        self.credentials = credentials
        self.realm = realm
        self.nonce = nonce

        var keyMaterial: [UInt8] = []
        keyMaterial.reserveCapacity(
            credentials.username.utf8.count
                + realm.utf8.count
                + credentials.password.utf8.count
                + 2
        )
        keyMaterial.append(contentsOf: credentials.username.utf8)
        keyMaterial.append(0x3A)
        keyMaterial.append(contentsOf: realm.utf8)
        keyMaterial.append(0x3A)
        keyMaterial.append(contentsOf: credentials.password.utf8)
        self.integrityKey = TURNMD5.hash(keyMaterial)
    }

    var requestAttributes: [STUNAttribute] {
        [
            STUNAttribute(
                type: STUNAttributeType.username.rawValue,
                value: Array(credentials.username.utf8)
            ),
            STUNAttribute(
                type: STUNAttributeType.realm.rawValue,
                value: Array(realm.utf8)
            ),
            STUNAttribute(
                type: STUNAttributeType.nonce.rawValue,
                value: Array(nonce.utf8)
            ),
        ]
    }
}
