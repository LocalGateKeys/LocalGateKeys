/// A stored passkey item, read from a snapshot item (the sync wrapper `{"ns", ..., "record"}` or a bare
/// record). Reading never rewrites the item.
public struct PasskeyRecord: Sendable {
    public let itemID: String
    public let title: String
    public let rpID: String
    public let userName: String
    public let userHandle: [UInt8]
    public let credentialID: [UInt8]
    /// nil = not usable for sign-in (desktop `passkeys.usable_record`: ES256, a non-empty credential id of at
    /// most 1023 bytes, and a P-256 PKCS#8 private key).
    public let key: PasskeyKey?

    /// desktop `passkeys.MAX_CREDENTIAL_ID`
    static let maxCredentialID = 1023

    /// The stored form of a relying party id (stripped, casefolded), for matching what iOS passes.
    public static func normaliseRPID(_ rpID: String) -> String { Normalise.casefold(Normalise.pyStrip(rpID)) }

    /// nil for anything that is not a `passkey` item.
    public static func from(_ snapshotItem: JSONValue, id: String) -> PasskeyRecord? {
        guard case .object(var rec) = snapshotItem else { return nil }
        if case .object(let inner)? = rec["record"] { rec = inner }
        guard rec["kind"] == .string("passkey"), case .object(let p)? = rec["payload"] else { return nil }
        func str(_ v: JSONValue?) -> String { if case .string(let s)? = v { return s }; return "" }
        let credText = Normalise.pyStrip(str(p["credential_id"]))   // as the normaliser stores it
        let credentialID = decodeBase64URL(credText, maxBytes: maxCredentialID) ?? []
        var key: PasskeyKey?
        if p["algorithm"] == .string("ES256"), !credentialID.isEmpty, case .string(let k)? = p["private_key"] {
            key = PasskeyKey(pkcs8B64URL: k)
        }
        return PasskeyRecord(itemID: id, title: str(rec["title"]),
                             rpID: Normalise.casefold(Normalise.pyStrip(str(p["relying_party_id"]))),
                             userName: str(p["user_name"]),
                             userHandle: decodeBase64URL(Normalise.pyStrip(str(p["user_handle"])), maxBytes: 1024) ?? [],
                             credentialID: credentialID, key: key)
    }

    /// The item title and payload desktop `passkeys.create_credential` writes, plus the normaliser defaults
    /// (`notes`, `template_id`) so the payload is its own normal form. `today` is `YYYY-MM-DD`.
    public static func newPayload(rpID: String, rpName: String, userName: String, userDisplayName: String,
                                  userHandle: [UInt8], credentialID: [UInt8], key: PasskeyKey,
                                  today: String) -> (title: String, fields: JSONValue) {
        let rp = Normalise.casefold(Normalise.pyStrip(rpID))
        var title = rpName.isEmpty ? rp : rpName
        if !userName.isEmpty { title += " (\(userName))" }
        let fields: JSONValue = .object([
            "relying_party_id": .string(rp),
            "rp_name": .string(rpName),
            "user_handle": .string(base64URLNoPad(userHandle)),
            "user_name": .string(userName),
            "user_display_name": .string(userDisplayName),
            "credential_id": .string(base64URLNoPad(credentialID)),
            "private_key": .string(key.pkcs8B64URL),
            "algorithm": .string("ES256"),
            "created": .string(today),
            "discoverable": .bool(true),
            "notes": .string(""),
            "template_id": .null,
        ])
        return (title, fields)
    }
}
