import Foundation

/// Signed revoke notice for one `.lgkshare` package (LGKSHARE v1.1, desktop `share_revoke.py`). Best effort:
/// Ed25519 over `label + canonical JSON(body without sig)` with the sender's member signing key, like sync
/// removal notices. Notice: `{"format":1,"package_id","signer","issued_at","sig"}`, at most 1 KiB.
public enum ShareRevoke {
    public static let label = Array("localgatekeys|share|revoke-notice|v1|".utf8)
    public static let format: Int64 = 1
    public static let maxBytes = 1024
    public static let maxNotices = 512
    public static let directoryName = "revoked"
    public static let suffix = ".lgkrevoke"
    static let fields: Set<String> = ["format", "package_id", "signer", "issued_at", "sig"]

    /// `reason`: `bad-revoke`, `other-package` or `bad-signature` (desktop `RevokeError`).
    public struct RevokeError: Error, Equatable, Sendable {
        public let reason: String
        init(_ reason: String) { self.reason = reason }
    }

    /// The canonical lower-case UUID text, or nil.
    static func packageID(_ text: String) -> String? {
        guard let id = UUID(uuidString: text)?.uuidString.lowercased(), id == text else { return nil }
        return id
    }

    static func fieldsOf(_ raw: [UInt8]) throws -> [String: JSONValue] {
        guard raw.count <= maxBytes, case .object(let o)? = try? CanonicalJSON.parse(raw) else {
            throw RevokeError("bad-revoke")
        }
        return o
    }

    /// The revoked package id when `raw` is a notice for `packageID` signed by the raw Ed25519 `publicKey`.
    public static func verify(_ raw: [UInt8], publicKey: [UInt8], packageID expected: String) throws -> String {
        let o = try fieldsOf(raw)
        guard Set(o.keys) == fields, o["format"] == .int(format),
              case .int(_)? = o["issued_at"], case .string(_)? = o["signer"],
              case .string(let sigText)? = o["sig"] else { throw RevokeError("bad-revoke") }
        guard case .string(let idText)? = o["package_id"], let id = packageID(idText) else {
            throw RevokeError("bad-revoke")
        }
        guard id == expected else { throw RevokeError("other-package") }
        guard let sig = try? Base64.decodeStrict(sigText) else { throw RevokeError("bad-revoke") }
        let signed = label + (try CanonicalJSON.encode(.object(o.filter { $0.key != "sig" }), dialect: .utf8))
        guard DeviceIdentity.verify(signature: sig, message: signed, publicKey: publicKey) else {
            throw RevokeError("bad-signature")
        }
        return id
    }

    /// Package ids revoked by a trusted member (`trusted`: device id -> base64 Ed25519 public key). `files`: the
    /// entries of `LocalGateKeys Sync/revoked/`; only the first 512 `.lgkrevoke` names (sorted) are read. Never throws.
    public static func collect(files: [(name: String, data: [UInt8])], trusted: [String: String]) -> Set<String> {
        var out = Set<String>()
        let notices = files.filter { $0.name.hasSuffix(suffix) }.sorted { $0.name < $1.name }.prefix(maxNotices)
        for file in notices {
            guard file.data.count <= maxBytes, let o = try? fieldsOf(file.data),
                  case .string(let signer)? = o["signer"], let keyText = trusted[signer],
                  let key = try? Base64.decodeStrict(keyText),
                  case .string(let id)? = o["package_id"],
                  let revoked = try? verify(file.data, publicKey: key, packageID: id) else { continue }
            out.insert(revoked)
        }
        return out
    }
}
