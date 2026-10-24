import Crypto

public enum ConflictCopy {
    /// Desktop `conflict_copy_id`; delegates to `UUID5.conflictCopyID`. An empty digest is rejected.
    public static func id(itemID: String, contentDigest: String) throws -> String {
        guard !itemID.isEmpty, !contentDigest.isEmpty else {
            throw EngineError("item_id and content_digest must be non-empty strings")
        }
        return UUID5.conflictCopyID(itemID: itemID, contentDigest: contentDigest)
    }

    /// sha256 hex of canonical JSON of the item without its top-level "id" (desktop `_content_digest`).
    public static func contentDigest(_ item: JSONValue) throws -> String {
        guard case .object(var o) = item else { throw EngineError("item must be a dict") }
        o.removeValue(forKey: "id")
        return try Engine.sha256Hex(.object(o))
    }
}
