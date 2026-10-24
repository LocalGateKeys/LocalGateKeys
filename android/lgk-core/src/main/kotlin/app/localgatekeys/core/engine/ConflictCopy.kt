package app.localgatekeys.core.engine

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.UUID5

object ConflictCopy {
    /** Desktop `conflict_copy_id`; delegates to [UUID5.conflictCopyId]. An empty id or digest is rejected. */
    fun id(itemId: String, contentDigest: String): String {
        if (itemId.isEmpty() || contentDigest.isEmpty()) {
            throw EngineException("item_id and content_digest must be non-empty strings")
        }
        return UUID5.conflictCopyId(itemId, contentDigest)
    }

    /** sha256 hex of canonical JSON of the item without its top-level "id" (desktop `_content_digest`). */
    fun contentDigest(item: JsonValue): String {
        if (item !is JsonValue.Obj) throw EngineException("item must be a dict")
        return Engine.sha256Hex(JsonValue.Obj(item.fields - "id"))
    }
}
