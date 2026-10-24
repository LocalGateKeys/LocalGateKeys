package app.localgatekeys.core.engine

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Identifier

/**
 * One item's sync state (desktop `engine.ItemState`). [vv] is stored without zero entries, so this is
 * a plain class with value equality rather than a `data class` (whose property would keep them).
 */
class ItemState(
    val itemId: String,
    vv: Map<String, Long>,
    val deleted: Boolean,
    val deletedAt: Long?,
    val item: JsonValue?,
) {
    val vv: Map<String, Long>

    init {
        if (!Identifier.isValid(itemId)) {
            throw EngineException("item_id must be 1..128 ASCII chars from [A-Za-z0-9._:-]")
        }
        VersionVector.check(vv)
        if (deletedAt != null && (deletedAt < 0 || deletedAt > VersionVector.MAX_COUNTER)) {
            throw EngineException("deleted_at must be None or an int in 0..2**53-1")
        }
        if (deleted != (item == null)) throw EngineException("item must be None exactly when deleted")
        if (item != null) {
            if (item !is JsonValue.Obj) throw EngineException("item must be a dict")
            checkJson(item, 0)
            try {
                CanonicalJson.encode(item, Dialect.UTF8)
            } catch (e: JsonException) {
                throw EngineException("item is not canonical-JSON safe: ${swiftName(e.kind)}")
            }
        }
        this.vv = vv.filterValues { it != 0L }
    }

    internal fun with(vv: Map<String, Long>, deletedAt: Long?): ItemState = ItemState(itemId, vv, deleted, deletedAt, item)

    override fun equals(other: Any?): Boolean =
        other is ItemState && itemId == other.itemId && vv == other.vv && deleted == other.deleted &&
            deletedAt == other.deletedAt && item == other.item

    override fun hashCode(): Int {
        var h = itemId.hashCode()
        h = 31 * h + vv.hashCode()
        h = 31 * h + deleted.hashCode()
        h = 31 * h + (deletedAt?.hashCode() ?: 0)
        h = 31 * h + (item?.hashCode() ?: 0)
        return h
    }

    /** Never shows the record: items hold plaintext secrets. */
    override fun toString(): String =
        "ItemState(itemId=$itemId, vv=$vv, deleted=$deleted, deletedAt=$deletedAt, item=${if (item == null) "null" else "<redacted>"})"

    companion object {
        /** Swift `JSONError` case spelling, so the message matches the iPhone's. */
        private fun swiftName(k: JsonException.Kind): String = when (k) {
            JsonException.Kind.DUPLICATE_KEY -> "duplicateKey"
            JsonException.Kind.NON_FINITE -> "nonFinite"
            JsonException.Kind.LONE_SURROGATE -> "loneSurrogate"
            JsonException.Kind.INT_OUT_OF_RANGE -> "intOutOfRange"
            JsonException.Kind.SYNTAX -> "syntax"
        }

        const val MAX_ITEM_INT: Long = Long.MAX_VALUE

        private fun checkJson(v: JsonValue, depth: Int) {
            if (depth > 64) throw EngineException("item nesting too deep")
            when (v) {
                JsonValue.Null, is JsonValue.Bool, is JsonValue.Str -> Unit
                is JsonValue.Int -> if (v.v < -MAX_ITEM_INT) throw EngineException("integer out of range")
                is JsonValue.Float -> if (!v.v.isFinite()) throw EngineException("non-finite float in item")
                is JsonValue.Arr -> for (x in v.items) checkJson(x, depth + 1)
                is JsonValue.Obj -> for (x in v.fields.values) checkJson(x, depth + 1)
            }
        }
    }
}
