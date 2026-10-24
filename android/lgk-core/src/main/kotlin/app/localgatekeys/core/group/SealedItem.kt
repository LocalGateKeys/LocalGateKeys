package app.localgatekeys.core.group

import app.localgatekeys.core.engine.EngineException
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.VersionVector
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.CryptoBoxException
import app.localgatekeys.core.primitives.RandomSource

/** Sealed item records (desktop `sync.group.seal_item` / `open_item`). */
object SealedItem {
    const val LABEL = "lgk-sync-item-v1"
    internal const val NONCE_LENGTH = 12
    internal const val TAG_LENGTH = 16
    private val FIELDS = setOf("id", "vv", "deleted", "deleted_at", "ct")

    internal fun isInt(v: JsonValue?): Boolean = v is JsonValue.Int && v.v in 0..VersionVector.MAX_COUNTER

    private fun aad(id: JsonValue, vv: JsonValue, deleted: Boolean, deletedAt: JsonValue, epoch: Long): ByteArray =
        CanonicalJson.encode(
            JsonValue.Obj(
                mapOf(
                    "label" to JsonValue.Str(LABEL), "id" to id, "vv" to vv, "deleted" to JsonValue.Bool(deleted),
                    "deleted_at" to deletedAt, "epoch" to JsonValue.Int(epoch),
                ),
            ),
            Dialect.UTF8,
        )

    internal fun nonce(random: RandomSource): ByteArray {
        val n = random.bytes(NONCE_LENGTH)
        if (n.size != NONCE_LENGTH) throw SyncFormatException("bad-nonce", "nonce source must return exactly $NONCE_LENGTH bytes")
        return n
    }

    /** Encrypts one state under the record key with the given nonce. */
    fun seal(key: GroupKey, state: ItemState, nonce: ByteArray): JsonValue {
        val vv = JsonValue.Obj(state.vv.mapValues { JsonValue.Int(it.value) })
        val at: JsonValue = state.deletedAt?.let { JsonValue.Int(it) } ?: JsonValue.Null
        val aad = aad(JsonValue.Str(state.itemId), vv, state.deleted, at, key.epoch)
        val plain = if (state.deleted) ByteArray(0) else CanonicalJson.encode(state.item!!, Dialect.UTF8)
        val body = CryptoBox.sealGcm(key.recordKey, nonce, plain, aad)
        return JsonValue.Obj(
            mapOf(
                "id" to JsonValue.Str(state.itemId), "vv" to vv, "deleted" to JsonValue.Bool(state.deleted),
                "deleted_at" to at, "ct" to JsonValue.Str(Base64Std.encode(nonce + body)),
            ),
        )
    }

    /** Validates and decrypts a sealed record; reasons and their order follow the desktop. */
    fun open(key: GroupKey, sealed: JsonValue, recordKey: ByteArray? = null): ItemState {
        val o = (sealed as? JsonValue.Obj)?.fields
        if (o == null || o.keys != FIELDS) {
            throw SyncFormatException("bad-fields", "sealed item must have exactly id, vv, deleted, deleted_at, ct")
        }
        val itemId = (o["id"] as? JsonValue.Str)?.v
        val vvRaw = (o["vv"] as? JsonValue.Obj)?.fields
        val deleted = (o["deleted"] as? JsonValue.Bool)?.v
        if (itemId == null || vvRaw == null || deleted == null) throw SyncFormatException("bad-fields", "id/vv/deleted types")
        val deletedAtRaw = o.getValue("deleted_at")
        if (deletedAtRaw != JsonValue.Null && !isInt(deletedAtRaw)) throw SyncFormatException("bad-fields", "deleted_at")
        val ct = (o["ct"] as? JsonValue.Str)?.v ?: throw SyncFormatException("bad-fields", "ct must be a string")
        val deletedAt = (deletedAtRaw as? JsonValue.Int)?.v
        val vv = HashMap<String, Long>()
        for ((k, v) in vvRaw) {
            if (v !is JsonValue.Int) throw SyncFormatException("invalid-state", "vv counter for $k must be an int")
            vv[k] = v.v
        }
        invalidState { ItemState(itemId, vv, true, deletedAt, null) }
        if (ct.isEmpty()) throw SyncFormatException("empty-ct", "every state needs authenticated ciphertext")
        if (!deleted && deletedAt != null) throw SyncFormatException("invalid-state", "live item must not carry deleted_at")
        val raw = try {
            Base64Std.decodeStrict(ct)
        } catch (e: Base64Exception) {
            throw SyncFormatException("bad-ct", "ciphertext is not canonical base64")
        }
        if (raw.size < NONCE_LENGTH + TAG_LENGTH) throw SyncFormatException("bad-ct", "ciphertext too short")
        val aad = aad(JsonValue.Str(itemId), JsonValue.Obj(vvRaw), deleted, deletedAtRaw, key.epoch)
        val plain = try {
            CryptoBox.openGcm(recordKey ?: key.recordKey, raw.copyOfRange(0, NONCE_LENGTH), raw.copyOfRange(NONCE_LENGTH, raw.size), aad)
        } catch (e: CryptoBoxException) {
            throw SyncFormatException("auth-failed", "item authentication failed")
        }
        if (deleted) {
            if (plain.isNotEmpty()) throw SyncFormatException("bad-item", "tombstone plaintext must be empty")
            return invalidState { ItemState(itemId, vv, true, deletedAt, null) }
        }
        val item = try {
            CanonicalJson.parse(plain)
        } catch (e: JsonException) {
            // The desktop's json.loads accepts these; it then fails them in ItemState.
            if (e.kind == JsonException.Kind.NON_FINITE || e.kind == JsonException.Kind.INT_OUT_OF_RANGE ||
                e.kind == JsonException.Kind.LONE_SURROGATE
            ) {
                throw SyncFormatException("invalid-state", "item is not canonical-JSON safe")
            }
            throw SyncFormatException("bad-item", "item plaintext is not valid JSON")
        }
        val body = (item as? JsonValue.Obj)?.fields ?: throw SyncFormatException("bad-item", "item plaintext must be an object")
        val id = body["id"]
        if (id != null) {
            if (id != JsonValue.Str(itemId)) throw SyncFormatException("id-mismatch", "item id differs from sealed id")
        } else {
            val record = (body["record"] as? JsonValue.Obj)?.fields
            val rid = record?.get("id")
            if (rid != null && rid != JsonValue.Str(itemId)) throw SyncFormatException("id-mismatch", "record id differs from sealed id")
        }
        return invalidState { ItemState(itemId, vv, false, null, item) }
    }

    private inline fun invalidState(make: () -> ItemState): ItemState = try {
        make()
    } catch (e: EngineException) {
        throw SyncFormatException("invalid-state", e.message ?: "")
    }
}
