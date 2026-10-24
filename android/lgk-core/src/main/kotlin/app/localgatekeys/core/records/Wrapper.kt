package app.localgatekeys.core.records

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.VersionVector
import app.localgatekeys.core.json.JsonValue

/** The item wrapper `{"ns", "schema", "updated_at", "record"}` (vectors README "Item wrapper"). */
object Wrapper {
    const val SCHEMA = 1L
    private val entryKinds = setOf("web", "desktop")
    private val unsyncedItemKinds = setOf("document")

    /** The engine's newest-edit rank: the record's int `updated_at` in 0..2^53-1, else 0. */
    fun rank(record: JsonValue): Long {
        val n = ((record as? JsonValue.Obj)?.fields?.get("updated_at") as? JsonValue.Int)?.v ?: return 0L
        return if (n in 0..VersionVector.MAX_COUNTER) n else 0L
    }

    /** Wraps a record; a licence always ranks 0. */
    fun make(ns: Namespace, record: JsonValue): JsonValue = JsonValue.Obj(
        mapOf(
            "ns" to JsonValue.Str(ns.wire),
            "schema" to JsonValue.Int(SCHEMA),
            "updated_at" to JsonValue.Int(if (ns == Namespace.LICENSE) 0L else rank(record)),
            "record" to record,
        ),
    )

    internal fun nsOf(record: Map<String, JsonValue>): Namespace {
        val k = (record["kind"] as? JsonValue.Str)?.v
        return if (k != null && k in entryKinds) Namespace.ENTRY else Namespace.ITEM
    }

    internal fun isLicenseId(id: String): Boolean = id.startsWith(License.ID_PREFIX)

    /**
     * Namespace and record of a live remote state (desktop `_unwrap`). A conflict copy ([isCopy]) gets the
     * copy id as its record id. Licences are verified against [licenseKeys].
     */
    fun unwrap(state: ItemState, isCopy: Boolean, licenseKeys: Map<String, ByteArray> = emptyMap()): Pair<Namespace, JsonValue> {
        val id = state.itemId
        fun bad(d: String) = RecordException("bad-remote", id, d)
        val item = (state.item as? JsonValue.Obj)?.fields
        // The schema comes first: a newer schema may add wrapper fields.
        val s0 = (item?.get("schema") as? JsonValue.Int)?.v
        if (s0 != null && s0 > SCHEMA) throw RecordException("update-needed", id, "written by a newer LocalGateKeys")
        val required = setOf("ns", "schema", "updated_at", "record")
        val allowed = if (isCopy) required + "id" else required
        if (item == null || !item.keys.containsAll(required) || !allowed.containsAll(item.keys)) throw bad("malformed wrapper")
        val schema = (item["schema"] as? JsonValue.Int)?.v
        if (schema == null || schema < 1) throw bad("malformed schema")
        if (item["ns"] == JsonValue.Str(Namespace.LICENSE.wire)) {
            return Namespace.LICENSE to unwrapLicense(state, item, isCopy, licenseKeys)
        }
        val ns = (item["ns"] as? JsonValue.Str)?.v?.let { Namespace.fromWire(it) }
        val recordObj = item["record"] as? JsonValue.Obj
        if (ns == null || ns == Namespace.LICENSE || recordObj == null || isLicenseId(id)) throw bad("malformed wrapper")
        val record = LinkedHashMap(recordObj.fields)
        val u = (item["updated_at"] as? JsonValue.Int)?.v
        if (u == null || u != rank(JsonValue.Obj(record))) throw bad("rank does not match its record")
        if (isCopy) {
            if (item["id"] != JsonValue.Str(id)) throw bad("malformed conflict copy")
            record["id"] = JsonValue.Str(id)
        } else if (record["id"] != JsonValue.Str(id)) {
            throw bad("state does not match its record")
        }
        if (nsOf(record) != ns) throw bad("wrong namespace")
        if (ns == Namespace.ITEM) {
            val k = (record["kind"] as? JsonValue.Str)?.v
            if (k != null && k in unsyncedItemKinds) throw bad("a kind that does not sync")
        }
        return ns to JsonValue.Obj(record)
    }

    private fun unwrapLicense(
        state: ItemState,
        item: Map<String, JsonValue>,
        isCopy: Boolean,
        keys: Map<String, ByteArray>,
    ): JsonValue {
        val id = state.itemId
        if (isCopy || item["id"] != null || !isLicenseId(id)) throw RecordException("bad-remote", id, "malformed licence state")
        if (item["updated_at"] != JsonValue.Int(0)) throw RecordException("bad-remote", id, "malformed licence state")
        val bundle = item.getValue("record")
        val info = try {
            License.verify(bundle, keys)
        } catch (e: LicenseException) {
            if (e.reason == "unknown-key" || e.reason == "bad-alg" || License.newerFormat(bundle, keys)) {
                throw RecordException("update-needed", id, "licence needs a newer LocalGateKeys")
            }
            throw RecordException("bad-remote", id, "licence does not verify (${e.reason})")
        }
        if (License.stateId(info.licenseId) != id) throw RecordException("bad-remote", id, "licence id mismatch")
        return bundle
    }
}
