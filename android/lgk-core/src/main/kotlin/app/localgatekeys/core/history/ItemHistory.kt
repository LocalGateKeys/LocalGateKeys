package app.localgatekeys.core.history

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.NormaliseException
import app.localgatekeys.core.records.PasswordHistory
import java.security.MessageDigest

/** A refused restore: [code] is `not_restorable` or `invalid_on_this_device` (contract §1.6). */
class HistoryException(val code: String) : Exception(code)

/**
 * Item history (feature pack contract 2026-11-15 §1): device-local snapshots of replaced versions, never synced. Rows are
 * kept as JSON objects exactly as the contract writes them (`snapshot_id`, `item_id`, `ns`, `created_at`, `change_type`,
 * `record`), so the byte cap is computed on the same canonical form on every platform.
 */
object ItemHistory {
    data class Limits(val maxVersions: Int, val maxAgeDays: Int, val maxBytes: Long)

    const val MIB = 1024L * 1024L
    val FREE = Limits(5, 30, 8 * MIB)
    val PRO = Limits(30, 365, 8 * MIB)

    fun limits(isPro: Boolean): Limits = if (isPro) PRO else FREE

    val CHANGE_TYPES = setOf("update", "sync", "restore", "import", "merge")

    /** Scope keys that are local trust state (`LOCAL_TRUST_SCOPE_KEYS`): never part of a diff or a history change. */
    val LOCAL_TRUST_SCOPE_KEYS = listOf(
        "sign_in_selector", "embedded_web_fill_approved", "browser_approval", "browser_approvals", "sync_pairing",
        "pairing_secret", "pairing_state",
    )

    /** Paths the diff ignores (§1.5); a path under one of them is ignored too. */
    val IGNORED: List<String> = listOf(
        "id", "created_at", "updated_at", "revision", "collection_ids", "password_history", "site_icon",
        "payload.document_ids", "policy.sign_in",
    ) + LOCAL_TRUST_SCOPE_KEYS.map { "scope.$it" }

    private val NOT_RESTORABLE = setOf("id", "kind", "created_at", "updated_at", "password_history")

    fun canon(v: JsonValue): ByteArray = CanonicalJson.encode(v, Dialect.UTF8)

    fun digest(v: JsonValue): String = Hex.lower(MessageDigest.getInstance("SHA-256").digest(canon(v)))

    // MARK: rows

    data class Row(val snapshotId: String, val itemId: String, val ns: String, val createdAt: Long, val changeType: String, val record: Map<String, JsonValue>) {
        fun json(): JsonValue = JsonValue.Obj(
            mapOf(
                "snapshot_id" to JsonValue.Str(snapshotId),
                "item_id" to JsonValue.Str(itemId),
                "ns" to JsonValue.Str(ns),
                "created_at" to JsonValue.Int(createdAt),
                "change_type" to JsonValue.Str(changeType),
                "record" to JsonValue.Obj(record),
            ),
        )

        /** Never shows the record. */
        override fun toString(): String = "HistoryRow(item=$itemId, at=$createdAt, type=$changeType)"

        companion object {
            /** Null for a row that is not one of ours (a lenient read never drops the rest). */
            fun of(v: JsonValue): Row? {
                val f = (v as? JsonValue.Obj)?.fields ?: return null
                fun s(k: String) = (f[k] as? JsonValue.Str)?.v
                return Row(
                    s("snapshot_id") ?: return null, s("item_id") ?: return null, s("ns") ?: return null,
                    (f["created_at"] as? JsonValue.Int)?.v ?: return null, s("change_type") ?: return null,
                    (f["record"] as? JsonValue.Obj)?.fields ?: return null,
                )
            }
        }
    }

    // MARK: prune (§1.4)

    private fun at(r: JsonValue): Long = ((r as? JsonValue.Obj)?.fields?.get("created_at") as? JsonValue.Int)?.v ?: 0L
    private fun sid(r: JsonValue): String = ((r as? JsonValue.Obj)?.fields?.get("snapshot_id") as? JsonValue.Str)?.v ?: ""
    private fun iid(r: JsonValue): String = ((r as? JsonValue.Obj)?.fields?.get("item_id") as? JsonValue.Str)?.v ?: ""

    /** `prune(rows, now, limits)`: age cut, per-item cap, then the byte cap. Kept rows stay in their input order. */
    fun prune(rows: List<JsonValue>, now: Long, limits: Limits): List<JsonValue> {
        val cutoff = now - limits.maxAgeDays.toLong() * 86_400L
        var kept: List<Int> = rows.indices.filter { at(rows[it]) >= cutoff }
        val newestFirst = Comparator<Int> { a, b ->
            val c = at(rows[b]).compareTo(at(rows[a]))
            if (c != 0) c else Scalars.compare(sid(rows[a]), sid(rows[b]))
        }
        val keep = HashSet<Int>()
        for ((_, group) in kept.groupBy { iid(rows[it]) }) keep.addAll(group.sortedWith(newestFirst).take(limits.maxVersions))
        kept = kept.filter { it in keep }
        val size = kept.associateWith { canon(rows[it]).size.toLong() }
        var total = size.values.sum()
        if (total > limits.maxBytes) {
            val drop = HashSet<Int>()
            for (i in oldest(kept, rows)) {
                if (total <= limits.maxBytes) break
                total -= size.getValue(i)
                drop.add(i)
            }
            kept = kept.filter { it !in drop }
        }
        return kept.map { rows[it] }
    }

    /** Indices in [kept], oldest first (`created_at` asc, then `snapshot_id` asc). */
    private fun oldest(kept: List<Int>, rows: List<JsonValue>): List<Int> = kept.sortedWith { a, b ->
        val c = at(rows[a]).compareTo(at(rows[b]))
        if (c != 0) c else Scalars.compare(sid(rows[a]), sid(rows[b]))
    }

    // MARK: diff (§1.5)

    data class Change(val field: String, val before: JsonValue?, val after: JsonValue?, val secret: Boolean) {
        /** Never shows values (they can be secrets). */
        override fun toString(): String = "Change(field=$field, secret=$secret)"
    }

    /** Flattened like `history._flatten`: objects recurse with dotted paths, a list is one field. */
    fun flatten(v: Map<String, JsonValue>?, prefix: String = "", out: MutableMap<String, JsonValue> = LinkedHashMap()): Map<String, JsonValue> {
        if (v == null) return out
        for ((k, value) in v) {
            val path = if (prefix.isEmpty()) k else "$prefix.$k"
            if (value is JsonValue.Obj) flatten(value.fields, path, out) else out[path] = value
        }
        return out
    }

    fun ignored(path: String): Boolean = IGNORED.any { path == it || path.startsWith("$it.") }

    private fun under(path: String, root: String): Boolean = path == root || path.startsWith("$root.")

    /** Whether [path] of a [kind] record is a secret (the diff masks it until revealed). */
    fun isSecret(kind: String, path: String): Boolean = when (kind) {
        "web", "desktop" -> listOf("password", "totp", "recovery_codes", "custom_fields", "notes").any { under(path, it) }
        "note" -> under(path, "payload.body") || under(path, "payload.fields")
        "card" -> listOf("payload.number", "payload.cvv", "payload.pin").any { under(path, it) }
        "bank_account" -> under(path, "payload.account_number") || under(path, "payload.pin")
        "identity" -> path.startsWith("payload.") && !under(path, "payload.template_id")
        "license" -> under(path, "payload.license_value") || under(path, "payload.notes")
        "ssh_key" -> under(path, "payload.private_key") || under(path, "payload.passphrase")
        "api_key" -> under(path, "payload.key") || under(path, "payload.secret")
        "wifi" -> under(path, "payload.password")
        "passkey" -> under(path, "payload.private_key") || under(path, "payload.user_handle")
        "bookmark" -> under(path, "payload.url") || under(path, "payload.notes")
        "purchase", "warranty", "subscription" -> under(path, "payload.notes")
        else -> false
    }

    const val PROTECTED = "[protected]"

    /**
     * `diff(before, after, kind)`: changed fields in code-point order of their path. With [reveal] false a secret's
     * values read [PROTECTED] (a missing side stays null).
     */
    fun diff(before: Map<String, JsonValue>?, after: Map<String, JsonValue>?, kind: String, reveal: Boolean = true): List<Change> {
        val a = flatten(before)
        val b = flatten(after)
        val out = ArrayList<Change>()
        for (path in (a.keys + b.keys).toSortedSet { x, y -> Scalars.compare(x, y) }) {
            if (ignored(path)) continue
            val x = a[path]
            val y = b[path]
            if (x == y) continue
            val secret = isSecret(kind, path)
            fun mask(v: JsonValue?) = if (secret && !reveal && v != null) JsonValue.Str(PROTECTED) else v
            out.add(Change(path, mask(x), mask(y), secret))
        }
        return out
    }

    // MARK: capture (§1.3)

    /** The record with local-only fields removed: two versions equal here differ only in what is never snapshotted. */
    fun comparable(record: Map<String, JsonValue>): Map<String, JsonValue> {
        val r = LinkedHashMap(record)
        r.remove("site_icon")
        r.remove("collection_ids")
        r.remove("revision")
        (r["scope"] as? JsonValue.Obj)?.let { s -> r["scope"] = JsonValue.Obj(s.fields - LOCAL_TRUST_SCOPE_KEYS.toSet()) }
        (r["policy"] as? JsonValue.Obj)?.let { p -> r["policy"] = JsonValue.Obj(p.fields - "sign_in") }
        return r
    }

    private fun wrapperParts(w: JsonValue?): Pair<String, Map<String, JsonValue>>? {
        val f = (w as? JsonValue.Obj)?.fields ?: return null
        val ns = (f["ns"] as? JsonValue.Str)?.v ?: return null
        if (ns != Namespace.ENTRY.wire && ns != Namespace.ITEM.wire) return null
        val r = (f["record"] as? JsonValue.Obj)?.fields ?: return null
        return ns to r
    }

    /**
     * The rows a commit from [before] to [after] (both id -> synced wrapper) adds: one per entry/item id present in
     * both whose record changed beyond local-only fields. Collection states, licences and heir plans are never
     * snapshotted (only `entry`/`item` wrappers are read). [newId] makes each `snapshot_id`.
     */
    fun captures(
        before: Map<String, JsonValue>,
        after: Map<String, JsonValue>,
        now: Long,
        changeType: String,
        newId: () -> String,
    ): List<JsonValue> {
        val out = ArrayList<JsonValue>()
        for (id in before.keys.sortedWith(Scalars::compare)) {
            val old = wrapperParts(before[id]) ?: continue
            val new = wrapperParts(after[id]) ?: continue
            if (canon(JsonValue.Obj(comparable(old.second))).contentEquals(canon(JsonValue.Obj(comparable(new.second))))) continue
            out.add(Row(newId(), id, old.first, now, changeType, old.second - "site_icon").json())
        }
        return out
    }

    // MARK: restore one field (§1.6)

    private fun setPath(rec: Map<String, JsonValue>, parts: List<String>, value: JsonValue?): Map<String, JsonValue> {
        val out = LinkedHashMap(rec)
        val head = parts.first()
        if (parts.size == 1) {
            if (value == null) out.remove(head) else out[head] = value
            return out
        }
        val child = (out[head] as? JsonValue.Obj)?.fields
        if (child == null && value == null) return out
        out[head] = JsonValue.Obj(setPath(child ?: emptyMap(), parts.drop(1), value))
        return out
    }

    private fun getPath(rec: Map<String, JsonValue>, parts: List<String>): JsonValue? {
        var cur: JsonValue? = JsonValue.Obj(rec)
        for (p in parts) cur = (cur as? JsonValue.Obj)?.fields?.get(p) ?: return null
        return cur
    }

    /**
     * `restore_field(current, snapshot_record, path, now)`: the record with [path] taken from the snapshot (checked by normalising).
     * Throws [HistoryException] (`not_restorable`, `invalid_on_this_device`).
     */
    fun restoreField(current: Map<String, JsonValue>, snapshot: Map<String, JsonValue>, path: String, now: Long): Map<String, JsonValue> {
        val parts = path.split(".")
        if (path.isEmpty() || parts.any { it.isEmpty() } || parts.first() in NOT_RESTORABLE || ignored(path)) {
            throw HistoryException("not_restorable")
        }
        var r = setPath(current, parts, getPath(snapshot, parts))
        if (path == "password") {
            val old = (current["password"] as? JsonValue.Str)?.v ?: ""
            r = PasswordHistory.push(r, old, now)
        }
        r = LinkedHashMap(r).apply { put("updated_at", JsonValue.Int(now)) }
        val kind = (r["kind"] as? JsonValue.Str)?.v
        val ns = if (kind == "web" || kind == "desktop") Namespace.ENTRY else Namespace.ITEM
        return try {
            // Validate only: the restored record keeps its own shape (no defaults added), as the vectors expect.
            Normalise.normalForm(ns, JsonValue.Obj(r)) as? JsonValue.Obj ?: throw HistoryException("invalid_on_this_device")
            r
        } catch (e: NormaliseException) {
            throw HistoryException("invalid_on_this_device")
        } catch (e: HistoryException) {
            throw e
        } catch (e: Exception) {
            throw HistoryException("invalid_on_this_device")
        }
    }
}
