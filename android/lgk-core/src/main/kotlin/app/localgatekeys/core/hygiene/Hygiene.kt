package app.localgatekeys.core.hygiene

import app.localgatekeys.core.access.AccessRules
import app.localgatekeys.core.history.ItemHistory
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Casefold
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.PasswordHistory
import app.localgatekeys.core.records.PyStrip
import java.time.LocalDate

/** A refused merge: [code] is `too_many_tags`, `too_many_values`, `notes_too_long` or `not_mergeable`. */
class MergeException(val code: String) : Exception(code)

/**
 * The clean-up sweep (feature pack contract 2026-11-15 §3): duplicates, "not changed in 2 years" and expired items,
 * computed on demand from what is stored, with no network access. Desktop logins are skipped.
 */
object Hygiene {
    const val SAME_LOGIN = "same_login"
    const val SAME_ACCOUNT_OTHER_PASSWORD = "same_account_other_password"
    const val SAME_SITE = "same_site"
    const val SAME_ITEM = "same_item"
    const val NOT_CHANGED_2Y = "not_changed_2y"
    const val EXPIRED = "expired"

    val DUPLICATE_TYPES = setOf(SAME_LOGIN, SAME_ACCOUNT_OTHER_PASSWORD, SAME_SITE, SAME_ITEM)

    /** Collection ids a merged typed item may carry (Python `hygiene.MAX_COLLECTIONS`). */
    const val MAX_COLLECTIONS = 20

    data class Finding(val type: String, val ids: List<String>)

    private typealias Rec = Map<String, JsonValue>

    private fun str(v: JsonValue?): String = (v as? JsonValue.Str)?.v ?: ""
    private fun obj(v: JsonValue?): Rec = (v as? JsonValue.Obj)?.fields ?: emptyMap()
    private fun id(r: Rec): String = str(r["id"])
    private fun kind(r: Rec): String = str(r["kind"])
    private fun updated(r: Rec): Long = (r["updated_at"] as? JsonValue.Int)?.v ?: 0L
    fun fold(s: String): String = Casefold.fold(PyStrip.strip(s))

    /** Ids sorted by `updated_at` desc, then id. */
    fun order(records: List<Rec>): List<String> = records.sortedWith { a, b ->
        val c = updated(b).compareTo(updated(a))
        if (c != 0) c else Scalars.compare(id(a), id(b))
    }.map(::id)

    /**
     * Every finding over [records] (each carries its `id`). [baseDomainOf] is the registrable domain of an origin
     * (`UrlMatcher.baseDomainOf`); it may throw for a malformed origin (then that login takes no part in `same_site`).
     */
    fun findings(records: List<Rec>, now: Long, today: LocalDate, baseDomainOf: (String) -> String): List<Finding> {
        val live = records.filter { kind(it) != "desktop" && id(it).isNotEmpty() }
        return duplicates(live, baseDomainOf) + listOfNotNull(notChanged(live, now), expired(live, today))
    }

    fun duplicates(records: List<Rec>, baseDomainOf: (String) -> String): List<Finding> {
        val out = ArrayList<Finding>()
        val logins = records.filter { kind(it) == "web" }
        // same_login / same_account_other_password: the importer key (origin, username).
        for ((_, group) in logins.groupBy { str(obj(it["scope"])["origin"]) to fold(str(it["username"])) }) {
            if (group.size < 2) continue
            val byPassword = group.groupBy { str(it["password"]) }
            for ((_, same) in byPassword) if (same.size >= 2) out.add(Finding(SAME_LOGIN, order(same)))
            if (byPassword.size > 1) out.add(Finding(SAME_ACCOUNT_OTHER_PASSWORD, order(group)))
        }
        // same_site: one username on related addresses (different origins, same registrable domain).
        val keyed = logins.mapNotNull { r ->
            val user = fold(str(r["username"]))
            if (user.isEmpty()) return@mapNotNull null
            val origin = str(obj(r["scope"])["origin"])
            val base = try {
                baseDomainOf(origin)
            } catch (e: Exception) {
                return@mapNotNull null
            }
            if (base.isEmpty()) null else Triple(user to base, origin, r)
        }
        for ((_, group) in keyed.groupBy { it.first }) {
            if (group.map { it.second }.toSet().size < 2) continue
            out.add(Finding(SAME_SITE, order(group.map { it.third })))
        }
        // same_item: typed items.
        val items = records.filter { kind(it) != "web" && kind(it) != "desktop" }
        for ((_, group) in items.groupBy(::itemKey)) {
            if (group.size >= 2 && itemKey(group[0]) != null) out.add(Finding(SAME_ITEM, order(group)))
        }
        return out.filter { it.ids.size >= 2 }
    }

    /** The `same_item` key of a typed item; null never matches. */
    private fun itemKey(r: Rec): List<Any>? {
        val p = obj(r["payload"])
        return when (kind(r)) {
            "passkey" -> {
                val rp = fold(str(p["relying_party_id"]))
                val cred = str(p["credential_id"])
                if (rp.isEmpty() && cred.isEmpty()) null else listOf("passkey", rp, cred)
            }
            "card" -> str(p["number"]).takeIf { it.isNotEmpty() }?.let { listOf("card", it) }
            else -> {
                val rest = JsonValue.Obj(p - "notes" - "template_id" - "document_ids")
                listOf(kind(r), fold(str(r["title"])), String(ItemHistory.canon(rest), Charsets.UTF_8))
            }
        }
    }

    fun notChanged(records: List<Rec>, now: Long): Finding? {
        val old = records.filter { updated(it) < now - 730L * 86_400L }
        return if (old.isEmpty()) null else Finding(NOT_CHANGED_2Y, order(old))
    }

    fun expired(records: List<Rec>, today: LocalDate): Finding? {
        val gone = records.filter { isExpired(it, today) }
        return if (gone.isEmpty()) null else Finding(EXPIRED, order(gone))
    }

    /** A `YYYY-MM-DD` or `YYYYMMDD` date; week dates and anything else are null (never compared). */
    fun date(s: String): LocalDate? {
        val t = when {
            s.length == 10 && s[4] == '-' && s[7] == '-' -> s
            s.length == 8 && s.all { it in '0'..'9' } -> "${s.substring(0, 4)}-${s.substring(4, 6)}-${s.substring(6)}"
            else -> return null
        }
        return AccessRules.isoDate(t)
    }

    fun isExpired(r: Rec, today: LocalDate): Boolean {
        val p = obj(r["payload"])
        return when (kind(r)) {
            "card" -> {
                val m = Regex("^\\s*(\\d{1,2})\\s*/\\s*(\\d{2}|\\d{4})\\s*$").find(str(p["expiry"])) ?: return false
                val month = m.groupValues[1].toInt()
                val y = m.groupValues[2]
                val year = if (y.length == 2) 2000 + y.toInt() else y.toInt()
                if (month !in 1..12) return false
                year < today.year || (year == today.year && month < today.monthValue)
            }
            "subscription" -> p["active"] != JsonValue.Bool(false) && (date(str(p["expiration_date"]))?.isBefore(today) ?: false)
            "license", "purchase", "warranty" -> date(str(p["expiration_date"]))?.isBefore(today) ?: false
            "api_key" -> date(str(p["expires"]))?.isBefore(today) ?: false
            else -> false
        }
    }

    // MARK: merge (§3.2, a port of Python `hygiene.merge`)

    private const val MAX_TAGS = 20
    private const val MAX_TAG_LENGTH = 40
    private const val MAX_URLS = 20
    private const val MAX_NOTES = 20_000
    private val LOGIN_KINDS = setOf("web", "desktop")
    private val MATCH_MODES = setOf("exact_origin", "host", "base_domain", "starts_with")

    /** Python truthiness of a JSON value (absent, null, false, 0, "", [] and {} are false). */
    internal fun truthy(v: JsonValue?): Boolean = when (v) {
        null, JsonValue.Null -> false
        is JsonValue.Bool -> v.v
        is JsonValue.Int -> v.v != 0L
        is JsonValue.Float -> v.v != 0.0
        is JsonValue.Str -> v.v.isNotEmpty()
        is JsonValue.Arr -> v.items.isNotEmpty()
        is JsonValue.Obj -> v.fields.isNotEmpty()
    }

    /** Python `str(value)` of a JSON value (a tag that is not text is read as Python reads it). */
    private fun pyStr(v: JsonValue): String = when (v) {
        is JsonValue.Str -> v.v
        JsonValue.Null -> "None"
        is JsonValue.Bool -> if (v.v) "True" else "False"
        is JsonValue.Int -> v.v.toString()
        is JsonValue.Float -> v.v.toString()
        is JsonValue.Arr -> v.items.joinToString(", ", "[", "]") { pyRepr(it) }
        is JsonValue.Obj -> v.fields.entries.joinToString(", ", "{", "}") { "'" + it.key + "': " + pyRepr(it.value) }
    }

    private fun pyRepr(v: JsonValue): String = if (v is JsonValue.Str) "'" + v.v + "'" else pyStr(v)

    /** Python `keeper.get("tags") or []`, iterated: a list's values, a text's characters, an object's keys. */
    private fun tagValues(v: JsonValue?): List<String> = when {
        !truthy(v) -> emptyList()
        v is JsonValue.Arr -> v.items.map(::pyStr)
        v is JsonValue.Str -> v.v.codePoints().toArray().map { String(Character.toChars(it)) }
        v is JsonValue.Obj -> v.fields.keys.toList()
        else -> emptyList()
    }

    /**
     * Keeper's tags then the other's, through the tag normaliser (Python `item_schema.normalize_tags`): an empty tag, one
     * over 40 characters or one with a NUL refuses, as more than 20 does (`too_many_tags`); blank ones are dropped and
     * the rest deduplicated by casefold, the first spelling kept.
     */
    fun mergedTags(a: List<String>, b: List<String>): List<String> {
        val seen = HashSet<String>()
        val out = ArrayList<String>()
        for (t in a + b) {
            if (t.isEmpty() || t.codePointCount(0, t.length) > MAX_TAG_LENGTH || t.contains('\u0000')) throw MergeException("too_many_tags")
            val s = PyStrip.strip(t)
            if (s.isEmpty()) continue
            if (seen.add(Casefold.fold(s))) out.add(s)
        }
        if (out.size > MAX_TAGS) throw MergeException("too_many_tags")
        return out
    }

    /** Python `_union`: [a]'s values then [b]'s (a value that is not a list counts as none), deduplicated, at most [cap]. */
    private fun union(a: JsonValue?, b: JsonValue?, cap: Int): JsonValue {
        val out = ArrayList<JsonValue>()
        val seen = HashSet<String>()
        for (v in (a as? JsonValue.Arr)?.items.orEmpty() + (b as? JsonValue.Arr)?.items.orEmpty()) {
            if (seen.add(String(ItemHistory.canon(v), Charsets.UTF_8))) out.add(v)
        }
        if (out.size > cap) throw MergeException("too_many_values")
        return JsonValue.Arr(out)
    }

    /**
     * A login's URL rows as `(url, match)` (Python `origin.entry_urls`): `scope.urls` (an unknown or missing `match`
     * reads `exact_origin`), or its origin as one `exact_origin` row when it has none.
     */
    private fun urlRows(record: Rec): List<Pair<String, String>> {
        val scope = (record["scope"] as? JsonValue.Obj)?.fields ?: return emptyList()
        val rows = (scope["urls"] as? JsonValue.Arr)?.items.orEmpty().mapNotNull { v ->
            val o = (v as? JsonValue.Obj)?.fields ?: return@mapNotNull null
            val url = (o["url"] as? JsonValue.Str)?.v ?: return@mapNotNull null
            val mode = (o["match"] as? JsonValue.Str)?.v?.takeIf { it in MATCH_MODES } ?: "exact_origin"
            url to mode
        }
        if (rows.isNotEmpty()) return rows
        val origin = (scope["origin"] as? JsonValue.Str)?.v?.takeIf { it.isNotEmpty() } ?: return emptyList()
        return listOf(origin to "exact_origin")
    }

    /**
     * Web keeper (§3.2, revised 2026-11-15): the keeper's rows then the other's (a web or a desktop login), deduplicated
     * by `(url, match)`, cap 20 (`too_many_values`). Null when that equals the keeper's rows, so its scope stays as it was.
     */
    private fun webUrls(keeper: Rec, other: Rec): JsonValue? {
        val mine = urlRows(keeper)
        val out = LinkedHashSet(mine)
        out.addAll(urlRows(other))
        if (out.size > MAX_URLS) throw MergeException("too_many_values")
        if (out.toList() == mine) return null
        return JsonValue.Arr(out.map { (u, m) -> JsonValue.Obj(linkedMapOf("url" to JsonValue.Str(u), "match" to JsonValue.Str(m))) })
    }

    /**
     * Python `vault.push_password_history`: [previous] goes in front of the history's object rows (kept as they are),
     * rows whose integer `changed_at` is older than 365 days are dropped (a row without one is kept), at most 5.
     */
    private fun pushHistory(history: JsonValue?, previous: String, now: Long): JsonValue {
        val first: JsonValue = JsonValue.Obj(linkedMapOf("password" to JsonValue.Str(previous), "changed_at" to JsonValue.Int(now)))
        val rows = listOf(first) + (history as? JsonValue.Arr)?.items.orEmpty().filterIsInstance<JsonValue.Obj>()
        val cutoff = now - PasswordHistory.KEEP_SECONDS
        val kept = rows.filter { row ->
            when (val at = (row as JsonValue.Obj).fields["changed_at"]) {
                is JsonValue.Int -> at.v >= cutoff
                is JsonValue.Bool -> (if (at.v) 1L else 0L) >= cutoff // a Python bool is an int
                else -> true
            }
        }
        return JsonValue.Arr(kept.take(PasswordHistory.WRITE_LIMIT))
    }

    private fun notes(keeper: JsonValue?, other: JsonValue?): String {
        val mine = str(keeper)
        val theirs = str(other)
        val n = if (theirs.isEmpty() || theirs == mine) mine else if (mine.isEmpty()) theirs else mine + "\n\n" + theirs
        if (n.codePointCount(0, n.length) > MAX_NOTES) throw MergeException("notes_too_long")
        return n
    }

    /**
     * The merged record (§3.2, Python `hygiene.merge`): [keeper] with the other's tags, notes, codes, fields, addresses
     * and stricter rules folded in. Logins merge across kinds (a website login with a desktop login; only a web keeper
     * gains the other's addresses); typed items merge only with the same kind, and only tags, notes and collection ids.
     * Access rules and the policy are never loosened. Refused with `not_mergeable`, `too_many_tags`, `too_many_values`
     * or `notes_too_long`.
     */
    fun merge(keeper: Rec, other: Rec, now: Long): Rec {
        val login = kind(keeper) in LOGIN_KINDS
        if (login != (kind(other) in LOGIN_KINDS) || (!login && kind(keeper) != kind(other))) throw MergeException("not_mergeable")
        val r = LinkedHashMap(keeper)
        if ("tags" in keeper || "tags" in other) {
            r["tags"] = JsonValue.Arr(mergedTags(tagValues(keeper["tags"]), tagValues(other["tags"])).map { JsonValue.Str(it) })
        }
        if (login) {
            if ("recovery_codes" in keeper || "recovery_codes" in other) r["recovery_codes"] = union(keeper["recovery_codes"], other["recovery_codes"], 100)
            if ("custom_fields" in keeper || "custom_fields" in other) r["custom_fields"] = union(keeper["custom_fields"], other["custom_fields"], 50)
            val scope = LinkedHashMap(obj(keeper["scope"]))
            val os = obj(other["scope"])
            // The other login's addresses (its urls, or its legacy origin) are kept as rows; scope.origin stays the keeper's.
            if (kind(keeper) == "web") webUrls(keeper, other)?.let { scope["urls"] = it }
            if ("notes" in keeper || "notes" in other) r["notes"] = JsonValue.Str(notes(keeper["notes"], other["notes"]))
            val theirs = other["password"]
            if (theirs is JsonValue.Str && theirs.v.isNotEmpty() && theirs != (keeper["password"] ?: JsonValue.Str(""))) {
                r["password_history"] = pushHistory(keeper["password_history"], theirs.v, now)
            }
            if (!truthy(keeper["totp"]) && truthy(other["totp"])) r["totp"] = other.getValue("totp")
            val access = AccessRules.stricter(scope["access"], os["access"])
            if (access == null) scope.remove("access") else scope["access"] = access
            r["scope"] = JsonValue.Obj(scope)
            AccessRules.stricterPolicy(keeper["policy"], other["policy"])?.let { r["policy"] = it }
        } else {
            val p = LinkedHashMap(obj(keeper["payload"]))
            val op = obj(other["payload"])
            if ("notes" in p || "notes" in op) p["notes"] = JsonValue.Str(notes(p["notes"], op["notes"]))
            r["payload"] = JsonValue.Obj(p)
            // At most 20 collection ids, as Python `hygiene.MAX_COLLECTIONS` (more: too_many_values).
            if ("collection_ids" in keeper || "collection_ids" in other) r["collection_ids"] = union(keeper["collection_ids"], other["collection_ids"], MAX_COLLECTIONS)
        }
        if ("favorite" in keeper || "favorite" in other) {
            r["favorite"] = JsonValue.Bool(keeper["favorite"] == JsonValue.Bool(true) || other["favorite"] == JsonValue.Bool(true))
        }
        r["updated_at"] = JsonValue.Int(now)
        return r
    }
}
