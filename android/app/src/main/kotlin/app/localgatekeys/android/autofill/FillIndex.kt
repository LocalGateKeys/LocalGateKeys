package app.localgatekeys.android.autofill

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.UrlMatcher
import app.localgatekeys.core.records.UrlRow
import app.localgatekeys.core.sync.StoreSnapshot

/** One web login as the locked service may see it: no password, 2FA secret or notes. */
data class IndexEntry(val id: String, val title: String, val username: String, val urls: List<UrlRow>, val updatedAt: Long) {
    /** The minimal record [UrlMatcher.candidates] reads. */
    fun matchRecord(): Map<String, JsonValue> = mapOf(
        "id" to JsonValue.Str(id),
        "kind" to JsonValue.Str("web"),
        "updated_at" to JsonValue.Int(updatedAt),
        "scope" to JsonValue.Obj(
            mapOf("urls" to JsonValue.Arr(urls.map { JsonValue.Obj(mapOf("url" to JsonValue.Str(it.url), "match" to JsonValue.Str(it.mode.stored))) })),
        ),
    )

    override fun toString(): String = "IndexEntry(id=$id, urls=${urls.size})"
}

/**
 * The fill index (spec section 5): username + site per login, so the service can list matches while the vault is
 * locked, plus the phone-local "app package -> item ids" pairings. Sealed at rest by `FillIndexStore`.
 */
data class FillIndex(val entries: List<IndexEntry>, val apps: Map<String, List<String>>) {
    fun entry(id: String): IndexEntry? = entries.firstOrNull { it.id == id }

    /** A copy with [itemId] paired to [packageName] (most recent first, no duplicates). */
    fun paired(packageName: String, itemId: String): FillIndex {
        val ids = listOf(itemId) + (apps[packageName] ?: emptyList()).filter { it != itemId }
        return copy(apps = apps + (packageName to ids))
    }

    fun encode(): ByteArray = CanonicalJson.encode(
        JsonValue.Obj(
            mapOf(
                "v" to JsonValue.Int(1),
                "entries" to JsonValue.Arr(
                    entries.map { e ->
                        val m = e.matchRecord().toMutableMap()
                        m.remove("kind")
                        m["title"] = JsonValue.Str(e.title)
                        m["username"] = JsonValue.Str(e.username)
                        JsonValue.Obj(m)
                    },
                ),
                "apps" to JsonValue.Obj(apps.mapValues { (_, ids) -> JsonValue.Arr(ids.map { JsonValue.Str(it) }) }),
            ),
        ),
        Dialect.UTF8,
    )

    override fun toString(): String = "FillIndex(entries=${entries.size}, apps=${apps.size})"

    companion object {
        val EMPTY = FillIndex(emptyList(), emptyMap())

        private fun text(v: JsonValue?): String = (v as? JsonValue.Str)?.v ?: ""

        /** Live web logins of [s] (tombstones, other kinds and desktop logins left out); [apps] keeps pairings to live ids. */
        fun build(s: StoreSnapshot, apps: Map<String, List<String>> = emptyMap()): FillIndex {
            val entries = ArrayList<IndexEntry>()
            for ((id, wrapper) in s.records.entries.sortedWith { a, b -> Scalars.compare(a.key, b.key) }) {
                if (s.meta[id]?.deleted == true) continue
                val w = (wrapper as? JsonValue.Obj)?.fields ?: continue
                if (w["ns"] != JsonValue.Str(Namespace.ENTRY.wire)) continue
                val r = (w["record"] as? JsonValue.Obj)?.fields ?: continue
                if (r["kind"] != JsonValue.Str("web")) continue
                val rows = UrlMatcher.entryUrls(r)
                if (rows.isEmpty()) continue
                entries.add(IndexEntry(id, text(r["label"]), text(r["username"]), rows, (r["updated_at"] as? JsonValue.Int)?.v ?: 0L))
            }
            val live = entries.map { it.id }.toSet()
            val kept = apps.mapValues { (_, ids) -> ids.filter { it in live } }.filterValues { it.isNotEmpty() }
            return FillIndex(entries, kept)
        }

        /** Null for anything that is not an index this version wrote. */
        fun decode(bytes: ByteArray): FillIndex? = try {
            val root = (CanonicalJson.parse(bytes) as JsonValue.Obj).fields
            if (root["v"] != JsonValue.Int(1)) {
                null
            } else {
                val entries = (root["entries"] as JsonValue.Arr).items.map { e ->
                    val f = (e as JsonValue.Obj).fields
                    IndexEntry(
                        id = (f["id"] as JsonValue.Str).v,
                        title = text(f["title"]),
                        username = text(f["username"]),
                        urls = UrlMatcher.entryUrls(f),
                        updatedAt = (f["updated_at"] as? JsonValue.Int)?.v ?: 0L,
                    )
                }
                val apps = (root["apps"] as JsonValue.Obj).fields.mapValues { (_, v) -> (v as JsonValue.Arr).items.map { (it as JsonValue.Str).v } }
                FillIndex(entries, apps)
            }
        } catch (e: Exception) {
            null
        }
    }
}

/** Which logins a target offers, best first. */
class FillMatcher(private val matcher: UrlMatcher) {
    fun match(index: FillIndex, target: FillTarget): List<IndexEntry> = when (target) {
        is FillTarget.Web -> matcher.candidates(index.entries.map { it.matchRecord() }, listOf(target.origin)).map { index.entries[it] }
        is FillTarget.App -> (index.apps[target.pairKey] ?: emptyList()).mapNotNull { index.entry(it) }
    }

    /** The re-check after unlock against the stored record itself (web) or the pairings (app). */
    fun recordMatches(record: Map<String, JsonValue>, id: String, target: FillTarget, index: FillIndex): Boolean = when (target) {
        is FillTarget.Web -> record["kind"] == JsonValue.Str("web") && matcher.matchRank(UrlMatcher.entryUrls(record), target.origin) != null
        is FillTarget.App -> record["kind"] == JsonValue.Str("web") && id in (index.apps[target.pairKey] ?: emptyList())
    }
}
