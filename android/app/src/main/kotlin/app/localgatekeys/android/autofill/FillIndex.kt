package app.localgatekeys.android.autofill

import app.localgatekeys.android.access.AccessGate
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.core.sync.TravelMode
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.UrlMatcher
import app.localgatekeys.core.records.UrlRow
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.itemRecords

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
 *
 * [freeFull]: the free plan was full (no Pro, [ItemLimit.FREE_ITEMS] live items) when the index was last written, so
 * the locked credential provider offers no "Create passkey" / save entry (release check 2026-11-01). Not a secret; the
 * create sheet re-checks after the unlock either way.
 */
data class FillIndex(
    val entries: List<IndexEntry>,
    val apps: Map<String, List<String>>,
    val freeFull: Boolean = false,
    /** This vault's travel mode (contract section 2), kept here so every rebuild leaves the same items out. */
    val travel: TravelMode.Setting = TravelMode.Setting.OFF,
) {
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
                "free_full" to JsonValue.Bool(freeFull),
            ) + (if (travel == TravelMode.Setting.OFF) emptyMap() else mapOf("travel" to travel.json())),
        ),
        Dialect.UTF8,
    )

    override fun toString(): String = "FillIndex(entries=${entries.size}, apps=${apps.size}, freeFull=$freeFull)"

    companion object {
        val EMPTY = FillIndex(emptyList(), emptyMap())

        private fun text(v: JsonValue?): String = (v as? JsonValue.Str)?.v ?: ""

        /**
         * Live web logins of [s] (tombstones, other kinds and desktop logins left out); [apps] keeps pairings to live ids.
         * [isPro] is this phone's Pro state for [freeFull]; null (an index built only for matching, never written): false.
         */
        fun build(
            s: StoreSnapshot,
            apps: Map<String, List<String>> = emptyMap(),
            isPro: Boolean? = null,
            travel: TravelMode.Setting = TravelMode.Setting.OFF,
            today: String = AccessGate.today(),
        ): FillIndex {
            // Hidden by travel mode, or never autofilled by its access rules (policy.fill, scope.access): left out, so
            // the locked service never offers them. Pairings to them are kept for when they come back.
            val hidden = TravelMode.hiddenIds(s, travel)
            val pairable = HashSet<String>()
            val entries = ArrayList<IndexEntry>()
            for ((id, wrapper) in s.itemRecords.entries.sortedWith { a, b -> Scalars.compare(a.key, b.key) }) {
                if (s.meta[id]?.deleted == true) continue
                val w = (wrapper as? JsonValue.Obj)?.fields ?: continue
                if (w["ns"] != JsonValue.Str(Namespace.ENTRY.wire)) continue
                val r = (w["record"] as? JsonValue.Obj)?.fields ?: continue
                if (r["kind"] != JsonValue.Str("web")) continue
                val rows = UrlMatcher.entryUrls(r)
                if (rows.isEmpty()) continue
                pairable.add(id)
                if (id in hidden || !AccessGate.mayFill(r, today)) continue
                entries.add(IndexEntry(id, text(r["label"]), text(r["username"]), rows, (r["updated_at"] as? JsonValue.Int)?.v ?: 0L))
            }
            val kept = apps.mapValues { (_, ids) -> ids.filter { it in pairable } }.filterValues { it.isNotEmpty() }
            val full = isPro == false && !ItemLimit.allows(ItemLimit.Action.CREATE, s, false)
            return FillIndex(entries, kept, full, travel)
        }

        /**
         * Whether the locked provider leaves out its create entry: the last written [index] says the free plan was full
         * and Pro is not known in this process ([isProNow], a purchase made since). No index: the entry is offered.
         */
        fun lockedFreePlanFull(index: FillIndex?, isProNow: Boolean): Boolean = index?.freeFull == true && !isProNow

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
                FillIndex(entries, apps, root["free_full"] == JsonValue.Bool(true), TravelMode.Setting.of(root["travel"]))
            }
        } catch (e: Exception) {
            null
        }
    }
}

/** Which logins a target offers, best first. */
class FillMatcher(private val matcher: UrlMatcher) {
    fun match(index: FillIndex, target: FillTarget): List<IndexEntry> = when (target) {
        // A page whose scheme the browser did not name is offered nothing by itself (only the search list).
        is FillTarget.Web -> if (!target.schemeKnown) emptyList()
        else matcher.candidates(index.entries.map { it.matchRecord() }, listOf(target.origin)).map { index.entries[it] }
        is FillTarget.App -> (index.apps[target.pairKey] ?: emptyList()).mapNotNull { index.entry(it) }
    }

    /** The re-check after unlock against the stored record itself (web) or the pairings (app). */
    fun recordMatches(record: Map<String, JsonValue>, id: String, target: FillTarget, index: FillIndex): Boolean = when (target) {
        is FillTarget.Web -> record["kind"] == JsonValue.Str("web") && matcher.matchRank(UrlMatcher.entryUrls(record), target.origin) != null
        is FillTarget.App -> record["kind"] == JsonValue.Str("web") && id in (index.apps[target.pairKey] ?: emptyList())
    }
}
