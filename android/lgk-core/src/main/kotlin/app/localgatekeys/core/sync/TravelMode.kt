package app.localgatekeys.core.sync

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.primitives.Casefold
import app.localgatekeys.core.records.PyStrip

/**
 * Travel mode (feature pack contract 2026-11-15 §2): per device, never synced. Hidden items are hidden, not removed:
 * they stay in the vault, keep syncing both ways and are in encrypted backups. Logins never belong to collections, so
 * they are hidden by tag only.
 */
object TravelMode {
    const val MAX_COLLECTIONS = 20
    const val MAX_TAGS = 20

    /** The setting as stored (`travel_mode`). [since] is when it was turned on (Unix seconds). */
    data class Setting(val on: Boolean = false, val collections: List<String> = emptyList(), val tags: List<String> = emptyList(), val since: Long = 0) {
        fun json(): JsonValue = JsonValue.Obj(
            mapOf(
                "on" to JsonValue.Bool(on),
                "collections" to JsonValue.Arr(collections.map { JsonValue.Str(it) }),
                "tags" to JsonValue.Arr(tags.map { JsonValue.Str(it) }),
                "since" to JsonValue.Int(since),
            ),
        )

        /** Hides nothing. */
        val isEmpty: Boolean get() = !on || (collections.isEmpty() && tags.isEmpty())

        override fun toString(): String = "TravelMode.Setting(on=$on, collections=${collections.size}, tags=${tags.size})"

        companion object {
            val OFF = Setting()

            /** Lenient read: a damaged value is off (hiding is a convenience, never a protection). */
            fun of(v: JsonValue?): Setting {
                val f = (v as? JsonValue.Obj)?.fields ?: return OFF
                fun strings(k: String) = (f[k] as? JsonValue.Arr)?.items?.mapNotNull { (it as? JsonValue.Str)?.v } ?: emptyList()
                return Setting(
                    on = f["on"] == JsonValue.Bool(true),
                    collections = cleanCollections(strings("collections")),
                    tags = cleanTags(strings("tags")),
                    since = (f["since"] as? JsonValue.Int)?.v ?: 0L,
                )
            }
        }
    }

    /** Canonical lower-case UUIDs, no duplicates, at most [MAX_COLLECTIONS]. */
    fun cleanCollections(ids: List<String>): List<String> =
        ids.map { it.lowercase() }.filter { ShareKeyring.isCanonicalUuid(it) }.distinct().take(MAX_COLLECTIONS)

    /** The tag rules (strip, drop empty, first spelling of each casefold wins), at most [MAX_TAGS]. */
    fun cleanTags(tags: List<String>): List<String> {
        val seen = HashSet<String>()
        val out = ArrayList<String>()
        for (t in tags) {
            val s = PyStrip.strip(t)
            if (s.isEmpty() || s.codePointCount(0, s.length) > 40) continue
            if (seen.add(Casefold.fold(s))) out.add(s)
        }
        return out.take(MAX_TAGS)
    }

    fun fold(s: String): String = Casefold.fold(PyStrip.strip(s))

    /** One item as the rule reads it. [collections] are ignored for logins (`web`, `desktop`). */
    data class Item(val id: String, val kind: String, val tags: List<String>, val collections: List<String>)

    fun isLogin(kind: String): Boolean = kind == "web" || kind == "desktop"

    /** `hidden(record)` for each item: the ids hidden by [setting]. */
    fun hiddenIds(items: List<Item>, setting: Setting): Set<String> {
        if (!setting.on) return emptySet()
        val cols = setting.collections.map { it.lowercase() }.toSet()
        val tags = setting.tags.map(::fold).toSet()
        val out = LinkedHashSet<String>()
        for (it in items) {
            val byCollection = !isLogin(it.kind) && it.collections.any { c -> c.lowercase() in cols }
            val byTag = it.tags.any { t -> fold(t) in tags }
            if (byCollection || byTag) out.add(it.id)
        }
        return out
    }

    /** The live entries and items of [snapshot] as [Item]s (memberships from the collection states). */
    fun items(snapshot: StoreSnapshot): List<Item> {
        val out = ArrayList<Item>()
        for ((id, wrapper) in snapshot.itemRecords) {
            if (snapshot.meta[id]?.deleted == true) continue
            val r = ((wrapper as? JsonValue.Obj)?.fields?.get("record") as? JsonValue.Obj)?.fields ?: continue
            val kind = (r["kind"] as? JsonValue.Str)?.v ?: continue
            val tags = (r["tags"] as? JsonValue.Arr)?.items?.mapNotNull { (it as? JsonValue.Str)?.v } ?: emptyList()
            out.add(Item(id, kind, tags, if (isLogin(kind)) emptyList() else CollectionCatalog.memberships(id, snapshot)))
        }
        return out
    }

    /** [collections] without the ones travel mode hides (section 2.3: hidden collections are absent). */
    fun <T> visibleCollections(collections: List<T>, setting: Setting, id: (T) -> String): List<T> {
        if (!setting.on || setting.collections.isEmpty()) return collections
        val hidden = setting.collections.map { it.lowercase() }.toSet()
        return collections.filter { id(it).lowercase() !in hidden }
    }

    fun hiddenIds(snapshot: StoreSnapshot, setting: Setting): Set<String> =
        if (setting.isEmpty) emptySet() else hiddenIds(items(snapshot), setting)
}
