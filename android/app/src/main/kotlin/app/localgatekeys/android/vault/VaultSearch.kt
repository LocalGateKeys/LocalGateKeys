package app.localgatekeys.android.vault

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.core.primitives.Casefold
import app.localgatekeys.core.primitives.Scalars

/** A type filter (desktop `FilterOption` without collections and smart views). */
sealed interface VaultFilter {
    fun label(t: Txt): String

    fun matches(item: VaultItem): Boolean

    data object All : VaultFilter {
        override fun label(t: Txt): String = t.s(R.string.home_title_all_types)
        override fun matches(item: VaultItem) = true
    }

    data object Favorites : VaultFilter {
        override fun label(t: Txt): String = t.s(R.string.nav_vault_favorites)
        override fun matches(item: VaultItem) = item.favorite
    }

    data class Kind(val kind: String) : VaultFilter {
        override fun label(t: Txt): String = when (kind) {
            "web" -> t.s(R.string.filter_web)
            "desktop" -> t.s(R.string.filter_desktop)
            else -> VaultItem.kindLabel(kind, t)
        }

        override fun matches(item: VaultItem) = item.kind == kind
    }
}

/**
 * Port of the desktop list search (`agent.py` `parse_search_query` / `search_fields` / `search_rank` /
 * `rank_search_results`): casefolded, every token must match; `tag:`, `url:`, `type:`, `user:` restrict
 * one field; rank exact title > title prefix > contains > fuzzy (difflib, cutoff 0.72, tokens of 3+).
 * Only list metadata is searched, never passwords, notes or payloads.
 */
object VaultSearch {
    private val prefixes = mapOf("tag" to "tags", "url" to "url", "type" to "kind", "user" to "username")
    const val RANK_EXACT = 0
    const val RANK_PREFIX = 1
    const val RANK_CONTAINS = 2
    const val RANK_FUZZY = 3
    const val FUZZY_CUTOFF = 0.72
    const val FUZZY_MIN_LENGTH = 3

    /** Python `str.casefold()` (core `Casefold`), per code point, no normalisation. */
    fun casefold(s: String): String = Casefold.fold(s)

    /** The tokens of a query: a field name for a `prefix:value` token, else null. */
    fun parse(query: String): List<Pair<String?, String>> {
        val out = ArrayList<Pair<String?, String>>()
        for (raw in query.split(Regex("[\\s\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000]+"))) {
            if (raw.isEmpty()) continue
            val token = casefold(raw)
            val colon = token.indexOf(':')
            val field = if (colon >= 0) prefixes[token.substring(0, colon)] else null
            if (field != null) {
                val value = token.substring(colon + 1)
                if (value.isNotEmpty()) out.add(field to value)
                continue
            }
            out.add(null to token)
        }
        return out
    }

    fun fields(item: VaultItem, t: Txt): Map<String, String> = mapOf(
        "title" to casefold(item.title),
        "username" to casefold(item.username),
        "url" to casefold(item.target),
        "kind" to casefold("${item.kind} ${item.kindLabel(t)}"),
        "tags" to casefold(item.tags.joinToString(" ")),
    )

    /** `re.split(r"[^0-9a-z]+", value)` over code points (empty pieces dropped). */
    fun words(s: String): List<String> {
        val out = ArrayList<String>()
        val cur = StringBuilder()
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            i += Character.charCount(cp)
            if (cp in 0x30..0x39 || cp in 0x61..0x7A) cur.appendCodePoint(cp) else if (cur.isNotEmpty()) { out.add(cur.toString()); cur.setLength(0) }
        }
        if (cur.isNotEmpty()) out.add(cur.toString())
        return out
    }

    /** Substring test by code points, so half of a surrogate pair never matches. */
    fun containsScalars(haystack: String, needle: String): Boolean {
        val h = haystack.codePoints().toArray()
        val n = needle.codePoints().toArray()
        if (n.isEmpty()) return true
        if (n.size > h.size) return false
        outer@ for (start in 0..h.size - n.size) {
            for (k in n.indices) if (h[start + k] != n[k]) continue@outer
            return true
        }
        return false
    }

    fun hasPrefixScalars(s: String, prefix: String): Boolean = Scalars.hasPrefix(s, prefix)

    private fun fuzzyHit(token: String, f: Map<String, String>): Boolean {
        if (Scalars.count(token) < FUZZY_MIN_LENGTH) return false
        for (name in listOf("title", "username", "url", "tags")) {
            val v = f[name] ?: continue
            if (v.isEmpty()) continue
            for (c in listOf(v) + words(v)) if (SequenceRatio.ratio(c, token) >= FUZZY_CUTOFF) return true
        }
        return false
    }

    fun tokenRank(f: Map<String, String>, field: String?, token: String): Int? {
        if (field != null) return if (containsScalars(f[field] ?: "", token)) RANK_CONTAINS else null
        val title = f["title"] ?: ""
        if (title == token) return RANK_EXACT
        if (hasPrefixScalars(title, token)) return RANK_PREFIX
        if (f.values.any { containsScalars(it, token) }) return RANK_CONTAINS
        return if (fuzzyHit(token, f)) RANK_FUZZY else null
    }

    /** Matching items, best rank first, then most recently updated, then by id. An empty query keeps everything. */
    fun rank(items: List<VaultItem>, query: String, t: Txt): List<VaultItem> {
        val tokens = parse(query)
        val ordered = items.sortedWith { a, b -> Scalars.compare(a.id, b.id) } // stable input order
        class Hit(val rank: Int, val negTime: Long, val index: Int, val item: VaultItem)
        val ranked = ArrayList<Hit>()
        for ((index, item) in ordered.withIndex()) {
            val f = fields(item, t)
            var r = RANK_EXACT
            var hit = true
            for ((field, token) in tokens) {
                val tr = tokenRank(f, field, token)
                if (tr == null) { hit = false; break }
                r = maxOf(r, tr)
            }
            if (hit) ranked.add(Hit(r, -item.updatedAt, index, item))
        }
        ranked.sortWith(compareBy<Hit>({ it.rank }, { it.negTime }, { it.index }))
        return ranked.map { it.item }
    }

    fun apply(items: List<VaultItem>, query: String, filter: VaultFilter, t: Txt): List<VaultItem> =
        rank(items.filter { filter.matches(it) }, query, t)

    /** Desktop `KIND_ORDER`: web, desktop, then the other kinds by label. */
    fun filterOptions(items: List<VaultItem>, t: Txt): List<VaultFilter> {
        val present = items.map { it.kind }.toSet()
        val rest = (present - setOf("web", "desktop")).sortedWith { a, b ->
            val c = Scalars.compare(casefold(VaultItem.kindLabel(a, t)), casefold(VaultItem.kindLabel(b, t)))
            if (c != 0) c else Scalars.compare(a, b)
        }
        return listOf<VaultFilter>(VaultFilter.All, VaultFilter.Favorites) +
            listOf("web", "desktop").filter { it in present }.map { VaultFilter.Kind(it) } +
            rest.map { VaultFilter.Kind(it) }
    }
}

/** `difflib.SequenceMatcher(None, a, b).ratio()` over code points, including autojunk on `b`. */
object SequenceRatio {
    fun ratio(a: String, b: String): Double {
        val x = a.codePoints().toArray()
        val y = b.codePoints().toArray()
        val total = x.size + y.size
        if (total == 0) return 1.0
        var b2j = HashMap<Int, MutableList<Int>>()
        for ((j, c) in y.withIndex()) b2j.getOrPut(c) { ArrayList() }.add(j)
        if (y.size >= 200) {
            val ntest = y.size / 100 + 1
            b2j = HashMap(b2j.filterValues { it.size <= ntest })
        }

        fun longest(alo: Int, ahi: Int, blo: Int, bhi: Int): IntArray {
            var bi = alo
            var bj = blo
            var size = 0
            var j2len = HashMap<Int, Int>()
            for (i in alo until ahi) {
                val next = HashMap<Int, Int>()
                for (j in b2j[x[i]] ?: emptyList()) {
                    if (j < blo) continue
                    if (j >= bhi) break
                    val k = (j2len[j - 1] ?: 0) + 1
                    next[j] = k
                    if (k > size) { bi = i - k + 1; bj = j - k + 1; size = k }
                }
                j2len = next
            }
            // No junk elements, but popular ones were dropped from b2j: extend the block over equal elements.
            while (bi > alo && bj > blo && x[bi - 1] == y[bj - 1]) { bi--; bj--; size++ }
            while (bi + size < ahi && bj + size < bhi && x[bi + size] == y[bj + size]) size++
            return intArrayOf(bi, bj, size)
        }

        var matches = 0
        val queue = ArrayDeque<IntArray>()
        queue.addLast(intArrayOf(0, x.size, 0, y.size))
        while (queue.isNotEmpty()) {
            val (alo, ahi, blo, bhi) = queue.removeLast()
            if (alo >= ahi || blo >= bhi) continue
            val (i, j, k) = longest(alo, ahi, blo, bhi)
            if (k == 0) continue
            matches += k
            queue.addLast(intArrayOf(alo, i, blo, j))
            queue.addLast(intArrayOf(i + k, ahi, j + k, bhi))
        }
        return 2.0 * matches / total
    }
}
