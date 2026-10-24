package app.localgatekeys.core.records

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Scalars

/**
 * Multi-URL credential matching: a port of the desktop's `localvault.origin` (`match_rank`, `entry_urls`,
 * `candidates_for`, `base_domain`, `public_suffix`, `parse_suffix_rules`). Port of Swift `Records/URLMatch.swift`.
 *
 * Kotlin `String ==` compares UTF-16 units, which is a code point comparison as in Python (no canonical
 * equivalence, unlike Swift `String`); `Scalars.hasPrefix` guards the split-surrogate case.
 *
 * Hosts are ASCII on the phone (`Origin.asciiHost` throws `NEEDS_PUNYCODE` for a non-ASCII host), so a candidate
 * or stored URL with a non-ASCII host fails closed: it matches nothing.
 */
enum class UrlMatchMode(val stored: String) {
    EXACT_ORIGIN("exact_origin"),
    HOST("host"),
    BASE_DOMAIN("base_domain"),
    STARTS_WITH("starts_with"),
    ;

    /** Rank in `MATCH_MODES` order; lower matches more strictly. */
    val rank: Int get() = ordinal

    companion object {
        /** Exact code-point lookup of a stored mode string. */
        fun fromStored(s: String): UrlMatchMode? = entries.firstOrNull { it.stored == s }
    }
}

/** One `{"url", "match"}` row. */
data class UrlRow(val url: String, val mode: UrlMatchMode)

/** The desktop's URL matcher. [rules] null = no usable suffix list (`base_domain` matches the exact host). */
class UrlMatcher(val rules: PublicSuffixRules?) {
    companion object {
        /** `host_of`. */
        fun hostOf(url: String): String = Origin.splitURL(url).host

        /**
         * `entry_urls`: the URL rows of a web login, migrating the legacy single origin. Bare-string rows are skipped
         * here exactly as the desktop's `entry_urls` skips them (normalisation turns them into `{"url", "match"}`
         * rows before they are stored).
         */
        fun entryUrls(record: Map<String, JsonValue>): List<UrlRow> {
            val scope = (record["scope"] as? JsonValue.Obj)?.fields ?: return emptyList()
            val rows = ArrayList<UrlRow>()
            val list = scope["urls"]
            if (list is JsonValue.Arr) {
                for (item in list.items) {
                    val row = (item as? JsonValue.Obj)?.fields ?: continue
                    val url = (row["url"] as? JsonValue.Str)?.v ?: continue
                    var mode = UrlMatchMode.EXACT_ORIGIN
                    val m = row["match"]
                    if (m is JsonValue.Str) UrlMatchMode.fromStored(m.v)?.let { mode = it }
                    rows.add(UrlRow(url, mode))
                }
            }
            val origin = (scope["origin"] as? JsonValue.Str)?.v
            if (rows.isEmpty() && origin != null && origin.isNotEmpty()) rows.add(UrlRow(origin, UrlMatchMode.EXACT_ORIGIN))
            return rows
        }

        /** `_starts_with` on normalised URLs, at a path boundary. */
        internal fun startsWith(stored: String, candidate: String): Boolean {
            if (stored == candidate) return true
            if (!Scalars.hasPrefix(candidate, stored)) return false
            if (stored.endsWith("/")) return true
            val next = candidate[stored.length]
            return next == '/' || next == '?'
        }
    }

    /** `base_domain` for an A-label host. */
    fun baseDomain(rawHost: String): String {
        if (rawHost.contains(':')) { // an IPv6 literal (`hostOf` gives it without brackets)
            if (rawHost.contains('%')) throw OriginException.invalid("IPv6 zone identifiers are not supported")
            Origin.ipv6(rawHost) ?: throw OriginException.invalid("Invalid IPv6 URL")
            return rawHost.lowercase()
        }
        val host = Origin.asciiHost(rawHost)
        if (Origin.ipv4(host) != null || Origin.ipv6(host) != null) return host
        val rules = rules
        if (rules == null || !host.contains('.')) return host
        val suffix = rules.publicSuffix(host)
        if (suffix == host) return host
        val head = host.substring(0, host.length - suffix.length - 1)
        val registrable = head.split(".").last()
        return "$registrable.$suffix"
    }

    fun baseDomainOf(url: String): String = baseDomain(hostOf(url))

    /** `_row_matches`. */
    internal fun rowMatches(row: UrlRow, candidate: String): Boolean = when (row.mode) {
        UrlMatchMode.EXACT_ORIGIN -> Origin.originOf(row.url) == Origin.originOf(candidate)
        UrlMatchMode.HOST -> Origin.splitURL(row.url).let { r ->
            Origin.splitURL(candidate).let { c -> r.host == c.host && r.port == c.port }
        }
        UrlMatchMode.BASE_DOMAIN -> baseDomainOf(row.url) == baseDomainOf(candidate)
        UrlMatchMode.STARTS_WITH -> startsWith(Origin.normalizeUrl(row.url), Origin.normalizeUrl(candidate))
    }

    /**
     * `match_rank`: the best (lowest) mode rank, null for no match or a malformed candidate. A plain-HTTP candidate on
     * a non-loopback host (one `Origin.canonicalize` refuses) never matches, so `host` / `base_domain` rows, which
     * ignore the scheme, cannot offer an HTTPS login to an `http://` page (audit M-4).
     */
    fun matchRank(rows: List<UrlRow>, candidate: String): Int? {
        val parts = try {
            Origin.splitURL(candidate)
        } catch (_: Exception) {
            return null
        }
        if (parts.scheme == "http" && !Origin.isLoopback(parts.host)) return null
        var best: Int? = null
        for (row in rows) {
            val matched = try {
                rowMatches(row, candidate)
            } catch (_: Exception) {
                false
            }
            if (matched) best = minOf(best ?: row.mode.rank, row.mode.rank)
        }
        return best
    }

    /**
     * `candidates_for` over several candidate URLs (one AutoFill request may name several service identifiers): web
     * records that match any of them, ranked by best mode, then most recently updated, then id. Returns the indices
     * into [records].
     */
    fun candidates(records: List<Map<String, JsonValue>>, urls: List<String>): List<Int> {
        class Ranked(val rank: Int, val updated: Long, val id: String, val index: Int)

        val ranked = ArrayList<Ranked>()
        for ((i, r) in records.withIndex()) {
            val kind = (r["kind"] as? JsonValue.Str)?.v ?: continue
            if (kind != "web") continue
            val rows = entryUrls(r)
            val rank = urls.mapNotNull { matchRank(rows, it) }.minOrNull() ?: continue
            val updated = when (val u = r["updated_at"]) {
                is JsonValue.Int -> u.v
                is JsonValue.Bool -> if (u.v) 1L else 0L // Python: bool is an int
                else -> 0L
            }
            val id = (r["id"] as? JsonValue.Str)?.v ?: ""
            ranked.add(Ranked(rank, updated, id, i))
        }
        ranked.sortWith { a, b ->
            if (a.rank != b.rank) {
                a.rank.compareTo(b.rank)
            } else if (a.updated != b.updated) {
                b.updated.compareTo(a.updated)
            } else {
                Scalars.compare(a.id, b.id)
            }
        }
        return ranked.map { it.index }
    }
}
