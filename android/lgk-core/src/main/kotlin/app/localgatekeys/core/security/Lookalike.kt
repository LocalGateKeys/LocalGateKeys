package app.localgatekeys.core.security

import app.localgatekeys.core.primitives.Casefold
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.Origin
import app.localgatekeys.core.records.OriginException
import app.localgatekeys.core.records.PublicSuffixRules
import app.localgatekeys.core.records.Punycode
import java.math.BigInteger
import java.text.Normalizer

/** [kind]: `exact`, `related`, `lookalike` or `unknown`. [matched] is the saved origin exactly as given, or null. */
data class LookalikeVerdict(val kind: String, val matched: String?, val reason: String)

/**
 * Lookalike-domain classifier for the phishing shield: a port of desktop `lookalike.py` / extension `lookalike.js`
 * (read the Python module doc for the verdicts and their order). Shared vectors: `tests/vectors/lookalike/cases.json`.
 *
 * Verdicts, strongest first: `exact/same-origin`, `related/same-host`, `related/same-site` (same registrable domain by
 * [rules]), then `lookalike` by `homoglyph`, `other-suffix`, `embedded`, `edit-distance` (2 edits from 9 characters;
 * for a saved label of 5-8 characters 1 edit, where a substitution must swap look-alike characters); ties go to the
 * smallest distance, then the earliest saved origin. With no match, a host label that mixes scripts beyond UTS #39
 * "highly restrictive" is `lookalike/mixed-script`; otherwise `unknown/no-match`. An unreadable origin is
 * `unknown/invalid-origin`.
 *
 * Everything runs on the phone. The phone carries no UTS-46 library, so the host checks the desktop takes from the
 * `idna` package are done here with the JDK: Punycode round trip, NFC, "already in mapped form" (NFKC of the Python
 * casefold, keeping the deviation characters), no leading combining mark, CheckJoiners (tables in [IdnaTables]) and
 * the RFC 5893 Bidi rule on labels with right-to-left characters. Character properties come from the runtime's
 * Unicode version, which can be older than the desktop's for very new characters.
 *
 * Without [rules], every host is its own registrable domain and no label check runs (as on the desktop).
 */
class Lookalike(private val rules: PublicSuffixRules?) {
    private class Site(
        val scheme: String,
        val host: String,
        val port: Int?,
        val ip: Boolean,
        val registrable: String,
        val sub: String,
        val label: String,
        val labels: List<String>,
    )

    /** Classifies [origin] (the page) against the vault's [saved] origins. */
    fun classify(origin: String, saved: Iterable<String>): LookalikeVerdict {
        val site = site(origin, bareHostOk = false) ?: return LookalikeVerdict("unknown", null, "invalid-origin")
        var best: Triple<IntArray, String, String>? = null
        for ((index, raw) in saved.withIndex()) {
            val other = site(raw, bareHostOk = true) ?: continue
            val (reason, distance) = compare(site, other) ?: continue
            val key = intArrayOf(RANKS.getValue(reason), distance, index)
            val b = best
            if (b == null || less(key, b.first)) best = Triple(key, reason, raw)
        }
        best?.let { (_, reason, matched) -> return LookalikeVerdict(KIND[reason] ?: "lookalike", matched, reason) }
        if (!site.ip && site.labels.any(::mixedScript)) return LookalikeVerdict("lookalike", null, "mixed-script")
        return LookalikeVerdict("unknown", null, "no-match")
    }

    /**
     * The phishing shield's verdict (desktop `lookalike.classify`): [classify] except that "related" (the "Related
     * site" badge) is kept only for the same host, or the same host with or without a leading `www.`. Another host
     * on the same registrable domain is `unknown/same-site` naming the saved origin (no badge, no guard), since a
     * domain can host other people's pages without being on the Public Suffix List; a mixed-script host there is
     * `lookalike/mixed-script`. Vectors: `crosscheck.json` `shield_pairs` and `shield_lists`.
     */
    fun shield(origin: String, saved: Iterable<String>): LookalikeVerdict {
        val site = site(origin, bareHostOk = false) ?: return LookalikeVerdict("unknown", null, "invalid-origin")
        var best: Triple<IntArray, String, String>? = null
        for ((index, raw) in saved.withIndex()) {
            val other = site(raw, bareHostOk = true) ?: continue
            var found = compare(site, other) ?: continue
            if (found.first == "same-site" && wwwTwin(site.host, other.host)) found = "www-host" to 0
            val rank = if (found.first == "www-host") RANKS.getValue("same-host") else RANKS.getValue(found.first)
            val key = intArrayOf(rank, found.second, index)
            val b = best
            if (b == null || less(key, b.first)) best = Triple(key, found.first, raw)
        }
        val mixed = !site.ip && site.labels.any(::mixedScript)
        val b = best
        if (b != null && !(b.second == "same-site" && mixed)) {
            return LookalikeVerdict(SHIELD_KIND[b.second] ?: "lookalike", b.third, b.second)
        }
        if (mixed) return LookalikeVerdict("lookalike", null, "mixed-script")
        if (b != null) return LookalikeVerdict("unknown", b.third, "same-site")
        return LookalikeVerdict("unknown", null, "no-match")
    }

    private fun wwwTwin(first: String, second: String): Boolean = first == "www.$second" || second == "www.$first"

    private fun less(a: IntArray, b: IntArray): Boolean {
        for (i in a.indices) if (a[i] != b[i]) return a[i] < b[i]
        return false
    }

    // ---- parsing (desktop `_split_url` / `_url_host` / `_ascii_host`, then `lookalike._site`) ----

    private fun site(input: String, bareHostOk: Boolean): Site? {
        var value = input
        if (value.isEmpty()) return null
        if (bareHostOk && !value.contains("://")) value = "https://$value"
        val n = Scalars.count(value)
        if (n <= 0 || n > 4096 || Origin.hasSpaceOrControl(value)) return null
        return try {
            parse(value)
        } catch (e: OriginException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private fun parse(value: String): Site? {
        val p = Origin.split(value)
        if (p.scheme != "https" && p.scheme != "http") return null
        if (p.hasUserInfo) return null
        val raw = p.hostname ?: return null
        val bracketed = p.netloc.substring(p.netloc.lastIndexOf('@') + 1).contains('[')
        var host = if (bracketed) Origin.urlHost(p, "URL is missing a host") else unicodeAsciiHost(raw)
        var port = p.port()
        if (port == (if (p.scheme == "https") 443 else 80)) port = null
        val scheme = p.scheme
        if (host.contains(':')) {
            host = compressedIpv6(Origin.ipv6(host) ?: return null)
            return Site(scheme, host, port, true, host, "", host, listOf(host))
        }
        if (endsInNumber(host)) {
            val v4 = whatwgIpv4(host) ?: return null
            return Site(scheme, v4, port, true, v4, "", v4, listOf(v4))
        }
        val labels = host.split(".").map(::decodeLabel)
        for (label in labels) checkBidi(label)
        val suffix = if (rules != null && host.contains('.')) rules.publicSuffix(host) else ""
        if (suffix.isEmpty() || suffix == host) return Site(scheme, host, port, false, host, "", "", labels)
        val head = host.substring(0, host.length - suffix.length - 1)
        val cut = head.lastIndexOf('.')
        val sub = if (cut < 0) "" else head.substring(0, cut)
        val regLabel = head.substring(cut + 1)
        val label = labels[if (sub.isEmpty()) 0 else sub.split(".").size]
        return Site(scheme, host, port, false, "$regLabel.$suffix", sub, label, labels)
    }

    /**
     * Desktop `_ascii_host`: ASCII hosts keep the historical label checks ([Origin.asciiHost]); a non-ASCII host is
     * mapped (UTS-46 style) and each non-ASCII label encoded to its `xn--` form.
     */
    private fun unicodeAsciiHost(raw: String): String {
        var host = raw.lowercase().replace('。', '.').replace('．', '.').replace('｡', '.')
        if (host.all { it.code < 0x80 }) return Origin.asciiHost(host)
        if (host.endsWith(".")) host = host.dropLast(1)
        require(host.isNotEmpty() && !host.endsWith(".")) { "bad host" }
        checkHostChars(host)
        val mapped = Normalizer.normalize(uts46Map(host), Normalizer.Form.NFC)
        val out = mapped.split(".").joinToString(".") { label ->
            require(label.isNotEmpty()) { "empty label" }
            if (label.all { it.code < 0x80 }) {
                label
            } else {
                // `idna.encode` (IDNA 2008) on a typed Unicode host: letters, marks and digits only (no emoji or symbols).
                require(label.codePoints().allMatch(::idna2008Like)) { "not IDNA 2008" }
                checkLabel(label)
                require(!(label.length >= 4 && label[2] == '-' && label[3] == '-')) { "hyphen in 3-4" }
                require(!label.startsWith("-") && !label.endsWith("-")) { "edge hyphen" }
                "xn--" + (Punycode.encode(label.codePoints().toArray()) ?: throw IllegalArgumentException("encode"))
            }
        }
        checkHostChars(out)
        return Origin.asciiHost(out)
    }

    private fun checkHostChars(host: String) {
        require(host.codePoints().noneMatch { it < 32 || Character.isWhitespace(it) || (it < 0x80 && FORBIDDEN_HOST_CHARS.indexOf(it.toChar()) >= 0) }) { "forbidden" }
    }

    private fun idna2008Like(cp: Int): Boolean {
        if (cp < 0x80) return cp.toChar() in 'a'..'z' || cp.toChar() in '0'..'9' || cp == '-'.code
        if (cp == ZWNJ || cp == ZWJ || cp in CONTEXTO) return true
        return when (Character.getType(cp).toByte()) {
            Character.LOWERCASE_LETTER, Character.OTHER_LETTER, Character.MODIFIER_LETTER, Character.NON_SPACING_MARK,
            Character.COMBINING_SPACING_MARK, Character.DECIMAL_DIGIT_NUMBER,
            -> true
            else -> false
        }
    }

    /** `uts46_remap` approximation: ignored code points dropped, NFKC of the casefold, deviation characters kept. */
    private fun uts46Map(s: String): String {
        val out = StringBuilder()
        s.codePoints().forEach { cp ->
            if (IdnaTables.contains(IGNORED, cp)) return@forEach
            if (cp in DEVIATIONS || cp == '.'.code) {
                out.appendCodePoint(cp)
            } else {
                val one = String(Character.toChars(cp))
                out.append(Normalizer.normalize(Casefold.fold(Normalizer.normalize(one, Normalizer.Form.NFKC)), Normalizer.Form.NFKC))
            }
        }
        return out.toString()
    }

    /** UTS-46 validity of a Unicode label: no disallowed code point, already mapped, NFC, no leading mark, joiners in context. */
    private fun checkLabel(label: String) {
        val cps = label.codePoints().toArray()
        for (cp in cps) {
            if (cp in DEVIATIONS) continue
            when (Character.getType(cp).toByte()) {
                Character.CONTROL, Character.PRIVATE_USE, Character.SURROGATE, Character.UNASSIGNED, Character.FORMAT,
                Character.SPACE_SEPARATOR, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR,
                -> throw IllegalArgumentException("disallowed")
            }
            if ((cp and 0xFFFE) == 0xFFFE || cp in 0xFDD0..0xFDEF) throw IllegalArgumentException("noncharacter")
        }
        require(uts46Map(label) == label) { "not in mapped form" }
        require(Normalizer.normalize(label, Normalizer.Form.NFC) == label) { "not NFC" }
        require(!isMark(cps[0])) { "leading combining mark" }
        for (i in cps.indices) {
            if ((cps[i] == ZWNJ || cps[i] == ZWJ) && !validContextJ(cps, i)) throw IllegalArgumentException("joiner context")
        }
    }

    /** `lookalike._decode_label`: the Unicode form of one A-label, refusing what browsers refuse. */
    private fun decodeLabel(label: String): String {
        if (!label.startsWith("xn--")) return label
        val cps = Punycode.decode(label.substring(4))
        require(cps.any { it >= 0x80 }) { "ascii punycode" }
        require(Punycode.encode(cps) == label.substring(4)) { "non-canonical punycode" }
        require(cps.none { it in 0xD800..0xDFFF }) { "surrogate" }
        val decoded = String(cps, 0, cps.size)
        checkLabel(decoded)
        return decoded
    }

    private fun isMark(cp: Int): Boolean = when (Character.getType(cp).toByte()) {
        Character.NON_SPACING_MARK, Character.ENCLOSING_MARK, Character.COMBINING_SPACING_MARK -> true
        else -> false
    }

    /** `idna.valid_contextj`. */
    private fun validContextJ(cps: IntArray, pos: Int): Boolean {
        if (pos > 0 && IdnaTables.contains(VIRAMA, cps[pos - 1])) return true
        if (cps[pos] == ZWJ) return false
        var ok = false
        for (i in pos - 1 downTo 0) {
            val cp = cps[i]
            if (IdnaTables.contains(JT_T, cp)) continue
            ok = IdnaTables.contains(JT_L, cp) || IdnaTables.contains(JT_D, cp)
            break
        }
        if (!ok) return false
        for (i in pos + 1 until cps.size) {
            val cp = cps[i]
            if (IdnaTables.contains(JT_T, cp)) continue
            return IdnaTables.contains(JT_R, cp) || IdnaTables.contains(JT_D, cp)
        }
        return false
    }

    /** `idna.check_bidi(label)` with `check_ltr=False`: only labels holding R, AL or AN characters are checked. */
    private fun checkBidi(label: String) {
        val dirs = label.codePoints().map { Character.getDirectionality(it).toInt() }.toArray()
        require(dirs.none { it == Character.DIRECTIONALITY_UNDEFINED.toInt() }) { "unknown directionality" }
        if (dirs.none { it == R || it == AL || it == AN }) return
        val rtl = when (dirs[0]) {
            R, AL -> true
            L -> false
            else -> throw IllegalArgumentException("bidi rule 1")
        }
        var validEnding = false
        var numberType = -1
        for (d in dirs) {
            if (rtl) {
                require(d in RTL_ALLOWED) { "bidi rule 2" }
                if (d == R || d == AL || d == EN || d == AN) validEnding = true else if (d != NSM) validEnding = false
                if (d == AN || d == EN) {
                    if (numberType < 0) numberType = d else require(numberType == d) { "bidi rule 4" }
                }
            } else {
                require(d in LTR_ALLOWED) { "bidi rule 5" }
                if (d == L || d == EN) validEnding = true else if (d != NSM) validEnding = false
            }
        }
        require(validEnding) { "bidi rule 3/6" }
    }

    private fun compressedIpv6(b: IntArray): String {
        val groups = IntArray(8) { (b[2 * it] shl 8) or b[2 * it + 1] }
        var bestStart = -1
        var bestLen = 0
        var i = 0
        while (i < 8) {
            if (groups[i] == 0) {
                var j = i
                while (j < 8 && groups[j] == 0) j++
                if (j - i > bestLen) { bestStart = i; bestLen = j - i }
                i = j
            } else {
                i++
            }
        }
        if (bestLen < 2) return groups.joinToString(":") { Integer.toHexString(it) }
        val left = (0 until bestStart).joinToString(":") { Integer.toHexString(groups[it]) }
        val right = (bestStart + bestLen until 8).joinToString(":") { Integer.toHexString(groups[it]) }
        return "$left::$right"
    }

    /** One WHATWG IPv4 number (decimal, 0x hex or 0 octal); null if invalid. */
    private fun number(part: String): BigInteger? {
        val (digits, base) = when {
            part.length >= 2 && part.substring(0, 2).lowercase() == "0x" -> part.substring(2) to 16
            part.length > 1 && part.startsWith("0") -> part.substring(1) to 8
            else -> part to 10
        }
        if (digits.isEmpty()) return if (base == 16) BigInteger.ZERO else null
        val allowed = "0123456789abcdef".substring(0, base)
        if (digits.lowercase().any { it !in allowed }) return null
        return BigInteger(digits, base)
    }

    private fun endsInNumber(host: String): Boolean {
        val last = host.substring(host.lastIndexOf('.') + 1)
        if (last.isNotEmpty() && last.all { it in '0'..'9' }) return true
        return last.length >= 2 && last.substring(0, 2).lowercase() == "0x" && number(last) != null
    }

    /** The WHATWG URL parser's IPv4 reading (`127.1` is `127.0.0.1`). */
    private fun whatwgIpv4(host: String): String? {
        val parts = host.split(".")
        if (parts.size > 4 || parts.any { it.isEmpty() }) return null
        val values = parts.map { number(it) ?: return null }
        val b256 = BigInteger.valueOf(256)
        if (values.dropLast(1).any { it > BigInteger.valueOf(255) }) return null
        if (values.last() >= b256.pow(5 - values.size)) return null
        var address = values.last()
        for ((index, v) in values.dropLast(1).withIndex()) address += v * b256.pow(3 - index)
        val a = address.toLong()
        return "${(a shr 24) and 255}.${(a shr 16) and 255}.${(a shr 8) and 255}.${a and 255}"
    }

    // ---- comparison (desktop `_compare`) ----

    private fun skeleton(label: String): String {
        val folded = Normalizer.normalize(label.lowercase(), Normalizer.Form.NFKD)
        val out = StringBuilder()
        folded.codePoints().forEach { cp ->
            if (isMark(cp)) return@forEach
            val c = CONFUSABLES[cp]
            if (c != null) out.append(c) else out.appendCodePoint(cp)
        }
        return out.toString()
    }

    private fun script(cp: Int): String? {
        if (cp < 0x80) return if (cp.toChar().isLetter()) "LATIN" else null
        SCRIPT_FIXED[cp]?.let { return it }
        if (!Character.isLetterOrDigit(cp) && !isNumber(cp)) return null
        val s = try {
            Character.UnicodeScript.of(cp)
        } catch (e: IllegalArgumentException) {
            return "OTHER"
        }
        return if (s.name in SCRIPTS) s.name else "OTHER"
    }

    private fun isNumber(cp: Int): Boolean = when (Character.getType(cp).toByte()) {
        Character.DECIMAL_DIGIT_NUMBER, Character.LETTER_NUMBER, Character.OTHER_NUMBER -> true
        else -> false
    }

    private fun mixedScript(label: String): Boolean {
        val scripts = HashSet<String>()
        label.codePoints().forEach { cp -> script(cp)?.let { scripts.add(it) } }
        return scripts.size > 1 && ALLOWED_MIXES.none { it.containsAll(scripts) }
    }

    private fun cps(s: String): IntArray = s.codePoints().toArray()

    private fun shortEditCounts(a: IntArray, b: IntArray): Boolean {
        if (a.size != b.size) return true
        val diff = a.indices.filter { a[it] != b[it] }
        if (diff.size == 1) return setOf(a[diff[0]], b[diff[0]]) in VISUAL_PAIRS
        return true // an adjacent transposition
    }

    /** Damerau-Levenshtein distance, optimal string alignment variant, on code points. */
    private fun osaDistance(a: IntArray, b: IntArray): Int {
        val rows = ArrayList<IntArray>()
        rows.add(IntArray(b.size + 1) { it })
        for (i in 1..a.size) {
            val row = IntArray(b.size + 1)
            row[0] = i
            for (j in 1..b.size) {
                val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                row[j] = minOf(rows[i - 1][j] + 1, row[j - 1] + 1, rows[i - 1][j - 1] + cost)
                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) row[j] = minOf(row[j], rows[i - 2][j - 2] + 1)
            }
            rows.add(row)
        }
        return rows[a.size][b.size]
    }

    private fun compare(site: Site, saved: Site): Pair<String, Int>? {
        if (site.host == saved.host) {
            return if (site.scheme == saved.scheme && site.port == saved.port) "same-origin" to 0 else "same-host" to 0
        }
        if (site.ip || saved.ip) return null
        if (site.registrable == saved.registrable) return "same-site" to 0
        if (site.label.isEmpty() || saved.label.isEmpty()) return null
        val mine = skeleton(site.label)
        val theirs = skeleton(saved.label)
        if (mine == theirs && site.label != saved.label) return "homoglyph" to 0
        val a = cps(mine)
        val b = cps(theirs)
        val longEnough = b.size >= MIN_EDIT_LABEL
        if (longEnough && site.label == saved.label) return "other-suffix" to 0
        if (site.sub.isNotEmpty() && ".${site.sub}.".contains(".${saved.registrable}.")) return "embedded" to 0
        val limit = if (b.size >= LONG_EDIT_LABEL) LONG_EDIT_DISTANCE else SHORT_EDIT_DISTANCE
        if (longEnough && Math.abs(a.size - b.size) <= limit) {
            val distance = osaDistance(a, b)
            if (distance <= limit && (limit > SHORT_EDIT_DISTANCE || shortEditCounts(a, b))) return "edit-distance" to distance
        }
        return null
    }

    companion object {
        const val MIN_EDIT_LABEL = 5
        const val SHORT_EDIT_DISTANCE = 1
        const val LONG_EDIT_LABEL = 9
        const val LONG_EDIT_DISTANCE = 2

        /** Same text as lookalike.py / lookalike.js. */
        const val VISUAL_PAIRS_TABLE = "0o 1i 1l 2z 5s 8b 9g 9q gq il uv nm"
        const val CONFUSABLES_TABLE =
            "0430a 0441c 0501d 0435e 04bbh 0456i 0458j 043ak 04cfl 043eo 0440p 051bq 0455s 0443y 0445x 051dw 04afy " +
                "03b1a 03b5e 03b9i 03bak 03bdv 03bfo 03c1p 03c4t 03c5u 03c7x 03b3y " +
                "0585o 057du 0581g 0570h 0578n 0566q " +
                "0131i 0251a 0261g 0237j"
        const val SCRIPT_TABLE = "3005h 3006h 3007h 303bh 309bk 309ck 30a0k 30fbk 30fck"

        private val VISUAL_PAIRS: Set<Set<Int>> = VISUAL_PAIRS_TABLE.split(' ').map { setOf(it[0].code, it[1].code) }.toSet()
        private val CONFUSABLES: Map<Int, String> = CONFUSABLES_TABLE.split(' ').associate { it.substring(0, 4).toInt(16) to it.substring(4) }
        private val SCRIPT_FIXED: Map<Int, String> = SCRIPT_TABLE.split(' ').associate {
            it.substring(0, 4).toInt(16) to (if (it[4] == 'h') "HAN" else "KATAKANA")
        }
        private val SCRIPTS = setOf(
            "HAN", "LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC", "HIRAGANA", "KATAKANA", "HANGUL",
            "BOPOMOFO", "THAI", "DEVANAGARI", "GEORGIAN", "CHEROKEE",
        )
        private val ALLOWED_MIXES = listOf(
            setOf("LATIN", "HAN", "HIRAGANA", "KATAKANA"),
            setOf("LATIN", "HAN", "BOPOMOFO"),
            setOf("LATIN", "HAN", "HANGUL"),
        )
        private val RANKS = mapOf(
            "same-origin" to 0, "same-host" to 1, "same-site" to 2, "homoglyph" to 3, "other-suffix" to 4,
            "embedded" to 5, "edit-distance" to 6,
        )
        private val KIND = mapOf("same-origin" to "exact", "same-host" to "related", "same-site" to "related")
        private val SHIELD_KIND = mapOf(
            "same-origin" to "exact", "same-host" to "related", "www-host" to "related", "same-site" to "unknown",
        )

        private const val FORBIDDEN_HOST_CHARS = "#/:<>?@[\\]^|%\u007f"
        private const val ZWNJ = 0x200C
        private const val ZWJ = 0x200D

        /** Non-transitional UTS-46 keeps these as they are. */
        private val DEVIATIONS = setOf(0x00DF, 0x03C2, ZWNJ, ZWJ)
        /** IDNA 2008 CONTEXTO code points (their context rules are not checked). */
        private val CONTEXTO = setOf(0x00B7, 0x0375, 0x05F3, 0x05F4, 0x30FB) + (0x0660..0x0669) + (0x06F0..0x06F9)

        /** UTS-46 "ignored": mapped to nothing (soft hyphen, variation selectors, zero width space...). */
        private val IGNORED = IdnaTables.ranges(
            "ad 34f 115f-1160 17b4-17b5 180b-180f 200b 2060-2064 206a-206f 3164 fe00-fe0f feff ffa0 1bca0-1bca3 " +
                "1d173-1d17a e0100-e01ef",
        )
        private val VIRAMA = IdnaTables.ranges(IdnaTables.VIRAMA)
        private val JT_L = IdnaTables.ranges(IdnaTables.JOINING_L)
        private val JT_D = IdnaTables.ranges(IdnaTables.JOINING_D)
        private val JT_R = IdnaTables.ranges(IdnaTables.JOINING_R)
        private val JT_T = IdnaTables.ranges(IdnaTables.JOINING_T)

        private val L = Character.DIRECTIONALITY_LEFT_TO_RIGHT.toInt()
        private val R = Character.DIRECTIONALITY_RIGHT_TO_LEFT.toInt()
        private val AL = Character.DIRECTIONALITY_RIGHT_TO_LEFT_ARABIC.toInt()
        private val EN = Character.DIRECTIONALITY_EUROPEAN_NUMBER.toInt()
        private val ES = Character.DIRECTIONALITY_EUROPEAN_NUMBER_SEPARATOR.toInt()
        private val ET = Character.DIRECTIONALITY_EUROPEAN_NUMBER_TERMINATOR.toInt()
        private val AN = Character.DIRECTIONALITY_ARABIC_NUMBER.toInt()
        private val CS = Character.DIRECTIONALITY_COMMON_NUMBER_SEPARATOR.toInt()
        private val NSM = Character.DIRECTIONALITY_NONSPACING_MARK.toInt()
        private val BN = Character.DIRECTIONALITY_BOUNDARY_NEUTRAL.toInt()
        private val ON = Character.DIRECTIONALITY_OTHER_NEUTRALS.toInt()
        private val RTL_ALLOWED = setOf(R, AL, AN, EN, ES, CS, ET, ON, BN, NSM)
        private val LTR_ALLOWED = setOf(L, EN, ES, CS, ET, ON, BN, NSM)
    }
}
