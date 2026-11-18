package app.localgatekeys.core.security

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.PublicSuffixRules
import app.localgatekeys.core.support.Vectors
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `tests/vectors/lookalike/cases.json`: the same cases `src/localvault/lookalike.py` and `browser-extension/lookalike.js`
 * pass. Kind, matched (the saved origin exactly as given) and reason must be identical.
 */
class LookalikeTest {
    private val rules: PublicSuffixRules by lazy {
        val psl = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot is not set"), "src/localvault/assets/public_suffix_list.dat")
        checkNotNull(PublicSuffixRules.load(psl.readText(Charsets.UTF_8)))
    }

    private val lookalike by lazy { Lookalike(rules) }

    private fun cases(): List<Map<String, JsonValue>> =
        Vectors.json(Vectors.file("lookalike/cases.json")).obj().fields.getValue("cases").arr().map { it.obj().fields }

    @Test
    fun every_shared_vector_matches() {
        val all = cases()
        assertTrue(all.size >= 92, "expected the full vector set, got ${all.size}")
        val failures = ArrayList<String>()
        for (case in all) {
            val origin = case.getValue("origin").str()
            val saved = case.getValue("saved").arr().map { it.str() }
            val expected = LookalikeVerdict(
                case.getValue("kind").str(),
                (case["matched"] as? JsonValue.Str)?.v,
                case.getValue("reason").str(),
            )
            val got = lookalike.classify(origin, saved)
            if (got != expected) failures.add("${case.getValue("name").str()}: expected $expected, got $got")
        }
        assertEquals(emptyList(), failures)
    }

    /** `tests/vectors/lookalike/crosscheck.json`: about 5,800 origin/saved pairs Python and the extension agree on. */
    @Test
    fun the_crosscheck_corpus_matches() {
        val doc = Vectors.json(Vectors.file("lookalike/crosscheck.json")).obj().fields
        val origins = doc.getValue("origins").arr().map { it.str() }
        val saved = doc.getValue("saved").arr().map { it.str() }
        val pairs = doc.getValue("pairs").arr()
        assertTrue(pairs.size >= 5000, "expected the full corpus, got ${pairs.size}")
        val failures = ArrayList<String>()
        fun verdict(row: List<JsonValue>, at: Int): LookalikeVerdict {
            val matched = row[at + 1].long().toInt()
            return LookalikeVerdict(row[at].str(), if (matched < 0) null else saved[matched], row[at + 2].str())
        }
        for (p in pairs) {
            val row = p.arr()
            val origin = origins[row[0].long().toInt()]
            val one = saved[row[1].long().toInt()]
            val expected = verdict(row, 2)
            val got = lookalike.classify(origin, listOf(one))
            if (got != expected) failures.add("$origin vs $one: expected $expected, got $got")
        }
        for (l in doc.getValue("lists").arr()) {
            val row = l.arr()
            val origin = origins[row[0].long().toInt()]
            val expected = verdict(row, 1)
            val got = lookalike.classify(origin, saved)
            if (got != expected) failures.add("$origin vs all: expected $expected, got $got")
        }
        assertEquals(emptyList(), failures)
    }

    /**
     * Design decision 2026-11-12: the phishing shield ([Lookalike.shield], desktop `lookalike.classify`) keeps
     * "related" for the same host or its `www.` twin; `crosscheck.json` `shield_pairs` (the pairs that differ from
     * [Lookalike.classify]) and `shield_lists`.
     */
    @Test
    fun the_shield_corpus_matches() {
        val doc = Vectors.json(Vectors.file("lookalike/crosscheck.json")).obj().fields
        val origins = doc.getValue("origins").arr().map { it.str() }
        val saved = doc.getValue("saved").arr().map { it.str() }
        fun verdict(row: List<JsonValue>, at: Int): LookalikeVerdict {
            val matched = row[at + 1].long().toInt()
            return LookalikeVerdict(row[at].str(), if (matched < 0) null else saved[matched], row[at + 2].str())
        }
        val overrides = HashMap<Pair<Int, Int>, LookalikeVerdict>()
        for (p in doc.getValue("shield_pairs").arr()) {
            val row = p.arr()
            overrides[row[0].long().toInt() to row[1].long().toInt()] = verdict(row, 2)
        }
        assertTrue(overrides.size >= 20, "expected shield overrides, got ${overrides.size}")
        val failures = ArrayList<String>()
        for (p in doc.getValue("pairs").arr()) {
            val row = p.arr()
            val o = row[0].long().toInt()
            val s = row[1].long().toInt()
            val expected = overrides[o to s] ?: verdict(row, 2)
            val got = lookalike.shield(origins[o], listOf(saved[s]))
            if (got != expected) failures.add("${origins[o]} vs ${saved[s]}: expected $expected, got $got")
        }
        for (l in doc.getValue("shield_lists").arr()) {
            val row = l.arr()
            val origin = origins[row[0].long().toInt()]
            val got = lookalike.shield(origin, saved)
            if (got != verdict(row, 1)) failures.add("$origin vs all: expected ${verdict(row, 1)}, got $got")
        }
        assertEquals(emptyList(), failures)
        assertEquals(
            LookalikeVerdict("unknown", "https://accounts.google.com", "same-site"),
            lookalike.shield("https://sites.google.com", listOf("https://accounts.google.com")),
        )
        assertEquals(
            LookalikeVerdict("related", "https://example.com", "www-host"),
            lookalike.shield("https://www.example.com", listOf("https://accounts.example.com", "https://example.com")),
        )
    }

    @Test
    fun without_rules_only_hosts_and_mixed_script_count() {
        val bare = Lookalike(null)
        assertEquals(LookalikeVerdict("exact", "https://example.com", "same-origin"), bare.classify("https://example.com", listOf("https://example.com")))
        assertEquals(LookalikeVerdict("unknown", null, "no-match"), bare.classify("https://paypa1.com", listOf("https://paypal.com")))
        assertEquals(LookalikeVerdict("lookalike", null, "mixed-script"), bare.classify("https://xn--pple-43d.com", listOf("https://example.com")))
    }

    @Test
    fun the_tables_are_the_reference_text() {
        val py = File(System.getProperty("lgk.repoRoot"), "src/localvault/lookalike.py").readText()
        for (table in listOf(Lookalike.CONFUSABLES_TABLE, Lookalike.VISUAL_PAIRS_TABLE, Lookalike.SCRIPT_TABLE)) {
            val words = table.split(' ')
            // The Python source splits long tables over several string literals; every entry must be there in order.
            var at = 0
            for (w in words) {
                val i = py.indexOf(w, at)
                assertTrue(i >= 0, "entry $w missing from lookalike.py")
                at = i + w.length
            }
        }
    }

    @Test
    fun junk_saved_entries_and_odd_inputs_never_throw() {
        val junk = listOf("", " ", "://", "https://", "https://[::1", "https://a:99999", "xn--", "https://xn--.com", "https://\u0000.com", "https://" + "a".repeat(5000))
        for (s in junk) {
            lookalike.classify(s, junk)
            lookalike.classify("https://example.com", listOf(s))
        }
    }
}
