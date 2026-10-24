package app.localgatekeys.core.records

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.support.Vectors
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `tests/vectors/origin/url_cases.json`: the desktop's `canonicalize_origin`, `normalize_url`, `origin_of`, `host_of`
 * and `match_rank` on forbidden host code points, whitespace, brackets, zone ids, IPv4-mapped addresses, trailing
 * dots, ports in `host` mode and plain-HTTP candidates (audit 2026-10-24 L-27, L-28, L-29, I-13, I-22, M-4).
 * Values and error messages must be identical.
 */
class OriginVectorsTest {
    private val doc: Map<String, JsonValue> by lazy {
        val file = File(Vectors.root, "origin/url_cases.json")
        check(file.isFile) { "vector missing: $file" }
        Vectors.json(file).obj().fields
    }

    private val rules: PublicSuffixRules? by lazy {
        val psl = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot is not set"), "src/localvault/assets/public_suffix_list.dat")
        PublicSuffixRules.load(psl.readText(Charsets.UTF_8))
    }

    private fun run(fn: (String) -> String, input: String): Map<String, String> = try {
        mapOf("ok" to fn(input))
    } catch (e: OriginException) {
        assertEquals(OriginException.Kind.INVALID, e.kind, input)
        mapOf("error" to (e.message ?: ""))
    }

    @Test
    fun functions_match_the_desktop() {
        val functions: List<Pair<String, (String) -> String>> = listOf(
            "canonicalize" to Origin::canonicalize,
            "normalize_url" to Origin::normalizeUrl,
            "origin_of" to Origin::originOf,
            "host_of" to UrlMatcher::hostOf,
        )
        val cases = doc["cases"]!!.arr()
        assertTrue(cases.size >= 50)
        for (c in cases) {
            val case = c.obj().fields
            val input = case["input"]!!.str()
            for ((name, fn) in functions) {
                val want = case[name]!!.obj().fields.mapValues { it.value.str() }
                assertEquals(want, run(fn, input), "$name(${input.map { if (it.code < 0x20 || it.code > 0x7e) "\\u%04x".format(it.code) else "$it" }.joinToString("")})")
            }
        }
    }

    @Test
    fun match_rank_matches_the_desktop() {
        val matcher = UrlMatcher(rules)
        val cases = doc["match"]!!.arr()
        assertTrue(cases.size >= 30)
        for (c in cases) {
            val case = c.obj().fields
            val rows = case["rows"]!!.arr().map { r ->
                val pair = r.arr()
                UrlRow(pair[0].str(), UrlMatchMode.fromStored(pair[1].str())!!)
            }
            val candidate = case["candidate"]!!.str()
            val want = (case["rank"] as? JsonValue.Int)?.v?.toInt()
            assertEquals(want, matcher.matchRank(rows, candidate), "$rows vs $candidate")
        }
    }
}
