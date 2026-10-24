package app.localgatekeys.core.records

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.support.Vectors
import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Port of Swift `URLMatchTests`. Desktop `localvault.origin` parity: expected values were produced by the desktop's
 * own functions (`match_rank`, `entry_urls`, `base_domain`) with the `idna` package installed.
 */
class UrlMatchTest {
    private val pslFile: File = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot is not set"), "src/localvault/assets/public_suffix_list.dat")

    private val rules: PublicSuffixRules? by lazy {
        check(pslFile.isFile) { "public suffix list missing at $pslFile" }
        PublicSuffixRules.load(pslFile.readText(Charsets.UTF_8))
    }

    private val matcher: UrlMatcher get() = UrlMatcher(rules)

    private fun digest(set: Set<String>): String {
        val text = set.sortedWith { a, b -> Scalars.compare(a, b) }.joinToString("\n")
        return Hex.lower(MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)))
    }

    @Test
    fun suffix_rules_equal_desktop_parse() {
        val r = assertNotNull(rules, "public suffix list missing at $pslFile")
        // Desktop: suffix_rules() -> 10018 normal, 311 wildcard, 8 exception (IDNA rules as A-labels).
        assertEquals(10018, r.normal.size)
        assertEquals(311, r.wildcard.size)
        assertEquals(8, r.exception.size)
        assertEquals("e7b252fd28770493bb4c535d99cd5b5231f9da115fe817a64a281f02b15e9e7b", digest(r.normal))
        assertEquals("ed512b85712c945aa1b889e3be8c831f60d152e7deb31025ae096d506d4aef5e", digest(r.wildcard))
        assertEquals("dfbf3e07d8e99b5b9d71971eebf7a926d2d23d02d7c5ae1841d02968244bc958", digest(r.exception))
    }

    @Test
    fun truncated_list_fails_closed() {
        assertNull(PublicSuffixRules.load("com\nco.uk\n"))
        val closed = UrlMatcher(null)
        assertEquals("login.example.co.uk", closed.baseDomain("login.example.co.uk"))
        assertNull(closed.matchRank(listOf(UrlRow("https://a.example.com/", UrlMatchMode.BASE_DOMAIN)), "https://b.example.com/"))
    }

    @Test
    fun base_domain_matches_desktop() {
        assertNotNull(rules)
        for ((host, expected) in baseDomains) assertEquals(expected, matcher.baseDomain(host), host)
    }

    /** The URL rows of `normalise/entries.json`: each accepted web case's normalised record is the stored login. */
    @Test
    fun matcher_table_from_normalise_vectors() {
        val top = Vectors.json(Vectors.sync("normalise/entries.json")).obj().fields
        val seen = HashSet<String>()
        for (c in top["cases"]!!.arr()) {
            val case = c.obj().fields
            val name = case["name"]!!.str()
            val expected = vectorExpected[name] ?: continue
            val record = (case["output"] as? JsonValue.Obj)?.fields ?: fail(name)
            seen.add(name)
            val rows = UrlMatcher.entryUrls(record)
            for ((i, candidate) in vectorCandidates.withIndex()) {
                var want = expected[i]
                // Known divergence: the phone has no UTS-46, so a non-ASCII candidate host fails closed (the desktop
                // encodes it). Browsers and AutoFill hand the extension A-label hosts.
                if (candidate.any { it.code >= 0x80 }) want = null
                assertEquals(want, matcher.matchRank(rows, candidate), "$name vs $candidate")
            }
        }
        assertEquals(12, vectorExpected.size)
        assertEquals(vectorExpected.keys, seen, "every URL case must be in the vectors")
    }

    @Test
    fun each_mode_extra_rows() {
        for (x in extraRows) {
            val record = mapOf<String, JsonValue>(
                "kind" to JsonValue.Str("web"),
                "scope" to JsonValue.Obj(
                    mapOf(
                        "urls" to JsonValue.Arr(
                            x.rows.map { JsonValue.Obj(mapOf("url" to JsonValue.Str(it.first), "match" to JsonValue.Str(it.second))) },
                        ),
                    ),
                ),
            )
            assertEquals(x.rank, matcher.matchRank(UrlMatcher.entryUrls(record), x.candidate), "${x.rows} vs ${x.candidate}")
        }
    }

    @Test
    fun starts_with_compares_code_points() {
        // "é" precomposed vs "e" + combining acute are different code point sequences (Python compares them so).
        assertFalse("caf\u00e9" == "cafe\u0301")
        assertFalse(UrlMatcher.startsWith("https://x.com/caf\u00e9", "https://x.com/cafe\u0301/a"))
        assertTrue(UrlMatcher.startsWith("https://x.com/caf\u00e9", "https://x.com/caf\u00e9/a"))
        assertNull(UrlMatchMode.fromStored("host\u0301"))
        assertEquals(UrlMatchMode.HOST, UrlMatchMode.fromStored("host"))
    }

    @Test
    fun mode_ranks_follow_match_modes_order() {
        assertEquals(listOf(0, 1, 2, 3), UrlMatchMode.entries.map { it.rank })
        assertEquals(listOf("exact_origin", "host", "base_domain", "starts_with"), UrlMatchMode.entries.map { it.stored })
    }

    private fun login(id: String, updated: Long, rows: List<Pair<String, String>>, kind: String = "web"): Map<String, JsonValue> = mapOf(
        "id" to JsonValue.Str(id),
        "kind" to JsonValue.Str(kind),
        "updated_at" to JsonValue.Int(updated),
        "scope" to JsonValue.Obj(
            mapOf(
                "origin" to JsonValue.Str("https://unused.example"),
                "urls" to JsonValue.Arr(rows.map { JsonValue.Obj(mapOf("url" to JsonValue.Str(it.first), "match" to JsonValue.Str(it.second))) }),
            ),
        ),
    )

    @Test
    fun candidates_rank_exact_origin_first_then_updated_then_id() {
        val records = listOf(
            login("d", 9, listOf("https://example.com/" to "base_domain")),
            login("c", 1, listOf("https://login.example.com" to "exact_origin")),
            login("b", 5, listOf("https://login.example.com/" to "host")),
            login("a", 1, listOf("https://login.example.com" to "exact_origin")),
            login("e", 99, listOf("https://login.example.com" to "exact_origin"), kind = "desktop"),
            login("f", 99, listOf("https://other.org" to "exact_origin")),
            mapOf(
                "id" to JsonValue.Str("g"),
                "kind" to JsonValue.Str("web"),
                "updated_at" to JsonValue.Int(2),
                "scope" to JsonValue.Obj(mapOf("origin" to JsonValue.Str("https://login.example.com"))),
            ),
        )
        fun ids(urls: List<String>) = matcher.candidates(records, urls).map { records[it]["id"]!!.str() }
        assertEquals(listOf("g", "a", "c", "b", "d"), ids(listOf("https://login.example.com/signin")))
        // Several service identifiers: best rank across them.
        assertEquals("f", ids(listOf("https://other.org/", "https://login.example.com/")).first())
    }

    @Test
    fun punycode_rfc3492_samples() {
        fun p(s: String): String? = Punycode.idnaLabel(s.codePoints().toArray())
        assertEquals("xn--bcher-kva", p("bücher"))
        assertEquals("xn--r8jz45g", p("例え"))
        assertEquals("xn--zckzah", p("テスト"))
        assertEquals("xn--fa-hia", p("faß"))
    }

    @Test
    fun punycode_overlong_label_is_ignored() {
        assertNull(Punycode.idnaLabel(IntArray(70) { 0x4f8b }))
    }

    @Test
    fun host_of_uses_the_origin_url_parser() {
        assertEquals("example.com", UrlMatcher.hostOf("HTTPS://Example.COM.:8443/x"))
        assertEquals("2001:db8::1", UrlMatcher.hostOf("https://[2001:DB8::1]/"))
        assertEquals(OriginException.Kind.INVALID, kotlin.test.assertFailsWith<OriginException> { UrlMatcher.hostOf("not a url") }.kind)
    }


    private val vectorCandidates = listOf(
        "https://example.com",
        "https://example.com/login?x=1",
        "https://www.example.com/",
        "http://example.com",
        "https://example.com:8443/",
        "https://app.example.com/a",
        "https://a.example.com",
        "https://a.example.com:444/",
        "https://b.example.com/x",
        "https://zz.b.example.com/",
        "https://c.example.com/",
        "https://other.c.example.com/p",
        "https://d.example.com/",
        "https://d.example.com/deep/path",
        "https://evil-example.com/",
        "https://xn--bcher-kva.example/login",
        "https://xn--fa-hia.de/",
        "https://xn--r8jz45g.xn--zckzah/",
        "https://[2001:db8::1]:8443/",
        "https://[2001:db8::1]/",
        "http://localhost:8080/x",
        "http://localhost/",
        "not a url",
        "https://b\u00fccher.example/",
    )

    private val vectorExpected: Map<String, List<Int?>> = mapOf(
        "plain_web_login" to listOf(0, 0, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null),
        "origin_upper_case_scheme_and_host" to listOf(0, 0, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null),
        "origin_default_https_port" to listOf(0, 0, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null),
        "origin_trailing_dot" to listOf(0, 0, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null),
        "origin_ipv6_upper_case_with_port" to listOf(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 0, null, null, null, null, null),
        "origin_localhost_http_with_port" to listOf(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 0, null, null, null),
        "origin_idna_umlaut" to listOf(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 0, null, null, null, null, null, null, null, 0),
        "origin_idna_sharp_s_non_transitional" to listOf(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 0, null, null, null, null, null, null, null),
        "origin_idna_japanese" to listOf(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 0, null, null, null, null, null, null),
        "urls_bare_string_row" to listOf(null, null, null, null, null, 0, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null),
        "urls_each_match_mode" to listOf(2, 2, 2, null, 2, 2, 0, 2, 1, 2, 2, 2, 2, 2, null, null, null, null, null, null, null, null, null, null),
        "urls_duplicate_row_dropped" to listOf(null, null, null, null, null, 0, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null),
    )

    private class Extra(val rows: List<Pair<String, String>>, val candidate: String, val rank: Int?)

    private val extraRows = listOf(
        Extra(listOf("https://example.com" to "exact_origin"), "https://example.com:443/x", 0),
        Extra(listOf("https://example.com" to "exact_origin"), "https://www.example.com/", null),
        // M-4: a plain-HTTP candidate on a non-loopback host never matches. I-13: host mode compares the port.
        Extra(listOf("https://login.example.com/" to "host"), "http://login.example.com:9/q", null),
        Extra(listOf("https://login.example.com/" to "host"), "https://login.example.com:9/q", null),
        Extra(listOf("https://login.example.com/" to "host"), "https://login.example.com:443/q", 1),
        Extra(listOf("https://login.example.com/" to "host"), "https://example.com/", null),
        Extra(listOf("https://login.example.co.uk/" to "base_domain"), "https://shop.example.co.uk/", 2),
        Extra(listOf("https://login.example.co.uk/" to "base_domain"), "https://other.co.uk/", null),
        Extra(listOf("https://a.github.io/" to "base_domain"), "https://b.github.io/", null),
        Extra(listOf("https://a.github.io/" to "base_domain"), "https://a.github.io/x", 2),
        Extra(listOf("https://www.ck/" to "base_domain"), "https://x.www.ck/", 2),
        Extra(listOf("https://foo.bar.ck/" to "base_domain"), "https://baz.bar.ck/", null),
        Extra(listOf("https://foo.bar.ck/" to "base_domain"), "https://x.foo.bar.ck/", 2),
        Extra(listOf("https://acct.z13.web.core.windows.net/" to "base_domain"), "https://other.z13.web.core.windows.net/", null),
        Extra(listOf("https://192.168.1.10/" to "base_domain"), "https://192.168.1.10:8443/", 2),
        Extra(listOf("https://localhost/" to "base_domain"), "https://localhost/", 2),
        Extra(listOf("https://co.uk/" to "base_domain"), "https://x.co.uk/", null),
        Extra(listOf("https://a.xn--r8jz45g.xn--zckzah/" to "base_domain"), "https://b.xn--r8jz45g.xn--zckzah/", 2),
        Extra(listOf("https://a.b.xn--zckzah/" to "base_domain"), "https://c.b.xn--zckzah/", 2),
        Extra(listOf("https://example.com/app" to "starts_with"), "https://example.com/app/login", 3),
        Extra(listOf("https://example.com/app" to "starts_with"), "https://example.com/application", null),
        Extra(listOf("https://example.com/app" to "starts_with"), "https://example.com/app?next=1", 3),
        Extra(listOf("https://example.com/app" to "starts_with"), "https://example.com/app", 3),
        Extra(listOf("https://example.com/app/" to "starts_with"), "https://example.com/app/x", 3),
        Extra(listOf("https://example.com/caf\u00e9" to "starts_with"), "https://example.com/cafe\u0301/x", null),
        Extra(listOf("https://example.com/caf\u00e9" to "starts_with"), "https://example.com/caf\u00e9/x", 3),
        Extra(listOf("https://EXAMPLE.com:443/A" to "starts_with"), "https://example.com/A/b", 3),
        Extra(listOf("https://example.com/A" to "starts_with"), "https://example.com/a/b", null),
        Extra(listOf("https://example.com" to "starts_with", "https://example.com" to "host", "https://example.com" to "exact_origin"), "https://example.com/z", 0),
        Extra(listOf("https://sub.example.com" to "exact_origin", "https://x.example.com" to "base_domain"), "https://sub.example.com/", 0),
        Extra(listOf("not a url" to "host", "https://example.com" to "host"), "https://example.com/", 1),
        Extra(listOf("https://example.com" to "regex"), "https://example.com/", 0),
    )

    private val baseDomains = listOf(
        "login.example.co.uk" to "example.co.uk",
        "example.co.uk" to "example.co.uk",
        "co.uk" to "co.uk",
        "a.b.github.io" to "b.github.io",
        "github.io" to "github.io",
        "x.www.ck" to "www.ck",
        "www.ck" to "www.ck",
        "a.b.c.ck" to "b.c.ck",
        "localhost" to "localhost",
        "192.168.0.1" to "192.168.0.1",
        "::1" to "::1",
        "a.b.kawasaki.jp" to "a.b.kawasaki.jp",
        "city.kawasaki.jp" to "city.kawasaki.jp",
        "x.city.kawasaki.jp" to "city.kawasaki.jp",
        "acct.z1.web.core.windows.net" to "acct.z1.web.core.windows.net",
        "foo.unknowntld" to "foo.unknowntld",
        "a.xn--r8jz45g.xn--zckzah" to "xn--r8jz45g.xn--zckzah",
        "xn--zckzah" to "xn--zckzah",
        "b.a.xn--55qx5d.cn" to "a.xn--55qx5d.cn",
        "EXAMPLE.COM." to "example.com",
        "q.blogspot.com" to "q.blogspot.com",
    )
}
