package app.localgatekeys.core.hygiene

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.PasswordHistory
import app.localgatekeys.core.records.PublicSuffixRules
import app.localgatekeys.core.records.UrlMatcher
import app.localgatekeys.core.support.Vectors
import java.io.File
import java.time.LocalDate
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.test.Test
import app.localgatekeys.core.support.assertEq
import app.localgatekeys.core.support.assertTr

class HygieneTest {
    private val matcher: UrlMatcher by lazy {
        val psl = File(System.getProperty("lgk.repoRoot")!!, "src/localvault/assets/public_suffix_list.dat")
        UrlMatcher(PublicSuffixRules.load(psl.readText(Charsets.UTF_8)))
    }

    private fun s(v: String) = JsonValue.Str(v)

    private fun login(id: String, origin: String, user: String, pw: String, updated: Long = 10, extra: Map<String, JsonValue> = emptyMap()) = mapOf(
        "id" to s(id), "kind" to s("web"), "label" to s(id), "username" to s(user), "password" to s(pw),
        "scope" to JsonValue.Obj(mapOf("origin" to s(origin))), "updated_at" to JsonValue.Int(updated),
    ) + extra

    private fun item(id: String, kind: String, payload: Map<String, JsonValue>, title: String = "T", updated: Long = 10) = mapOf(
        "id" to s(id), "kind" to s(kind), "title" to s(title), "payload" to JsonValue.Obj(payload), "updated_at" to JsonValue.Int(updated),
    )

    private val today = LocalDate.of(2026, 11, 15)

    @Test
    fun duplicateFinders() {
        val records = listOf(
            login("a", "https://example.com", "Me ", "pw", updated = 5),
            login("b", "https://example.com", "me", "pw", updated = 9),
            login("c", "https://example.com", "ME", "other"),
            login("d", "https://www.example.com", "me", "x"),
            login("e", "https://alice.github.io", "bob", "1"),
            login("f", "https://carol.github.io", "bob", "1"),
            login("g", "https://shop.example.co.uk", "", "1"),
            login("h", "https://mail.example.co.uk", "", "1"),
            item("p1", "passkey", mapOf("relying_party_id" to s("x.com"), "credential_id" to s("c1"))),
            item("p2", "passkey", mapOf("relying_party_id" to s("x.com"), "credential_id" to s("c1"))),
            item("n1", "note", mapOf("body" to s("b"), "notes" to s("one")), title = "Note"),
            item("n2", "note", mapOf("body" to s("b"), "notes" to s("two")), title = " note"),
            mapOf("id" to s("z"), "kind" to s("desktop"), "username" to s("me")),
        )
        val got = Hygiene.findings(records, 1_000_000_000L, today, matcher::baseDomainOf).filter { it.type in Hygiene.DUPLICATE_TYPES }
        assertEquals(
            listOf(
                Hygiene.Finding(Hygiene.SAME_LOGIN, listOf("b", "a")),
                Hygiene.Finding(Hygiene.SAME_ACCOUNT_OTHER_PASSWORD, listOf("c", "b", "a")),
                Hygiene.Finding(Hygiene.SAME_SITE, listOf("c", "d", "b", "a")),
                Hygiene.Finding(Hygiene.SAME_ITEM, listOf("p1", "p2")),
                Hygiene.Finding(Hygiene.SAME_ITEM, listOf("n1", "n2")),
            ),
            got,
        )
    }

    @Test
    fun notChangedAndExpired() {
        val now = 2_000_000_000L
        val records = listOf(
            login("old", "https://a.example", "u", "p", updated = now - 731L * 86_400L),
            login("new", "https://a.example", "v", "p", updated = now - 10),
            item("card1", "card", mapOf("expiry" to s("10/26"))),
            item("card2", "card", mapOf("expiry" to s("11/26"))),
            item("card3", "card", mapOf("expiry" to s("10/2026"))),
            item("lic", "license", mapOf("expiration_date" to s("2026-11-14"))),
            item("lic2", "license", mapOf("expiration_date" to s("2026-W01"))),
            item("api", "api_key", mapOf("expires" to s("20261101"))),
            item("sub", "subscription", mapOf("expiration_date" to s("2020-01-01"), "active" to JsonValue.Bool(false))),
        )
        val all = Hygiene.findings(records, now, today, matcher::baseDomainOf)
        assertEquals(listOf("old"), all.first { it.type == Hygiene.NOT_CHANGED_2Y }.ids.filter { it == "old" || it == "new" })
        assertEquals(setOf("card1", "card3", "lic", "api"), all.first { it.type == Hygiene.EXPIRED }.ids.toSet())
        assertTrue(Hygiene.isExpired(item("c", "card", mapOf("expiry" to s("12/26"))), LocalDate.of(2027, 1, 1)))
        assertTrue(!Hygiene.isExpired(item("c", "card", mapOf("expiry" to s("12/26"))), LocalDate.of(2026, 12, 31)))
    }

    private fun row(url: String) = JsonValue.Obj(mapOf("url" to s(url), "match" to s("starts_with")))

    @Test
    fun mergeRules() {
        val keeper = login(
            "k", "https://a.example", "u", "new", extra = mapOf(
                "tags" to JsonValue.Arr(listOf(s("Bank"))), "notes" to s("mine"),
                "scope" to JsonValue.Obj(mapOf("origin" to s("https://a.example"), "urls" to JsonValue.Arr(listOf(row("https://a.example/x"))))),
            ),
        )
        val other = login(
            "o", "https://a.example", "u", "old", extra = mapOf(
                "tags" to JsonValue.Arr(listOf(s("bank"), s("Trip"))), "notes" to s("theirs"), "favorite" to JsonValue.Bool(true),
                "scope" to JsonValue.Obj(
                    mapOf(
                        "origin" to s("https://a.example"), "urls" to JsonValue.Arr(listOf(row("https://a.example/x"), row("https://a.example/y"))),
                        "access" to JsonValue.Obj(mapOf("copy" to s("once"))),
                    ),
                ),
            ),
        )
        val m = Hygiene.merge(keeper, other, 500)
        assertEquals(JsonValue.Arr(listOf(s("Bank"), s("Trip"))), m["tags"])
        assertEquals(s("mine\n\ntheirs"), m["notes"])
        assertEquals(JsonValue.Bool(true), m["favorite"])
        assertEquals(s("new"), m["password"])
        assertEquals("old", PasswordHistory.entries(m).first().password)
        val scope = (m["scope"] as JsonValue.Obj).fields
        assertEquals(2, (scope["urls"] as JsonValue.Arr).items.size)
        assertEquals(JsonValue.Obj(mapOf("copy" to s("once"))), scope["access"])
        assertEquals(JsonValue.Int(500), m["updated_at"])
        fun refused(code: String, a: Map<String, JsonValue>, b: Map<String, JsonValue>) {
            try {
                Hygiene.merge(a, b, 1)
                fail(code)
            } catch (e: MergeException) {
                assertEquals(code, e.code)
            }
        }
        refused("notes_too_long", keeper + ("notes" to s("x".repeat(15_000))), other + ("notes" to s("y".repeat(6_000))))
        refused("too_many_tags", keeper + ("tags" to JsonValue.Arr((1..15).map { s("a$it") })), other + ("tags" to JsonValue.Arr((1..15).map { s("b$it") })))
        // Typed items: at most 20 collection ids, as Python (scan A-L7).
        fun note(id: String, cols: IntRange) = item(id, "secure_note", mapOf("notes" to s("n"))) + ("collection_ids" to JsonValue.Arr(cols.map { s("c$it") }))
        assertEquals(20, (Hygiene.merge(note("a", 1..10), note("b", 11..20), 1)["collection_ids"] as JsonValue.Arr).items.size)
        refused("too_many_values", note("a", 1..11), note("b", 12..21))
    }

    // MARK: shared vectors (tests/vectors/hygiene/)

    private fun cases(file: String): List<Map<String, JsonValue>> {
        val root = Vectors.json(Vectors.optional("hygiene/$file"))
        val list = (root as? JsonValue.Arr)?.items ?: ((root as JsonValue.Obj).fields["cases"] as JsonValue.Arr).items
        return list.map { (it as JsonValue.Obj).fields }
    }

    private fun recs(v: JsonValue?): List<Map<String, JsonValue>> = (v as JsonValue.Arr).items.map { (it as JsonValue.Obj).fields }
    private fun strs(v: JsonValue?) = (v as JsonValue.Arr).items.map { (it as JsonValue.Str).v }

    @Test
    fun duplicateVectors() {
        for (c in cases("duplicates.json")) {
            val now = (c.getValue("now") as JsonValue.Int).v
            val got = Hygiene.findings(recs(c["records"]), now, today, matcher::baseDomainOf).filter { it.type in Hygiene.DUPLICATE_TYPES }
            val want = recs(c["expected"]).map { Hygiene.Finding((it.getValue("type") as JsonValue.Str).v, strs(it["ids"])) }
            val key = compareBy<Hygiene.Finding>({ it.type }, { it.ids.joinToString(",") })
            assertEq("${c["name"]}", want.filter { it.type in Hygiene.DUPLICATE_TYPES }.sortedWith(key), got.sortedWith(key))
        }
    }

    @Test
    fun expiredVectors() {
        for (c in cases("expired.json")) {
            val day = LocalDate.parse((c.getValue("today") as JsonValue.Str).v)
            val got = recs(c["records"]).filter { Hygiene.isExpired(it, day) }.map { (it.getValue("id") as JsonValue.Str).v }
            assertEq("${c["name"]}", strs(c["expected_ids"]).sorted(), got.sorted())
        }
    }

    @Test
    fun mergeVectors() {
        for (c in cases("merge.json")) {
            val run = { Hygiene.merge((c.getValue("keeper") as JsonValue.Obj).fields, (c.getValue("other") as JsonValue.Obj).fields, (c.getValue("now") as JsonValue.Int).v) }
            val err = (c["error"] as? JsonValue.Str)?.v
            if (err != null) {
                try {
                    run()
                    fail("${c["name"]}")
                } catch (e: MergeException) {
                    assertEq("${c["name"]}", err, e.code)
                }
            } else {
                assertEq("${c["name"]}", c.getValue("expected"), JsonValue.Obj(run()))
            }
        }
    }

    // MARK: cross-kind merge and edge cases (A-L13); expected values made by running Python `hygiene.merge` and
    // `access_policy.stricter_policy` (resource hygiene/merge_cross_kind.json; the shared vectors have no such case).

    private val crossKind: Map<String, JsonValue> by lazy {
        val bytes = javaClass.getResourceAsStream("/hygiene/merge_cross_kind.json")!!.use { it.readBytes() }
        (app.localgatekeys.core.json.CanonicalJson.parse(bytes) as JsonValue.Obj).fields
    }

    @Test
    fun crossKindMergeMatchesPython() {
        val list = (crossKind.getValue("merge") as JsonValue.Arr).items.map { (it as JsonValue.Obj).fields }
        assertTrue(list.size >= 10)
        for (c in list) {
            val name = (c.getValue("name") as JsonValue.Str).v
            val run = { Hygiene.merge((c.getValue("keeper") as JsonValue.Obj).fields, (c.getValue("other") as JsonValue.Obj).fields, (c.getValue("now") as JsonValue.Int).v) }
            val err = (c["error"] as? JsonValue.Str)?.v
            if (err != null) {
                try {
                    run()
                    fail(name)
                } catch (e: MergeException) {
                    assertEq(name, err, e.code)
                }
            } else {
                assertEq(name, c.getValue("expected"), JsonValue.Obj(run()))
            }
        }
    }

    @Test
    fun webLoginMergesWithDesktopLogin() {
        val web = mapOf("kind" to JsonValue.Str("web"), "password" to JsonValue.Str("a"), "scope" to JsonValue.Obj(mapOf("origin" to JsonValue.Str("https://example.com"))))
        val desktop = mapOf(
            "kind" to JsonValue.Str("desktop"), "password" to JsonValue.Str("b"),
            "scope" to JsonValue.Obj(mapOf("app" to JsonValue.Str("x.exe"), "access" to JsonValue.Obj(mapOf("phones" to JsonValue.Str("view"))))),
        )
        val merged = Hygiene.merge(web, desktop, 10)
        val scope = (merged.getValue("scope") as JsonValue.Obj).fields
        // The keeper's addresses stay; the desktop login's view-only rule is never loosened by the merge.
        assertEquals(JsonValue.Str("https://example.com"), scope["origin"])
        assertEquals(JsonValue.Obj(mapOf("phones" to JsonValue.Str("view"))), scope["access"])
        assertEquals(listOf("b"), PasswordHistory.entries(merged).map { it.password })
        val back = Hygiene.merge(desktop, web, 10)
        assertEquals(JsonValue.Str("x.exe"), ((back.getValue("scope") as JsonValue.Obj).fields)["app"])
        assertTrue("urls" !in (back.getValue("scope") as JsonValue.Obj).fields)
    }

    @Test
    fun stricterPolicyMatchesPython() {
        for (c in (crossKind.getValue("stricter_policy") as JsonValue.Arr).items.map { (it as JsonValue.Obj).fields }) {
            val a = c["a"]?.takeIf { it != JsonValue.Null }
            val b = c["b"]?.takeIf { it != JsonValue.Null }
            assertEq("$a + $b", c["expected"]?.takeIf { it != JsonValue.Null }, app.localgatekeys.core.access.AccessRules.stricterPolicy(a, b))
        }
    }
}
