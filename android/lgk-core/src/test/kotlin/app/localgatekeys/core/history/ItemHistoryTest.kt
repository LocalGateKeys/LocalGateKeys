package app.localgatekeys.core.history

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.PasswordHistory
import app.localgatekeys.core.support.Vectors
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.test.Test
import app.localgatekeys.core.support.assertEq
import app.localgatekeys.core.support.assertTr

class ItemHistoryTest {
    private fun s(v: String) = JsonValue.Str(v)
    private fun i(v: Long) = JsonValue.Int(v)

    private fun row(id: String, item: String, at: Long, pad: Int = 0) = ItemHistory.Row(
        id, item, "entry", at, "update", mapOf("id" to s(item), "notes" to s("x".repeat(pad))),
    ).json()

    private fun ids(rows: List<JsonValue>) = rows.map { (it as JsonValue.Obj).fields["snapshot_id"]!!.let { v -> (v as JsonValue.Str).v } }

    @Test
    fun pruneCutsAgeThenPerItemThenBytes() {
        val now = 100L * 86_400L
        val limits = ItemHistory.Limits(2, 30, Long.MAX_VALUE)
        val rows = listOf(
            row("old", "a", now - 31 * 86_400L),
            row("a1", "a", now - 10), row("a2", "a", now - 5), row("a3", "a", now - 1),
            row("b2", "b", now - 3), row("b1", "b", now - 3), row("b3", "b", now - 3),
        )
        // Equal created_at: snapshot_id ascending wins.
        assertEquals(listOf("a2", "a3", "b2", "b1"), ids(ItemHistory.prune(rows, now, limits)))
        val size = ItemHistory.canon(row("x1", "x", now - 3, 50)).size.toLong()
        val bytes = ItemHistory.prune(
            listOf(row("x1", "x", now - 3, 50), row("y1", "y", now - 2, 50), row("x2", "x", now - 1, 50)),
            now, ItemHistory.Limits(5, 30, size * 2),
        )
        assertEquals(listOf("y1", "x2"), ids(bytes))
    }

    @Test
    fun freeAndProWindows() {
        val now = 400L * 86_400L
        val rows = (1..40).map { row("r%02d".format(it), "a", now - it * 86_400L) }
        assertEquals(5, ItemHistory.prune(rows, now, ItemHistory.FREE).size)
        assertEquals(30, ItemHistory.prune(rows, now, ItemHistory.PRO).size)
        assertEquals(10, ItemHistory.prune(rows.takeLast(10), now, ItemHistory.limits(true)).size)
    }

    @Test
    fun diffFlattensMasksAndIgnores() {
        val before = mapOf(
            "id" to s("a"), "kind" to s("web"), "password" to s("old"), "tags" to JsonValue.Arr(listOf(s("x"))),
            "updated_at" to i(1), "site_icon" to s("i"), "policy" to JsonValue.Obj(mapOf("sign_in" to s("never"), "fill" to s("click"))),
            "custom_fields" to JsonValue.Arr(listOf(JsonValue.Obj(mapOf("name" to s("n"))))),
            "scope" to JsonValue.Obj(mapOf("origin" to s("https://a.example"), "browser_approvals" to s("1"))),
        )
        val after = before + mapOf(
            "password" to s("new"), "tags" to JsonValue.Arr(listOf(s("x"), s("y"))), "updated_at" to i(2), "site_icon" to s("j"),
            "policy" to JsonValue.Obj(mapOf("sign_in" to s("enabled"), "fill" to s("click"))),
            "custom_fields" to JsonValue.Arr(emptyList()), "username" to s("ü"),
            "scope" to JsonValue.Obj(mapOf("origin" to s("https://b.example"), "browser_approvals" to s("2"))),
        )
        val d = ItemHistory.diff(before, after, "web", reveal = false)
        assertEquals(listOf("custom_fields", "password", "scope.origin", "tags", "username"), d.map { it.field })
        val pw = d.first { it.field == "password" }
        assertTrue(pw.secret)
        assertEquals(s(ItemHistory.PROTECTED), pw.before)
        assertNull(d.first { it.field == "username" }.before)
        assertFalse(d.first { it.field == "tags" }.secret)
        assertEquals(s("new"), ItemHistory.diff(before, after, "web", reveal = true).first { it.field == "password" }.after)
    }

    @Test
    fun secretTable() {
        assertTrue(ItemHistory.isSecret("card", "payload.number"))
        assertFalse(ItemHistory.isSecret("card", "payload.cardholder"))
        assertTrue(ItemHistory.isSecret("identity", "payload.email"))
        assertFalse(ItemHistory.isSecret("identity", "payload.template_id"))
        assertTrue(ItemHistory.isSecret("web", "totp.secret"))
        assertTrue(ItemHistory.isSecret("bookmark", "payload.url"))
    }

    private fun login(password: String, username: String = "me", now: Long = 1_000L) = mapOf(
        "id" to s("6f1c1a52-0000-4000-8000-000000000001"), "kind" to s("web"), "label" to s("Site"), "username" to s(username),
        "password" to s(password), "scope" to JsonValue.Obj(mapOf("origin" to s("https://example.com"))),
        "created_at" to i(1), "updated_at" to i(now),
    )

    @Test
    fun capturesOnlyRealChanges() {
        fun w(r: Map<String, JsonValue>) = JsonValue.Obj(mapOf("ns" to s("entry"), "record" to JsonValue.Obj(r)))
        val a = login("one")
        val before = mapOf("x" to w(a), "y" to w(a), "col:1" to s("c"))
        val after = mapOf("x" to w(a + ("site_icon" to s("icon"))), "y" to w(login("two")), "col:1" to s("d"), "z" to w(a))
        var n = 0
        val rows = ItemHistory.captures(before, after, 50, "sync") { "id${n++}" }
        assertEquals(1, rows.size)
        val r = ItemHistory.Row.of(rows[0])!!
        assertEquals("y", r.itemId)
        assertEquals("sync", r.changeType)
        assertEquals(s("one"), r.record["password"])
    }

    @Test
    fun restoreOneField() {
        val current = login("new", "now")
        val snap = login("old", "then")
        val u = ItemHistory.restoreField(current, snap, "username", 2_000)
        assertEquals(s("then"), u["username"])
        assertEquals(s("new"), u["password"])
        assertEquals(i(2_000), u["updated_at"])
        val p = ItemHistory.restoreField(current, snap, "password", 2_000)
        assertEquals(s("old"), p["password"])
        assertEquals("new", PasswordHistory.entries(p).first().password)
        for (bad in listOf("created_at", "id", "kind", "password_history", "site_icon", "policy.sign_in", "")) {
            try {
                ItemHistory.restoreField(current, snap, bad, 2_000)
                fail(bad)
            } catch (e: HistoryException) {
                assertEquals("not_restorable", e.code)
            }
        }
        val broken = current + ("scope" to JsonValue.Obj(mapOf("origin" to s("not a url at all ://"))))
        try {
            ItemHistory.restoreField(current, broken, "scope.origin", 2_000)
            fail()
        } catch (e: HistoryException) {
            assertEquals("invalid_on_this_device", e.code)
        }
    }

    // MARK: shared vectors (tests/vectors/history/)

    private fun cases(file: String): List<Map<String, JsonValue>> {
        val root = Vectors.json(Vectors.optional("history/$file"))
        val list = (root as? JsonValue.Arr)?.items ?: ((root as JsonValue.Obj).fields["cases"] as JsonValue.Arr).items
        return list.map { (it as JsonValue.Obj).fields }
    }

    private fun limits(v: JsonValue): ItemHistory.Limits {
        val f = (v as JsonValue.Obj).fields
        return ItemHistory.Limits(
            (f.getValue("max_versions") as JsonValue.Int).v.toInt(), (f.getValue("max_age_days") as JsonValue.Int).v.toInt(),
            (f.getValue("max_bytes") as JsonValue.Int).v,
        )
    }

    @Test
    fun pruneVectors() {
        for (c in cases("prune.json")) {
            val got = ids(ItemHistory.prune((c.getValue("rows") as JsonValue.Arr).items, (c.getValue("now") as JsonValue.Int).v, limits(c.getValue("limits"))))
            val want = (c.getValue("expected_ids") as JsonValue.Arr).items.map { (it as JsonValue.Str).v }
            assertEq("${c["name"]}", want.sorted(), got.sorted())
        }
    }

    @Test
    fun diffVectors() {
        for (c in cases("diff.json")) {
            val got = ItemHistory.diff(
                (c["before"] as? JsonValue.Obj)?.fields, (c["after"] as? JsonValue.Obj)?.fields, (c.getValue("kind") as JsonValue.Str).v,
                c["reveal"] == JsonValue.Bool(true),
            ).map {
                JsonValue.Obj(
                    mapOf("field" to s(it.field), "before" to (it.before ?: JsonValue.Null), "after" to (it.after ?: JsonValue.Null), "secret" to JsonValue.Bool(it.secret)),
                )
            }
            assertEq("${c["name"]}", c.getValue("expected"), JsonValue.Arr(got))
        }
    }

    @Test
    fun restoreFieldVectors() {
        for (c in cases("restore_field.json")) {
            val run = {
                ItemHistory.restoreField(
                    (c.getValue("current") as JsonValue.Obj).fields, (c.getValue("snapshot") as JsonValue.Obj).fields,
                    (c.getValue("path") as JsonValue.Str).v, (c.getValue("now") as JsonValue.Int).v,
                )
            }
            val err = (c["error"] as? JsonValue.Str)?.v
            if (err != null) {
                try {
                    run()
                    fail("${c["name"]}")
                } catch (e: HistoryException) {
                    assertEq("${c["name"]}", err, e.code)
                }
            } else {
                assertEq("${c["name"]}", c.getValue("expected"), JsonValue.Obj(run()))
            }
        }
    }
}
