package app.localgatekeys.core.records

import app.localgatekeys.core.json.JsonValue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame

/** Workstream 8: 10 entries, 365 days, restore puts the current password into the history. */
class PasswordHistoryTest {
    private val day = 86_400L
    private val now = 1_800_000_000L

    private fun login(password: String, history: List<Pair<String, Long>> = emptyList()): Map<String, JsonValue> = mapOf(
        "password" to JsonValue.Str(password),
        "password_history" to JsonValue.Arr(
            history.map { (p, at) -> JsonValue.Obj(mapOf("password" to JsonValue.Str(p), "changed_at" to JsonValue.Int(at))) },
        ),
    )

    @Test fun a_change_pushes_the_old_password_to_the_front() {
        val r = PasswordHistory.push(login("new", listOf("older" to now - day)), "old", now)
        assertEquals(listOf("old", "older"), PasswordHistory.entries(r).map { it.password })
        assertEquals(now, PasswordHistory.entries(r)[0].changedAt)
    }

    @Test fun no_change_or_an_empty_old_password_leaves_the_record() {
        val r = login("same")
        assertSame(r, PasswordHistory.push(r, "same", now))
        assertSame(r, PasswordHistory.push(r, "", now))
    }

    @Test fun keeps_ten_entries_and_drops_those_older_than_a_year() {
        val ten = (1..10).map { "p$it" to now - it }
        val r = PasswordHistory.push(login("new", ten), "old", now)
        assertEquals(PasswordHistory.WRITE_LIMIT, PasswordHistory.entries(r).size, "Windows 0.4.9 refuses more than 5")
        assertEquals("p4", PasswordHistory.entries(r).last().password)
        val aged = PasswordHistory.push(login("new", listOf("year" to now - 365 * day, "stale" to now - 366 * day)), "old", now)
        assertEquals(listOf("old", "year"), PasswordHistory.entries(aged).map { it.password })
    }

    @Test fun restore_swaps_the_entry_with_the_current_password() {
        val r = PasswordHistory.restore(login("current", listOf("a" to now - 5, "b" to now - 9)), 1, now)!!
        assertEquals(JsonValue.Str("b"), r["password"])
        assertEquals(listOf("current", "a"), PasswordHistory.entries(r).map { it.password })
        assertNull(PasswordHistory.restore(login("x"), 0, now))
    }

    @Test fun the_normaliser_accepts_ten_entries() {
        val rows = (1..10).map { JsonValue.Obj(mapOf("password" to JsonValue.Str("p$it"), "changed_at" to JsonValue.Int(now))) }
        val entry = JsonValue.Obj(
            mapOf(
                "id" to JsonValue.Str("0b5e0000-0000-4000-8000-000000000001"), "kind" to JsonValue.Str("web"),
                "label" to JsonValue.Str("Example"), "username" to JsonValue.Str("ada"), "password" to JsonValue.Str("now"),
                "scope" to JsonValue.Obj(mapOf("origin" to JsonValue.Str("https://example.com"))),
                "created_at" to JsonValue.Int(now), "updated_at" to JsonValue.Int(now),
                "favorite" to JsonValue.Bool(false), "tags" to JsonValue.Arr(emptyList()),
                "password_history" to JsonValue.Arr(rows),
            ),
        )
        val normal = (Normalise.normalForm(Namespace.ENTRY, entry) as JsonValue.Obj).fields
        assertEquals(10, PasswordHistory.entries(normal).size)
    }
}
