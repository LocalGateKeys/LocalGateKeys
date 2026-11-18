package app.localgatekeys.android.trash

import app.localgatekeys.android.reminders.Reminder
import app.localgatekeys.core.json.JsonValue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class LocalDataTest {
    private val record = JsonValue.Obj(mapOf("id" to JsonValue.Str("n1"), "kind" to JsonValue.Str("note"), "title" to JsonValue.Str("Ünïcode ✓")))

    @Test fun encode_and_decode_round_trip_and_keep_unknown_keys() {
        val d = LocalData(
            trash = listOf(LocalData.TrashRow.of(record, 100), LocalData.TrashRow.of(record, 200)),
            preferences = LocalData.Preferences(trashRetentionDays = 7),
            extra = mapOf("events" to JsonValue.Arr(listOf(JsonValue.Int(1)))),
            reminders = listOf(
                Reminder("r1", "i1", "2026-12-25", 30),
                Reminder("r2", "i2", "2027-01-31", 7, Reminder.Status.SNOOZED, "2027-01-02", "2027-01-01"),
                Reminder("r3", "i2", "2027-03-01", 0, Reminder.Status.DISMISSED),
            ),
        )
        val back = LocalData.decode(LocalData.encode(d))
        assertEquals(d, back)
        assertEquals(record, back.trash[0].record())
        // The iPhone's keys.
        val text = String(LocalData.encode(d), Charsets.UTF_8)
        for (k in listOf(
            "\"trash\"", "\"record\"", "\"deleted_at\"", "\"trash_retention_days\"", "\"trash_auto_purge\"", "\"reminders\"",
            "\"item_id\"", "\"due_date\"", "\"lead_days\"", "\"snooze_until\"", "\"last_notified\"", "\"pending\"",
        )) {
            assert(text.contains(k)) { k }
        }
    }

    @Test fun a_file_from_before_reminders_moved_here_reads_with_none() {
        val old = """{"preferences":{"reminder_default_lead_days":0,"trash_auto_purge":true,"trash_retention_days":30},"trash":[]}"""
        val d = LocalData.decode(old.toByteArray())
        assertEquals(emptyList<Reminder>(), d.reminders)
        assertEquals(emptyMap<String, JsonValue>(), d.extra)
        // Written again, it carries the (empty) reminders key from now on.
        assert(String(LocalData.encode(d)).contains("\"reminders\":[]"))
    }

    @Test fun reminder_rows_are_validated_like_the_iphones() {
        val ok = Reminder("r1", "i1", "2026-12-25", 0)
        LocalData(reminders = listOf(ok)).validated()
        for (bad in listOf(
            listOf(ok, ok),
            listOf(ok.copy(id = "")),
            listOf(ok.copy(itemId = "")),
            listOf(ok.copy(dueDate = "2026-02-30")),
            listOf(ok.copy(leadDays = -1)),
            listOf(ok.copy(leadDays = Reminder.MAX_LEAD_DAYS + 1)),
            listOf(ok.copy(snoozeUntil = "soon")),
        )) {
            assertThrows(LocalDataException::class.java) { LocalData(reminders = bad).validated() }
        }
        val text = { status: String ->
            """{"preferences":{"reminder_default_lead_days":0,"trash_auto_purge":true,"trash_retention_days":30},"trash":[],
               "reminders":[{"id":"r1","item_id":"i1","due_date":"2026-12-25","lead_days":0,"status":"$status","snooze_until":"","last_notified":""}]}"""
        }
        assertEquals(Reminder.Status.ACTIVE, LocalData.decode(text("pending").toByteArray()).reminders.single().status)
        assertThrows(LocalDataException::class.java) { LocalData.decode(text("active").toByteArray()) }
        assertThrows(LocalDataException::class.java) { LocalData.decode(text("pending").replace("\"lead_days\":0", "\"lead_days\":\"0\"").toByteArray()) }
    }

    @Test fun validation_refuses_what_the_iphone_refuses() {
        assertThrows(LocalDataException::class.java) { LocalData(preferences = LocalData.Preferences(trashRetentionDays = 0)).validated() }
        assertThrows(LocalDataException::class.java) { LocalData(preferences = LocalData.Preferences(trashRetentionDays = 366)).validated() }
        assertThrows(LocalDataException::class.java) { LocalData(trash = listOf(LocalData.TrashRow("[1]", 1))).validated() }
        assertThrows(LocalDataException::class.java) { LocalData(trash = listOf(LocalData.TrashRow("{", 1))).validated() }
        assertThrows(LocalDataException::class.java) { LocalData(trash = listOf(LocalData.TrashRow.of(record, -1))).validated() }
        val many = List(LocalData.MAX_TRASH + 1) { LocalData.TrashRow.of(record, 1) }
        assertThrows(LocalDataException::class.java) { LocalData(trash = many).validated() }
        assertThrows(LocalDataException::class.java) { LocalData.decode("{}".toByteArray()) }
        assertThrows(LocalDataException::class.java) { LocalData.decode("not json".toByteArray()) }
    }

    @Test fun purge_drops_rows_past_the_retention_only_when_auto_purge_is_on() {
        val now = 1_800_000_000L
        val d = LocalData(
            trash = listOf(LocalData.TrashRow.of(record, now - 31 * 86_400), LocalData.TrashRow.of(record, now - 30 * 86_400), LocalData.TrashRow.of(record, now)),
        )
        assertEquals(2, d.purgeExpiredTrash(now).trash.size)
        assertEquals(1, d.copy(preferences = LocalData.Preferences(trashRetentionDays = 1)).purgeExpiredTrash(now).trash.size)
        assertEquals(3, d.copy(preferences = LocalData.Preferences(trashAutoPurge = false)).purgeExpiredTrash(now).trash.size)
    }

    // Sub-plan 07: the starter ids stay on this phone; older local collections are read once for the migration.
    @Test fun starter_collection_ids_round_trip_and_are_left_out_when_none() {
        val ids = listOf("c0000000-0000-4000-8000-000000000001", "c0000000-0000-4000-8000-000000000002")
        val d = LocalData(starterCollectionIds = ids)
        assertEquals(ids, LocalData.decode(LocalData.encode(d)).starterCollectionIds)
        assert(String(LocalData.encode(d), Charsets.UTF_8).contains("\"starter_collection_ids\""))
        assert(!String(LocalData.encode(LocalData()), Charsets.UTF_8).contains("starter_collection_ids"))
        assertThrows(LocalDataException::class.java) { LocalData(starterCollectionIds = listOf(ids[0], ids[0])).validated() }
        assertThrows(LocalDataException::class.java) { LocalData(starterCollectionIds = listOf("not-an-id")).validated() }
    }

    @Test fun legacy_collections_are_read_leniently_and_cleared() {
        val good = "c0000000-0000-4000-8000-000000000001"
        fun row(vararg f: Pair<String, JsonValue>) = JsonValue.Obj(mapOf(*f))
        val d = LocalData(
            extra = mapOf(
                "events" to JsonValue.Arr(emptyList()),
                "collections" to JsonValue.Arr(
                    listOf(
                        row("id" to JsonValue.Str(good.uppercase()), "name" to JsonValue.Str("x".repeat(150)), "description" to JsonValue.Str("d"),
                            "created_at" to JsonValue.Int(5), "updated_at" to JsonValue.Int(3), "starter" to JsonValue.Bool(true)),
                        row("id" to JsonValue.Str(good), "name" to JsonValue.Str("Duplicate id")),
                        row("id" to JsonValue.Str("nope"), "name" to JsonValue.Str("Bad id")),
                        row("id" to JsonValue.Str("c0000000-0000-4000-8000-000000000002")),
                        JsonValue.Str("not a row"),
                    ),
                ),
                "memberships" to JsonValue.Obj(
                    mapOf("i1" to JsonValue.Arr(listOf(JsonValue.Str(good), JsonValue.Str("bad"))), "i2" to JsonValue.Arr(emptyList())),
                ),
            ),
        )
        assert(d.hasLegacyCollections)
        val c = d.legacyCollections().single()
        assertEquals(good, c.id)
        assertEquals(100, c.name.length)
        assertEquals(5L, c.createdAt)
        assertEquals(5L, c.updatedAt)
        assert(c.starter)
        assertEquals(mapOf("i1" to listOf(good)), d.legacyMemberships())
        val cleared = d.withoutLegacyCollections()
        assert(!cleared.hasLegacyCollections)
        assertEquals(setOf("events"), cleared.extra.keys)
        assertEquals(emptyList<Any>(), LocalData().legacyCollections())
    }

    @Test fun to_string_never_shows_records() {
        val d = LocalData(trash = listOf(LocalData.TrashRow.of(record, 1)))
        assert(!d.toString().contains("Ünïcode")) { d.toString() }
    }
}
