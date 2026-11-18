package app.localgatekeys.android.reminders

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.json.JsonValue
import java.io.File
import java.nio.file.Files
import java.time.LocalDate
import java.time.ZoneId
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** The alarm book and the reminders model on fakes: what is armed, when, with which text, and what a wipe leaves. */
class RemindersModelTest {
    private class FakeSetter : AlarmSetter {
        val armed = linkedMapOf<String, Long>()
        override fun set(id: String, atMillis: Long) { armed[id] = atMillis }
        override fun cancel(id: String) { armed.remove(id) }
    }

    private val utc = ZoneId.of("UTC")
    private fun millis(date: String, hour: Int = 0, minute: Int = 0): Long =
        LocalDate.parse(date).atTime(hour, minute).atZone(utc).toInstant().toEpochMilli()

    private lateinit var dir: File
    private val setter = FakeSetter()
    private var now = millis("2026-11-01", 8)
    private val txt = EnglishTxt()
    private val store = MemoryReminderStore()
    private val prefs = ReminderPrefs(MemoryStore())
    private var ids = 0
    private lateinit var alarms: ReminderAlarms
    private lateinit var model: Reminders

    @Before fun setUp() {
        dir = Files.createTempDirectory("lgk-alarms").toFile()
        alarms = ReminderAlarms(File(dir, "reminder-alarms.json"), setter, { now }, { utc })
        model = Reminders(store, alarms, prefs, txt, { now }, { utc }, { "r${++ids}" })
        model.items = listOf(card("c1", "Visa", "08/27"), item("d1", "document", "Passport"), item("w1", "web", "Example"))
    }

    @After fun tearDown() { dir.deleteRecursively() }

    private fun item(id: String, kind: String, title: String, payload: Map<String, JsonValue> = emptyMap()) =
        VaultItem.of(
            id,
            JsonValue.Obj(
                mapOf(
                    "kind" to JsonValue.Str(kind), "title" to JsonValue.Str(title), "password" to JsonValue.Str("hunter2-SECRET"),
                    "payload" to JsonValue.Obj(payload),
                ),
            ),
        )!!

    private fun card(id: String, title: String, expiry: String) = item(id, "card", title, mapOf("expiry" to JsonValue.Str(expiry), "number" to JsonValue.Str("4111111111111111")))

    @Test fun a_reminder_arms_one_alarm_at_nine_on_due_minus_lead() {
        assertNull(model.set("d1", "2026-12-25", 7))
        assertEquals(mapOf("r1" to millis("2026-12-18", 9)), setter.armed)
        assertEquals("2026-12-18", alarms.entry("r1")!!.day)
    }

    @Test fun setting_again_replaces_the_items_active_reminder_and_its_alarm() {
        model.set("d1", "2026-12-25", 7)
        model.set("d1", "2027-01-10", 0)
        assertEquals(listOf("r2"), store.rows.map { it.id })
        assertEquals(mapOf("r2" to millis("2027-01-10", 9)), setter.armed)
    }

    @Test fun a_login_gets_no_reminder_and_a_bad_date_or_unknown_item_is_refused() {
        assertEquals(Reminders.Failure.NOT_TYPED, model.set("w1", "2026-12-25", 0))
        assertEquals(Reminders.Failure.NOT_TYPED, model.set("nope", "2026-12-25", 0))
        assertEquals(Reminders.Failure.INVALID_DATE, model.set("d1", "2026-02-30", 0))
        assertTrue(store.rows.isEmpty())
        assertTrue(setter.armed.isEmpty())
        assertFalse(Reminders.canHaveReminder(item("x", "desktop", "App")))
    }

    @Test fun done_cancels_the_alarm_snooze_moves_it_and_delete_removes_the_row() {
        model.set("d1", "2026-11-05", 0)
        model.snooze("r1")
        assertEquals(Reminder.Status.SNOOZED, store.rows.single().status)
        assertEquals(mapOf("r1" to millis("2026-11-05", 9)), setter.armed) // snooze to tomorrow is before the due day: unchanged
        model.snooze("r1", days = 10)
        assertEquals(mapOf("r1" to millis("2026-11-11", 9)), setter.armed)
        model.complete("r1")
        assertTrue(setter.armed.isEmpty())
        assertEquals(Reminder.Status.DISMISSED, store.rows.single().status)
        assertTrue(model.rows().isEmpty())
        assertNull(model.reminderFor("d1"))
        model.delete("r1")
        assertTrue(store.rows.isEmpty())
    }

    @Test fun the_text_is_anonymous_unless_names_are_on_and_a_change_of_the_setting_replans() {
        model.set("d1", "2026-12-25", 0)
        assertNull(alarms.entry("r1")!!.name)
        prefs.showItemNames = true
        model.reschedule()
        assertEquals("Passport", alarms.entry("r1")!!.name)
        prefs.showItemNames = false
        model.reschedule()
        assertNull(alarms.entry("r1")!!.name)
    }

    @Test fun nothing_secret_is_in_the_row_file_or_the_alarm_book() {
        prefs.showItemNames = false
        model.set("c1", "2027-08-31", 30)
        val book = File(dir, "reminder-alarms.json").readText()
        val rows = String(app.localgatekeys.android.trash.LocalData.encode(app.localgatekeys.android.trash.LocalData(reminders = store.rows)))
        for (text in listOf(book, rows)) {
            assertFalse(text, text.contains("hunter2"))
            assertFalse(text, text.contains("4111"))
            assertFalse(text, text.contains("Visa"))
        }
        // The plain book holds only what re-arming needs: reminder ids and days (no item id, no due date, no lead).
        assertFalse(book, book.contains("c1"))
        assertFalse(book, book.contains("2027-08-31"))
        assertEquals(setOf("v", "alarms", "notified", "id", "day"), Regex("\"(\\w+)\":").findAll(book).map { it.groupValues[1] }.toSet())
    }

    @Test fun a_notification_sent_while_locked_is_kept_in_the_rows_at_the_next_plan_and_not_sent_again() {
        model.set("d1", "2026-11-02", 0)
        // The 09:00 alarm went off on the 2nd while the vault was locked: the receiver writes only the book.
        alarms.fired("r1", "2026-11-02")
        assertEquals(mapOf("r1" to "2026-11-02"), alarms.notified())
        assertEquals("", store.rows.single().lastNotified)
        now = millis("2026-11-02", 11)
        model.reschedule() // the unlock after: no "soon" repeat, and the day is now in the encrypted rows
        assertTrue(setter.armed.isEmpty())
        assertEquals("2026-11-02", store.rows.single().lastNotified)
        // A later day drops the old record from the book.
        now = millis("2026-11-03", 8)
        model.reschedule()
        assertTrue(alarms.notified().isEmpty())
    }

    @Test fun a_reminder_that_became_due_after_nine_comes_soon_once_and_is_remembered() {
        now = millis("2026-11-01", 10)
        model.set("d1", "2026-11-01", 0)
        assertEquals(now + ReminderAlarms.SOON_MILLIS, setter.armed["r1"])
        // Shown: the receiver records the day in the book.
        alarms.fired("r1", "2026-11-01")
        model.reschedule() // a second re-plan the same day sends nothing new
        assertTrue(setter.armed.isEmpty())
        assertEquals("2026-11-01", store.rows.single().lastNotified)
    }

    /** Release check 2026-11-01: the alarm went off while the Allow dialog was still open, and the day's reminder was lost. */
    @Test fun a_soon_notification_that_could_not_be_shown_stays_due_and_comes_with_the_next_plan() {
        now = millis("2026-11-01", 10)
        model.set("d1", "2026-11-01", 0)
        // The alarm went off, but the notification was not allowed yet: the receiver records nothing.
        setter.armed.clear()
        assertEquals("", store.rows.single().lastNotified)
        assertTrue(alarms.notified().isEmpty())
        assertNotNull("the entry stays in the book, so a restart re-arms it", alarms.entry("r1"))
        now = millis("2026-11-01", 10, 1)
        model.reschedule() // allowed now (or the next unlock): it comes again, soon
        assertEquals(now + ReminderAlarms.SOON_MILLIS, setter.armed["r1"])
    }

    @Test fun the_book_never_arms_an_entry_already_notified_on_its_day() {
        now = millis("2026-11-01", 10)
        alarms.replaceAll(listOf(AlarmEntry("r1", null, null), AlarmEntry("r2", null, null), AlarmEntry("r3", "2026-11-05", null)))
        // r1 went out while a plan that still listed it was being made.
        alarms.fired("r1", "2026-11-01")
        alarms.replaceAll(listOf(AlarmEntry("r1", null, null), AlarmEntry("r2", null, null), AlarmEntry("r3", "2026-11-05", null)))
        assertEquals(setOf("r2", "r3"), setter.armed.keys)
        assertEquals(listOf("r2", "r3"), alarms.entries().map { it.id })
    }

    @Test fun a_gone_item_or_a_trashed_one_has_no_alarm_and_a_restored_one_gets_it_back() {
        model.set("d1", "2026-12-25", 0)
        val all = model.items
        model.items = all.filter { it.id != "d1" }
        assertTrue(setter.armed.isEmpty())
        assertTrue(model.rows().isEmpty())
        model.items = all
        assertEquals(1, setter.armed.size)
    }

    @Test fun rows_list_overdue_first_and_only_the_window() {
        model.set("c1", "2026-10-30", 0) // overdue
        model.set("d1", "2026-11-20", 0)
        val rows = model.rows(days = 30)
        assertEquals(listOf("c1", "d1"), rows.map { it.itemId })
        assertTrue(rows[0].overdue)
        assertFalse(rows[1].overdue)
        assertEquals("Visa", rows[0].title)
        assertEquals(listOf("c1"), model.rows(days = 10).map { it.itemId })
    }

    @Test fun a_card_suggests_the_end_of_its_expiry_month_until_it_has_a_reminder_or_has_passed() {
        val c = model.items.first { it.id == "c1" }
        assertEquals("2027-08-31", model.suggestion(c))
        assertNull(model.suggestion(model.items.first { it.id == "d1" }))
        model.set("c1", "2027-08-31", 0)
        assertNull(model.suggestion(c))
        model.delete("r1")
        now = millis("2027-09-02", 8)
        assertNull(model.suggestion(c))
    }

    @Test fun a_failed_save_says_so_changes_nothing_and_arms_nothing() {
        store.failSaves = true
        assertEquals(Reminders.Failure.SAVE, model.set("d1", "2026-12-25", 0))
        assertEquals(txt.s(app.localgatekeys.android.R.string.reminder_save_failed), model.message.value)
        assertTrue(setter.armed.isEmpty())
        store.failSaves = false
        assertNull(model.set("d1", "2026-12-25", 0))
        assertNull(model.message.value)
    }

    @Test fun wipe_cancels_every_alarm_and_deletes_the_rows_the_book_and_the_setting() {
        prefs.showItemNames = true
        model.set("d1", "2026-12-25", 0)
        model.set("c1", "2027-08-31", 0)
        assertEquals(2, setter.armed.size)
        assertTrue(model.wipe())
        assertTrue(setter.armed.isEmpty())
        assertTrue(store.rows.isEmpty())
        assertFalse(File(dir, "reminder-alarms.json").exists())
        assertFalse(prefs.showItemNames)
        assertTrue(model.wipe()) // erasing again is safe
    }

    @Test fun after_a_restart_the_book_arms_the_same_alarms_without_the_vault() {
        model.set("d1", "2026-12-25", 0)
        model.set("c1", "2027-08-31", 0)
        val before = setter.armed.toMap()
        setter.armed.clear() // the system forgot them
        ReminderAlarms(File(dir, "reminder-alarms.json"), setter, { now }, { utc }).rearm()
        assertEquals(before, setter.armed)
    }

    @Test fun an_alarm_missed_while_the_phone_was_off_comes_a_few_seconds_after_it_is_back() {
        model.set("d1", "2026-11-03", 0)
        setter.armed.clear()
        now = millis("2026-11-05", 7)
        alarms.rearm()
        assertEquals(now + ReminderAlarms.SOON_MILLIS, setter.armed["r1"])
    }

    @Test fun the_nine_oclock_follows_a_changed_time_zone() {
        model.set("d1", "2026-12-25", 0)
        val tokyo = ZoneId.of("Asia/Tokyo")
        setter.armed.clear()
        ReminderAlarms(File(dir, "reminder-alarms.json"), setter, { now }, { tokyo }).rearm()
        assertEquals(LocalDate.parse("2026-12-25").atTime(9, 0).atZone(tokyo).toInstant().toEpochMilli(), setter.armed["r1"])
    }

    @Test fun a_fired_alarm_is_forgotten_and_an_unknown_or_cancelled_one_is_not_found() {
        model.set("d1", "2026-12-25", 0)
        assertNotNull(alarms.entry("r1"))
        alarms.fired("r1")
        assertNull(alarms.entry("r1"))
        assertTrue(setter.armed.isEmpty())
        assertNull(alarms.entry("zzz"))
    }

    @Test fun a_damaged_alarm_book_reads_as_empty() {
        File(dir, "reminder-alarms.json").writeText("{not json")
        assertTrue(alarms.entries().isEmpty())
        alarms.rearm() // no crash
    }
}
