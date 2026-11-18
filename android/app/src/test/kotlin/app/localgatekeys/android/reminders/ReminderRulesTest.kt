package app.localgatekeys.android.reminders

import app.localgatekeys.android.trash.InMemoryLocalData
import app.localgatekeys.android.trash.LocalData
import java.io.File
import java.io.IOException
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Day arithmetic, the notification plan and the stored rows (the iPhone `ReminderDays` / `PhoneReminders.plan` rules). */
class ReminderRulesTest {
    private fun day(s: String) = ReminderDays.dayNumber(s)!!
    private fun rem(
        id: String = "r1", item: String = "i1", due: String = "2026-12-25", lead: Int = 0,
        status: Reminder.Status = Reminder.Status.ACTIVE, snooze: String = "", notified: String = "",
    ) = Reminder(id, item, due, lead, status, snooze, notified)

    @Test fun day_numbers_round_trip_and_reject_bad_dates() {
        assertEquals(0L, day("1970-01-01"))
        assertEquals(20_392L, day("2025-10-31"))
        assertEquals("2026-02-28", ReminderDays.text(day("2026-02-28")))
        for (bad in listOf("", "2026-02-30", "2026-13-01", "2026-1-1", "26-01-01", "2026/01/01", "2026-01-01 ", "x")) {
            assertNull(bad, ReminderDays.dayNumber(bad))
        }
        assertEquals("2028-02-29", ReminderDays.text(day("2028-02-28") + 1))
    }

    @Test fun effective_day_is_due_minus_lead_and_a_snooze_never_moves_it_earlier() {
        assertEquals(day("2026-12-18"), ReminderDays.effectiveDay(rem(lead = 7)))
        assertEquals(day("2026-12-25"), ReminderDays.effectiveDay(rem()))
        val snoozed = rem(lead = 7, status = Reminder.Status.SNOOZED, snooze = "2026-12-20")
        assertEquals(day("2026-12-20"), ReminderDays.effectiveDay(snoozed))
        // A snooze date before the effective day changes nothing.
        assertEquals(day("2026-12-18"), ReminderDays.effectiveDay(snoozed.copy(snoozeUntil = "2026-12-01")))
        assertNull(ReminderDays.effectiveDay(rem(due = "nope")))
    }

    @Test fun a_cards_expiry_month_ends_on_its_last_day() {
        assertEquals("2027-08-31", ReminderDays.cardExpiryDay("08/27"))
        assertEquals("2027-08-31", ReminderDays.cardExpiryDay("08 / 2027"))
        assertEquals("2028-02-29", ReminderDays.cardExpiryDay("02/28"))
        assertEquals("2027-02-28", ReminderDays.cardExpiryDay("02/27"))
        for (bad in listOf("", "13/27", "00/27", "8/7", "08/270", "08-27", "ab/cd", "08/27/1", "08/-7")) {
            assertNull(bad, ReminderDays.cardExpiryDay(bad))
        }
    }

    private val names = mapOf("i1" to "Visa", "i2" to "Passport")
    private fun plan(rs: List<Reminder>, today: String, pastNine: Boolean = false, showNames: Boolean = false) =
        ReminderPlanner.plan(rs, names, day(today), pastNine, showNames)

    @Test fun a_future_reminder_is_planned_at_nine_on_its_effective_day() {
        val p = plan(listOf(rem(lead = 7)), "2026-11-01").single()
        assertEquals("2026-12-18", p.day)
        assertNull(p.name)
    }

    @Test fun today_before_nine_waits_for_nine_and_after_nine_comes_soon_once() {
        val due = rem(due = "2026-11-01")
        assertEquals("2026-11-01", plan(listOf(due), "2026-11-01", pastNine = false).single().day)
        assertNull(plan(listOf(due), "2026-11-01", pastNine = true).single().day)
        // Already notified today: nothing more; tomorrow it is overdue and silent.
        assertTrue(plan(listOf(due.copy(lastNotified = "2026-11-01")), "2026-11-01", pastNine = true).isEmpty())
        assertTrue(plan(listOf(due), "2026-11-02", pastNine = false).isEmpty())
    }

    @Test fun dismissed_overdue_unknown_item_and_bad_date_reminders_are_not_planned() {
        val rs = listOf(
            rem("a", "i1", status = Reminder.Status.DISMISSED),
            rem("b", "i1", due = "2026-10-01"),
            rem("c", "gone"),
            rem("d", "i1", due = "bad"),
        )
        assertTrue(plan(rs, "2026-11-01").isEmpty())
    }

    @Test fun a_snoozed_reminder_is_planned_for_its_snooze_day() {
        val p = plan(listOf(rem(due = "2026-11-01", status = Reminder.Status.SNOOZED, snooze = "2026-11-02")), "2026-11-01", pastNine = true).single()
        assertEquals("2026-11-02", p.day)
    }

    @Test fun the_item_name_goes_into_a_notification_only_when_names_are_on() {
        assertNull(plan(listOf(rem()), "2026-11-01", showNames = false).single().name)
        assertEquals("Visa", plan(listOf(rem()), "2026-11-01", showNames = true).single().name)
        // An empty name stays anonymous.
        val blank = ReminderPlanner.plan(listOf(rem()), mapOf("i1" to ""), day("2026-11-01"), false, true)
        assertNull(blank.single().name)
    }

    @Test fun the_old_plain_row_file_still_reads_and_damaged_text_reads_as_nothing() {
        val old = """{"v":1,"reminders":[{"id":"a","item":"i1","due":"2026-12-25","lead":30,"status":"active","snooze":"","notified":""},
            {"id":"b","item":"i2","due":"2027-01-31","lead":7,"status":"snoozed","snooze":"2027-01-02","notified":"2027-01-01"}]}"""
        assertEquals(
            listOf(rem("a", "i1", "2026-12-25", 30), rem("b", "i2", "2027-01-31", 7, Reminder.Status.SNOOZED, "2027-01-02", "2027-01-01")),
            LegacyReminderFile.decode(old.toByteArray()),
        )
        assertNull(LegacyReminderFile.decode("not json".toByteArray()))
        assertNull(LegacyReminderFile.decode("{}".toByteArray()))
        // Rows without an id, an item or a real date are dropped, a lead is clamped.
        val odd = """{"v":1,"reminders":[{"id":"","item":"i","due":"2026-12-25"},{"id":"x","item":"i","due":"2026-99-25"},
            {"id":"y","item":"i","due":"2026-12-25","lead":999999,"status":"zzz"}]}"""
        val got = LegacyReminderFile.decode(odd.toByteArray())!!
        assertEquals(1, got.size)
        assertEquals(Reminder.MAX_LEAD_DAYS, got[0].leadDays)
        assertEquals(Reminder.Status.ACTIVE, got[0].status)
    }

    @Test fun the_rows_live_in_the_local_data_and_share_its_lock_with_recently_deleted() {
        val local = InMemoryLocalData()
        val store = LocalReminderStore(local)
        assertTrue(store.load().isEmpty())
        store.save(listOf(rem("a")))
        store.update { it + rem("b") }
        assertEquals(listOf("a", "b"), local.localData!!.reminders.map { it.id })
        assertEquals(listOf("a", "b"), LocalReminderStore(local).load().map { it.id })
        local.failSaves = true
        assertThrows(IOException::class.java) { store.save(emptyList()) }
        assertFalse(store.wipe())
        local.failSaves = false
        // A row the local data refuses (two rows with one id) is a failed save, not a crash.
        assertThrows(IOException::class.java) { store.save(listOf(rem("a"), rem("a"))) }
        assertEquals(2, store.load().size)
        assertTrue(store.wipe())
        assertTrue(store.load().isEmpty())
        assertTrue(store.wipe()) // erasing again is safe
    }

    @Test fun the_old_plain_file_moves_into_the_local_data_once_and_is_deleted() {
        val dir = Files.createTempDirectory("lgk-rem").toFile()
        try {
            val file = File(dir, "reminders.json")
            val local = InMemoryLocalData()
            val store = LocalReminderStore(local)
            store.save(listOf(rem("a", item = "keep")))
            file.writeText("""{"v":1,"reminders":[{"id":"a","item":"old","due":"2026-12-25"},{"id":"b","item":"i2","due":"2027-01-31","lead":7}]}""")
            assertTrue(LegacyReminderFile.migrate(file, store))
            assertFalse(file.exists())
            assertEquals(listOf("a" to "keep", "b" to "i2"), store.load().map { it.id to it.itemId })
            // Unreadable: nothing to carry over, the file goes anyway.
            file.writeText("garbage")
            assertTrue(LegacyReminderFile.migrate(file, store))
            assertFalse(file.exists())
            // Rows that cannot be saved: the file stays for the next unlock.
            file.writeText("""{"v":1,"reminders":[{"id":"c","item":"i3","due":"2027-01-31"}]}""")
            local.failSaves = true
            assertFalse(LegacyReminderFile.migrate(file, store))
            assertTrue(file.exists())
            assertTrue(LegacyReminderFile.migrate(File(dir, "missing.json"), store))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun the_stored_rows_hold_no_title_and_no_secret() {
        val text = String(LocalData.encode(LocalData(reminders = listOf(rem()))))
        val reminder = text.substringAfter("\"reminders\":").substringBefore("]")
        assertEquals(
            setOf("id", "item_id", "due_date", "lead_days", "status", "snooze_until", "last_notified"),
            Regex("\"(\\w+)\":").findAll(reminder).map { it.groupValues[1] }.toSet(),
        )
    }
}
