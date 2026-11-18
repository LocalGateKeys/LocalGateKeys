package app.localgatekeys.android.trash

import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.tempDir
import app.localgatekeys.core.json.JsonValue
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PhoneLocalDataTest {
    private val key = ByteArray(32) { (it + 1).toByte() }
    private val secret = "Maple-Orbit-7731"
    private val record = JsonValue.Obj(mapOf("id" to JsonValue.Str("n1"), "kind" to JsonValue.Str("note"), "title" to JsonValue.Str("Bank PIN $secret")))

    private fun open(dir: File, k: ByteArray = key) = PhoneLocalData(dir, k, CountingRandom(), now = { 1_800_000_000 }, dirSync = {})

    @Test fun a_new_vault_starts_empty_and_writes_nothing() {
        val dir = tempDir("local")
        val l = open(dir)
        assertEquals(LocalData.EMPTY, l.localData)
        assertFalse(l.file.exists())
        assertFalse(l.wasReset)
    }

    @Test fun the_file_is_sealed_and_reads_back_after_the_next_unlock() {
        val dir = tempDir("local")
        val l = open(dir)
        val d = LocalData(trash = listOf(LocalData.TrashRow.of(record, 5)))
        l.commitLocalData(d)
        assertEquals(File(dir, "local-data.bin"), l.file)
        val bytes = l.file.readBytes()
        assertEquals(1, bytes[0].toInt())
        val text = String(bytes, Charsets.ISO_8859_1)
        assertFalse("no plaintext on disk", text.contains(secret) || text.contains("trash") || text.contains("Bank"))
        assertEquals(d, open(dir).localData)
        // No temp file is left next to it.
        assertEquals(listOf("local-data.bin"), dir.list()!!.sorted())
    }

    @Test fun reminder_rows_are_sealed_with_the_rest_and_read_back() {
        val dir = tempDir("local")
        val rows = listOf(app.localgatekeys.android.reminders.Reminder("rem-1", "item-1", "2031-05-17", 14))
        open(dir).commitLocalData(LocalData(reminders = rows))
        val text = String(File(dir, "local-data.bin").readBytes(), Charsets.ISO_8859_1)
        assertFalse("no plaintext on disk", text.contains("2031-05-17") || text.contains("item-1") || text.contains("due_date"))
        assertEquals(rows, open(dir).localData!!.reminders)
    }

    @Test fun a_file_sealed_with_another_key_is_set_aside_and_starts_empty() {
        val dir = tempDir("local")
        open(dir).commitLocalData(LocalData(trash = listOf(LocalData.TrashRow.of(record, 5))))
        val other = open(dir, ByteArray(32) { 9 })
        assertEquals(LocalData.EMPTY, other.localData)
        assertTrue(other.wasReset)
        assertFalse(other.file.exists())
        assertTrue(dir.list()!!.any { it.startsWith(PhoneLocalData.BAD_PREFIX) })
        // It saves again under its own key.
        other.commitLocalData(LocalData(preferences = LocalData.Preferences(trashRetentionDays = 7)))
        assertEquals(7, open(dir, ByteArray(32) { 9 }).localData!!.preferences.trashRetentionDays)
    }

    @Test fun travel_mode_is_read_from_the_file_and_fails_closed_without_touching_it() {
        val dir = tempDir("local")
        val off = app.localgatekeys.core.sync.TravelMode.Setting.OFF
        assertEquals("no file yet: never set", off, PhoneLocalData.readTravelMode(dir, key))
        val on = app.localgatekeys.core.sync.TravelMode.Setting(true, emptyList(), listOf("Work"), 9)
        open(dir).commitLocalData(LocalData().withTravelMode(on))
        assertEquals(on, PhoneLocalData.readTravelMode(dir, key))
        // Another key, a zeroed key or damaged bytes: unreadable is null (callers hide everything), and the file stays.
        assertNull(PhoneLocalData.readTravelMode(dir, ByteArray(32) { 9 }))
        assertNull(PhoneLocalData.readTravelMode(dir, ByteArray(32)))
        File(dir, "local-data.bin").writeBytes(byteArrayOf(1, 2, 3))
        assertNull(PhoneLocalData.readTravelMode(dir, key))
        assertEquals(listOf("local-data.bin"), dir.list()!!.sorted())
    }

    @Test fun damaged_bytes_are_set_aside() {
        val dir = tempDir("local")
        File(dir, "local-data.bin").writeBytes(byteArrayOf(1, 2, 3))
        val l = open(dir)
        assertEquals(LocalData.EMPTY, l.localData)
        assertTrue(l.wasReset)
    }

    @Test fun after_a_lock_zeroes_the_key_nothing_is_written() {
        val dir = tempDir("local")
        val k = key.copyOf()
        val l = open(dir, k)
        k.fill(0)
        assertThrows(Exception::class.java) { l.commitLocalData(LocalData(trash = listOf(LocalData.TrashRow.of(record, 5)))) }
        assertFalse(l.file.exists())
        // Opened after the lock: nothing is read either.
        File(dir, "local-data.bin").writeBytes(ByteArray(64))
        assertNull(open(dir, ByteArray(32)).localData)
    }

    @Test fun an_invalid_change_is_refused_and_the_old_data_stays() {
        val dir = tempDir("local")
        val l = open(dir)
        l.commitLocalData(LocalData(trash = listOf(LocalData.TrashRow.of(record, 5))))
        assertThrows(LocalDataException::class.java) { l.commitLocalData(LocalData(preferences = LocalData.Preferences(trashRetentionDays = 0))) }
        assertEquals(1, l.localData!!.trash.size)
        assertEquals(1, open(dir).localData!!.trash.size)
    }
}
