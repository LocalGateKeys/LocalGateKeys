package app.localgatekeys.android.backup

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.core.backup.PhoneBackupFormat
import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Desktop `restore_test.py` on the phone: scratch copy, one open, item count, scratch always removed. */
class RestoreTestTest {
    private val now = 1_800_000_000L
    private val created = 1_799_900_000L
    private val password = "correct horse battery staple"
    private val root: File = Files.createTempDirectory("lgk-restore-test").toFile().also { it.deleteOnExit() }
    private val scratch = File(root, "restore-test")

    private fun backupFile(): File {
        val states = listOf(
            live(noteRecord(noteId(1), "Secret title one", 1_799_000_001), mapOf(OTHER_PHONE to 1L)),
            live(noteRecord(noteId(2), "Secret title two", 1_799_000_002), mapOf(OTHER_PHONE to 2L)),
            tomb(noteId(3), mapOf(OTHER_PHONE to 3L), 1_799_000_003),
        )
        val bytes = PhoneBackupFormat.write(states, password, OTHER_PHONE, "android", "1.0.0", created, false, CountingRandom(), TEST_KDF)
        return File(root, "LocalGateKeys-Backup-2026-11-01.lgkm").also { it.writeBytes(bytes) }
    }

    private fun scratchEmpty() = (scratch.listFiles() ?: emptyArray()).isEmpty()

    @Test fun a_good_backup_passes_with_its_live_item_count_and_age() {
        val r = RestoreTest.run(backupFile(), password, scratch, now)
        assertTrue(r.ok)
        assertEquals(2, r.items)
        assertEquals(now - created, r.backupAgeSeconds)
        assertEquals("", r.reason)
        assertTrue("scratch removed", scratchEmpty())
    }

    @Test fun a_corrupted_backup_is_unreadable_and_the_scratch_is_removed() {
        val f = backupFile()
        f.writeBytes(f.readBytes().copyOfRange(0, 20))
        val r = RestoreTest.run(f, password, scratch, now)
        assertFalse(r.ok)
        assertEquals(RestoreTest.UNREADABLE, r.reason)
        assertTrue(scratchEmpty())
    }

    @Test fun a_wrong_password_is_old_password_and_the_scratch_is_removed() {
        val r = RestoreTest.run(backupFile(), "not the password", scratch, now)
        assertFalse(r.ok)
        assertEquals(RestoreTest.OLD_PASSWORD, r.reason)
        assertTrue(scratchEmpty())
    }

    @Test fun no_backup_and_newest_backup() {
        assertEquals(RestoreTest.NO_BACKUP, RestoreTest.run(null, password, scratch, now).reason)
        assertEquals(RestoreTest.NO_BACKUP, RestoreTest.newestBackup(File(root, "missing"))?.let { "x" } ?: RestoreTest.NO_BACKUP)
        val f = backupFile()
        assertEquals(f, RestoreTest.newestBackup(root))
    }

    @Test fun weekly_due_rule_and_round_trip_and_row_text() {
        val r = RestoreTest.Result(true, "p", 10, 2, "", now - 3 * 86400)
        assertFalse(RestoreTest.due(r, now, enabled = true))
        assertTrue(RestoreTest.due(r.copy(testedAt = now - RestoreTest.WEEK), now, enabled = true))
        assertTrue(RestoreTest.due(null, now, enabled = true))
        assertFalse(RestoreTest.due(null, now, enabled = false))
        assertEquals(r.copy(backupPath = ""), RestoreTest.decode(RestoreTest.encode(r)))
        val t = EnglishTxt()
        assertEquals("Last backup restore test: passed 3 days ago", RestoreTest.rowText(r, now, t))
        assertEquals("Last backup restore test: never run", RestoreTest.rowText(null, now, t))
        assertEquals(
            "Last backup restore test: failed: the password did not open it",
            RestoreTest.rowText(r.copy(ok = false, reason = RestoreTest.OLD_PASSWORD), now, t),
        )
        assertEquals("Last backup restore test: passed today", RestoreTest.rowText(r.copy(testedAt = now - 100), now, t))
        assertEquals("passed today", RestoreTest.valueText(r.copy(testedAt = now - 100), now, t))
        assertEquals("passed 3 days ago", RestoreTest.valueText(r, now, t))
        assertEquals("never run", RestoreTest.valueText(null, now, t))
        assertEquals("failed: the password did not open it", RestoreTest.valueText(r.copy(ok = false, reason = RestoreTest.OLD_PASSWORD), now, t))
    }

    /** A Windows full backup (`tests/vectors/backup/v2`): both passwords pass; either wrong one is old_password. */
    @Test fun a_computer_backup_needs_its_backup_and_master_passwords() {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null && !File(dir, "tests/vectors/backup/v2/full.lgkfull").isFile) dir = dir.parentFile
        val bytes = File(dir!!, "tests/vectors/backup/v2/full.lgkfull").readBytes()
        val backupPw = "fixture backup password 2026"
        val masterPw = "fixture master password 2026"
        val good = RestoreTest.run("full.lgkfull", bytes, backupPw, scratch, now, masterPassword = masterPw)
        assertTrue(good.ok)
        assertTrue(good.items > 0)
        assertEquals(RestoreTest.OLD_PASSWORD, RestoreTest.run("full.lgkfull", bytes, "not the backup password", scratch, now, masterPassword = masterPw).reason)
        assertEquals(RestoreTest.OLD_PASSWORD, RestoreTest.run("full.lgkfull", bytes, backupPw, scratch, now, masterPassword = "not the master").reason)
        assertEquals(RestoreTest.OLD_PASSWORD, RestoreTest.run("full.lgkfull", bytes, backupPw, scratch, now).reason)
    }
}
