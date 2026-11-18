package app.localgatekeys.core.backup

import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** A computer's full backup checked on the phone (restore test), against the Windows v2 and v3 fixtures. */
class ComputerBackupTest {
    private val expected = Vectors.json(Vectors.backup("v2/expected.json")).obj().fields
    private val backupPassword = (expected.getValue("backup_password") as app.localgatekeys.core.json.JsonValue.Str).v
    private val master = (expected.getValue("master_password") as app.localgatekeys.core.json.JsonValue.Str).v

    @Test
    fun v2AndV3OpenWithBothPasswordsAndCountTheSameItems() {
        val v2 = ComputerBackup.check(Vectors.backup("v2/full.lgkfull").readBytes(), backupPassword, master)
        val v3 = ComputerBackup.check(Vectors.backup("v3/full.lgkfull").readBytes(), backupPassword, master)
        assertTrue(v2.items > 0)
        assertEquals(v2.items, v3.items)
        assertTrue(v3.createdAt > 0)
    }

    @Test
    fun aMacV3BackupOpensToo() {
        val mac = ComputerBackup.check(Vectors.backup("v3/from_mac_v3.lgkfull").readBytes(), backupPassword, master)
        assertTrue(mac.items >= 0)
    }

    @Test
    fun wrongPasswordsAreReportedApart() {
        for (name in listOf("v2/full.lgkfull", "v3/full.lgkfull")) {
            val data = Vectors.backup(name).readBytes()
            assertFailsWith<ComputerBackup.WrongBackupPassword> {
                ComputerBackup.check(data, "not the backup password", master)
            }
            assertFailsWith<ComputerBackup.WrongMasterPassword> {
                ComputerBackup.check(data, backupPassword, "not the master password")
            }
        }
    }

    @Test
    fun aModifiedMemberIsRefused() {
        val data = Vectors.backup("v2/full.lgkfull").readBytes()
        data[data.size / 2] = (data[data.size / 2].toInt() xor 1).toByte()
        assertFailsWith<Exception> { ComputerBackup.check(data, backupPassword, master) }
    }

    @Test
    fun phoneBackupsAreNotComputerBackups() {
        assertTrue(ComputerBackup.looksLikeComputerBackup(Vectors.backup("v2/full.lgkfull").readBytes()))
        assertFalse(ComputerBackup.looksLikeComputerBackup(Vectors.backup("backup.lgkm").readBytes()))
        assertFailsWith<ComputerBackup.Unreadable> {
            ComputerBackup.check(Vectors.backup("backup.lgkm").readBytes(), backupPassword, master)
        }
    }
}
