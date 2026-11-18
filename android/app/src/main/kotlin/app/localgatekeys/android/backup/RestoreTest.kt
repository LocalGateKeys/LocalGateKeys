package app.localgatekeys.android.backup

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.backup.ComputerBackup
import app.localgatekeys.core.backup.PhoneBackup
import app.localgatekeys.core.backup.PhoneBackupException
import app.localgatekeys.core.backup.PhoneBackupFormat
import app.localgatekeys.core.json.JsonValue
import java.io.File
import java.util.UUID

/**
 * Backup restore test (desktop `restore_test.py` + `backup.restore_to_scratch`, sub-plan 12): the backup is copied
 * into a scratch folder `<scratchRoot>/<uuid>` under the app's private data dir, opened there once with the given
 * password, its items counted, and the scratch folder deleted again, always. The live vault is never touched. The
 * result holds no secret and no title.
 */
object RestoreTest {
    const val WEEK: Long = 7L * 24 * 3600
    const val UNREADABLE = "unreadable"
    const val OLD_PASSWORD = "old_password"
    const val NO_BACKUP = "no_backup"
    val REASONS = setOf(UNREADABLE, OLD_PASSWORD, NO_BACKUP)

    /** [backupAgeSeconds]: between the backup's creation and the test. [reason]: "" when [ok], else one of [REASONS]. */
    data class Result(
        val ok: Boolean,
        val backupPath: String,
        val backupAgeSeconds: Long,
        val items: Int,
        val reason: String,
        val testedAt: Long = 0,
    )

    /** The newest `.lgkm` / `.lgk` file in [dir], or null. */
    fun newestBackup(dir: File?): File? = dir?.listFiles { f -> f.isFile && (f.name.endsWith(".lgkm") || f.name.endsWith(".lgk")) }
        ?.maxByOrNull { it.lastModified() }

    /** Tests the backup file [backup] (null or missing: [NO_BACKUP]). */
    fun run(backup: File?, password: String, scratchRoot: File, now: Long, read: (ByteArray, String) -> PhoneBackup = PhoneBackupFormat::read): Result {
        if (backup == null || !backup.isFile) return Result(false, backup?.path ?: "", 0, 0, NO_BACKUP, now)
        val bytes = try { backup.readBytes() } catch (e: Exception) { return Result(false, backup.path, 0, 0, UNREADABLE, now) }
        return run(backup.path, bytes, password, scratchRoot, now, read)
    }

    /** Tests backup [bytes] named [source] (a picked document); null bytes: [NO_BACKUP]. */
    fun run(
        source: String, bytes: ByteArray?, password: String, scratchRoot: File, now: Long,
        read: (ByteArray, String) -> PhoneBackup = PhoneBackupFormat::read,
        masterPassword: String? = null,
    ): Result {
        if (bytes == null) return Result(false, source, 0, 0, NO_BACKUP, now)
        // A computer's full backup (.lgk/.lgkfull, a zip): its backup password, then that computer's master password.
        if (ComputerBackup.looksLikeComputerBackup(bytes)) return runComputer(source, bytes, password, masterPassword ?: "", now)
        val scratch = File(scratchRoot, UUID.randomUUID().toString())
        try {
            scratch.mkdirs()
            val copy = File(scratch, "backup.lgkm")
            copy.writeBytes(bytes)
            val backup = try {
                read(copy.readBytes(), password)
            } catch (e: PhoneBackupException) {
                return Result(false, source, 0, 0, if (e.reason == "wrong-password-or-damaged") OLD_PASSWORD else UNREADABLE, now)
            } catch (e: Exception) {
                return Result(false, source, 0, 0, UNREADABLE, now)
            }
            val items = backup.states.count { s ->
                !s.deleted && ((s.item as? JsonValue.Obj)?.fields?.get("ns") as? JsonValue.Str)?.v in CONTENT_NS
            }
            val created = backup.header.createdAt
            return Result(true, source, if (created > 0) maxOf(0, now - created) else 0, items, "", now)
        } catch (e: Exception) {
            return Result(false, source, 0, 0, UNREADABLE, now)
        } finally {
            scratch.deleteRecursively()
        }
    }

    /** A computer's full backup checked in memory (nothing written or kept): backup password, then master password. */
    fun runComputer(source: String, bytes: ByteArray, password: String, masterPassword: String, now: Long): Result = try {
        val checked = ComputerBackup.check(bytes, password, masterPassword)
        val age = if (checked.createdAt > 0) maxOf(0, now - checked.createdAt) else 0
        Result(true, source, age, checked.items, "", now)
    } catch (e: ComputerBackup.WrongBackupPassword) {
        Result(false, source, 0, 0, OLD_PASSWORD, now)
    } catch (e: ComputerBackup.WrongMasterPassword) {
        Result(false, source, 0, 0, OLD_PASSWORD, now)
    } catch (e: Exception) {
        Result(false, source, 0, 0, UNREADABLE, now)
    }

    /** Weekly: due when [enabled] and never run or the last run is a week old. */
    fun due(last: Result?, now: Long, enabled: Boolean): Boolean = enabled && (last == null || now - last.testedAt >= WEEK)

    /** One line for preferences (no secret, no title): `ok|age|items|reason|testedAt` (the path is not kept). */
    fun encode(r: Result): String = listOf(if (r.ok) "1" else "0", r.backupAgeSeconds, r.items, r.reason, r.testedAt).joinToString("|")

    fun decode(raw: String?): Result? {
        val p = raw?.split("|") ?: return null
        if (p.size != 5) return null
        val reason = p[3]
        if (reason.isNotEmpty() && reason !in REASONS) return null
        return try {
            Result(p[0] == "1", "", p[1].toLong(), p[2].toInt(), reason, p[4].toLong())
        } catch (e: NumberFormatException) {
            null
        }
    }

    /** "Last backup restore test: passed N days ago / failed: reason / never run". */
    fun rowText(result: Result?, now: Long, t: Txt): String = when {
        result == null -> t.s(R.string.restore_test_never)
        result.ok -> daysAgo(result, now).let { if (it == 0) t.s(R.string.restore_test_passed_today) else t.s(R.string.restore_test_passed, it) }
        else -> t.s(R.string.restore_test_failed, reasonText(result.reason, t))
    }

    /** The same result without the "Last backup restore test:" label, for the health report's value column. */
    fun valueText(result: Result?, now: Long, t: Txt): String = when {
        result == null -> t.s(R.string.restore_test_value_never)
        result.ok -> daysAgo(result, now).let { if (it == 0) t.s(R.string.restore_test_value_passed_today) else t.s(R.string.restore_test_value_passed, it) }
        else -> t.s(R.string.restore_test_value_failed, reasonText(result.reason, t))
    }

    private fun daysAgo(result: Result, now: Long): Int = maxOf(0L, (now - result.testedAt) / 86400).toInt()

    fun reasonText(reason: String, t: Txt): String = t.s(
        when (reason) {
            OLD_PASSWORD -> R.string.restore_test_reason_old_password
            NO_BACKUP -> R.string.restore_test_reason_no_backup
            else -> R.string.restore_test_reason_unreadable
        },
    )

    private val CONTENT_NS = setOf("entry", "item")
}
