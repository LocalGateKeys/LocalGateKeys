package app.localgatekeys.android.backup

import app.localgatekeys.android.generator.PassphraseWordlist
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.core.backup.BackupHeader
import app.localgatekeys.core.backup.PhoneBackup
import app.localgatekeys.core.backup.PhoneBackupException
import app.localgatekeys.core.backup.PhoneBackupFormat
import app.localgatekeys.core.password.StrengthEstimator
import app.localgatekeys.core.primitives.UnixClock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

/**
 * Settings › Backup copy. The restore lines and statuses are the desktop's (`app/phone_backup_web.py`); the rest is
 * new Android copy in the same style (the iPhone has no backup screens yet).
 */
object BackupText {
    const val SECTION = "Backup"
    const val EXPORT = "Export backup…"
    const val RESTORE = "Restore from a backup…"
    const val FOOTER =
        "A backup file holds this phone's items, protected by a password you choose. Without the password the file cannot be opened."

    /** The fresh unlock before an export (the prompt's title). */
    const val EXPORT_REASON = "Export a backup"
    const val EXPORT_TITLE = "Export backup"
    const val EXPORT_HINT =
        "Choose a password for the backup file. You need it to restore the file on a phone or PC; it cannot be recovered."
    const val PASSWORD = "Backup password"
    const val CONFIRM = "Repeat the password"
    const val EXPORT_BUTTON = "Export"
    const val WORKING = "Encrypting the backup…"
    const val SAVED = "Backup saved."
    const val EXPORT_FAILED = "The backup could not be made. Try again."
    const val WRITE_FAILED = "The backup file could not be saved. Try again."

    const val RESTORE_TITLE = "Restore from a backup"
    const val CHOOSE = "Choose backup file…"
    const val CHOOSE_HINT = "Choose a LocalGateKeys backup file (.lgkm). Restoring never overwrites a newer version of an item."
    const val ENTER_PASSWORD = "Enter the backup password."
    const val OPEN_BUTTON = "Preview"
    const val RESTORE_BUTTON = "Restore"
    const val OPENING = "Opening the backup…"
    const val READ_FAILED = "That file could not be read."
    const val UNREADABLE = "The vault could not be read for the restore."

    // Desktop wording, verbatim.
    const val TOO_MANY_ATTEMPTS = "Too many attempts. Try again in 30 seconds."
    const val PREVIEW_READY = "Preview is ready. Review it, then restore."
    const val DONE = "Phone backup restored."

    fun fromLine(header: BackupHeader): String =
        "Made on ${if (header.platform == "ios") "an iPhone" else "an Android phone"} on ${date(header.createdAt, ZoneOffset.UTC)}."

    /** `LocalGateKeys-Backup-YYYY-MM-DD.lgkm` for the day [epochSeconds] falls on in [zone]. */
    fun fileName(epochSeconds: Long, zone: ZoneId = ZoneId.systemDefault()): String = "LocalGateKeys-Backup-${date(epochSeconds, zone)}.lgkm"

    private fun date(epochSeconds: Long, zone: ZoneId): String =
        DateTimeFormatter.ofPattern("uuuu-MM-dd", Locale.ROOT).format(Instant.ofEpochSecond(epochSeconds).atZone(zone))

    private fun skipped(count: Int, verb: String) = "$count items this version cannot read $verb skipped"
    private fun deletedLine(count: Int) = "$count items deleted (deleted before the backup was made)"
    private fun heldBackLine(count: Int) = "$count items held back by the free plan's ${ItemLimit.FREE_ITEMS}-item limit"

    /**
     * The desktop's preview lines. Its deletion line ("moved to the trash (deleted on the phone)") is Android copy here,
     * because this phone has no trash: "deleted (deleted before the backup was made)".
     */
    fun planLines(p: RestorePlan): List<String> = buildList {
        add("${p.new} new items"); add("${p.updated} items updated from the backup"); add("${p.unchanged} already up to date")
        if (p.deleted > 0) add(deletedLine(p.deleted))
        if (p.skipped > 0) add(skipped(p.skipped, "will be"))
        if (p.heldBack > 0) add(heldBackLine(p.heldBack))
    }

    fun reportLines(r: RestoreReport): List<String> = if (r.failure != null) {
        emptyList()
    } else {
        buildList {
            add("${r.new} new items"); add("${r.updated} items updated from the backup")
            if (r.deleted > 0) add(deletedLine(r.deleted))
            if (r.heldBack > 0) add(heldBackLine(r.heldBack))
        }
    }

    /** The desktop's result status, with its fatal reasons. */
    fun reportStatus(r: RestoreReport): String {
        r.failure?.let { return "Nothing was restored: ${FATAL[it] ?: "the vault could not be updated"}." }
        val changed = r.new > 0 || r.updated > 0 || r.deleted > 0
        if (r.skipped > 0 && !changed && !r.licenseRestored) return "Nothing was restored: ${skipped(r.skipped, "were")}."
        var status = DONE
        if (r.skipped > 0) status += " ${skipped(r.skipped, "were")}."
        if (r.licenseRestored) {
            status += " Your Pro licence was restored."
            if (r.heldBack > 0) status += " Restore again to bring back the ${r.heldBack} held-back items."
        }
        return status
    }

    private val FATAL = mapOf("busy" to "the vault changed while restoring. Try again")
}

/**
 * The backup password gate: the desktop's sync-password rule (`sync_view.check_sync_password`, Ruling 26): at least 12
 * characters, a desktop strength score of 3 ("Strong") or more ([StrengthEstimator], the port of
 * `password_tools.estimate_strength`), and both entries equal. Messages and labels are the desktop's.
 */
object BackupPasswordCheck {
    const val MIN_LENGTH = 12
    const val MIN_SCORE = 3

    /** Desktop `PasswordCheck`. [label] is the desktop's strength label for [score]. */
    data class Result(val ok: Boolean, val score: Int, val label: String, val message: String)

    /** The desktop's dictionary: the packaged passphrase list plus the built-in list (`_word_set()`), read once. */
    val estimator: StrengthEstimator by lazy {
        val packaged = PassphraseWordlist.packaged
        StrengthEstimator(packaged.toSet() + PassphraseWordlist.FALLBACK, packaged.size)
    }

    fun check(password: String, confirm: String, strength: StrengthEstimator = estimator): Result {
        val score = if (password.isEmpty()) 0 else strength.estimate(password).score
        val label = StrengthEstimator.LABELS[score.coerceIn(0, StrengthEstimator.LABELS.lastIndex)]
        return when {
            password.codePointCount(0, password.length) < MIN_LENGTH -> Result(false, score, label, "Use at least $MIN_LENGTH characters.")
            score < MIN_SCORE -> Result(false, score, label, "Too easy to guess. Add more words or characters.")
            password != confirm -> Result(false, score, label, "The two passwords do not match.")
            else -> Result(true, score, label, "Good.")
        }
    }

    /** The problem to show, or null when the password may be used. */
    fun problem(password: String, confirm: String, strength: StrengthEstimator = estimator): String? =
        check(password, confirm, strength).let { if (it.ok) null else it.message }
}

/** Five wrong backup passwords, then 30 s before the next try (desktop `MAX_WRONG` / `LOCKOUT_SECONDS`). Process-wide. */
class RestoreAttempts(private val clock: UnixClock) {
    private var wrong = 0
    private var blockedUntil = Long.MIN_VALUE

    @Synchronized fun blocked(): Boolean = clock.now < blockedUntil

    @Synchronized fun wrongPassword() {
        wrong += 1
        if (wrong >= MAX_WRONG) {
            wrong = 0
            blockedUntil = clock.now + LOCKOUT_SECONDS
        }
    }

    @Synchronized fun succeeded() {
        wrong = 0
    }

    companion object {
        const val MAX_WRONG = 5
        const val LOCKOUT_SECONDS = 30L
    }
}

/**
 * Export backup's form: the password twice, checked, then the encrypted file ([make]); the screen then hands the bytes
 * to the system "save as" picker. The passwords live only here, in memory, and are cleared once used; toString shows
 * neither them nor the file.
 */
class ExportFlow(
    private val export: (String) -> ByteArray,
    private val io: CoroutineContext,
    /** The password gate (seam): the problem to show, or null. */
    private val check: (String, String) -> String? = { p, c -> BackupPasswordCheck.problem(p, c) },
) {
    private val _password = MutableStateFlow("")
    val password: StateFlow<String> = _password.asStateFlow()
    private val _confirm = MutableStateFlow("")
    val confirm: StateFlow<String> = _confirm.asStateFlow()
    private val _working = MutableStateFlow(false)
    val working: StateFlow<Boolean> = _working.asStateFlow()
    private val _message = MutableStateFlow<String?>(null)
    /** The check's or the export's problem, or the saved confirmation. */
    val message: StateFlow<String?> = _message.asStateFlow()
    private val _saved = MutableStateFlow(false)
    val saved: StateFlow<Boolean> = _saved.asStateFlow()

    fun updatePassword(text: String) { _password.value = text; _message.value = null }
    fun updateConfirm(text: String) { _confirm.value = text; _message.value = null }

    /** The desktop's strength label for the typed password ("Strength: Fair"); null while empty. */
    fun strengthText(): String? = _password.value.takeIf { it.isNotEmpty() }?.let { "Strength: ${BackupPasswordCheck.check(it, it).label}" }

    /** The encrypted file, or null (the problem is in [message]). Runs the export (Argon2id) on [io]. */
    suspend fun make(): ByteArray? {
        if (_working.value) return null
        val pw = _password.value
        val confirm = _confirm.value
        _working.value = true
        return try {
            // The strength estimate can take a moment on a long password: it runs on [io] too, never on Main.
            val problem = withContext(io) { check(pw, confirm) }
            if (problem != null) {
                _message.value = problem
                null
            } else {
                withContext(io) { export(pw) }.also { clear() }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            _message.value = BackupText.EXPORT_FAILED
            null
        } finally {
            _working.value = false
        }
    }

    /** The picker wrote the file ([ok]) or could not. */
    fun written(ok: Boolean) {
        _saved.value = ok
        _message.value = if (ok) BackupText.SAVED else BackupText.WRITE_FAILED
    }

    private fun clear() { _password.value = ""; _confirm.value = "" }

    override fun toString(): String = "ExportFlow(working=${_working.value}, saved=${_saved.value})"
}

/**
 * Restore from a backup: a chosen file, its password ([open]: five wrong ones, then 30 s), the preview, then [restore].
 * The password lives only here and is cleared once tried; the decrypted states live only in the plan, which this flow
 * drops on restore (and which goes away with the screen when the vault locks). toString shows none of them.
 * [restorer] is asked at each step for the open vault's [PhoneRestore] (its gated store).
 */
class RestoreFlow(
    private val attempts: RestoreAttempts,
    private val restorer: () -> PhoneRestore,
    private val io: CoroutineContext,
    private val read: (ByteArray, String) -> PhoneBackup = PhoneBackupFormat::read,
) {
    enum class Step { CHOOSE, PASSWORD, PREVIEW, DONE }

    private val _step = MutableStateFlow(Step.CHOOSE)
    val step: StateFlow<Step> = _step.asStateFlow()
    private val _password = MutableStateFlow("")
    val password: StateFlow<String> = _password.asStateFlow()
    private val _working = MutableStateFlow(false)
    val working: StateFlow<Boolean> = _working.asStateFlow()
    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()
    private val _lines = MutableStateFlow<List<String>>(emptyList())
    val lines: StateFlow<List<String>> = _lines.asStateFlow()
    private val _status = MutableStateFlow<String?>(null)
    val status: StateFlow<String?> = _status.asStateFlow()
    private val _from = MutableStateFlow<String?>(null)
    /** "Made on an Android phone on 2026-10-24." once a file is chosen. */
    val from: StateFlow<String?> = _from.asStateFlow()

    private var file: ByteArray? = null
    private var plan: RestorePlan? = null

    fun updatePassword(text: String) { _password.value = text; _error.value = null }

    /** A file the picker returned (already read with the size limit), or null when it could not be read. */
    fun chose(bytes: ByteArray?) {
        _error.value = null; plan = null; _lines.value = emptyList(); _status.value = null
        if (bytes == null) {
            _error.value = BackupText.READ_FAILED
            return
        }
        val header = try {
            PhoneBackupFormat.inspect(bytes)
        } catch (e: PhoneBackupException) {
            _error.value = e.message
            return
        }
        file = bytes
        _from.value = BackupText.fromLine(header)
        _step.value = Step.PASSWORD
    }

    /** Decrypts with the typed password and plans the restore (nothing is written). */
    suspend fun open() {
        val bytes = file ?: return
        if (_working.value) return
        if (_password.value.isEmpty()) {
            _error.value = BackupText.ENTER_PASSWORD
            return
        }
        if (attempts.blocked()) {
            _error.value = BackupText.TOO_MANY_ATTEMPTS
            return
        }
        val pw = _password.value
        _password.value = ""
        _working.value = true
        try {
            val backup = try {
                withContext(io) { read(bytes, pw) }
            } catch (e: PhoneBackupException) {
                if (e.reason == "wrong-password-or-damaged") attempts.wrongPassword()
                _error.value = e.message
                return
            }
            attempts.succeeded()
            val p = withContext(io) { restorer().plan(backup) }
            plan = p
            _lines.value = BackupText.planLines(p)
            _status.value = BackupText.PREVIEW_READY
            _step.value = Step.PREVIEW
        } catch (e: CancellationException) {
            throw e
        } catch (e: PhoneRestoreException) {
            _error.value = e.message
        } catch (e: Exception) {
            _error.value = BackupText.UNREADABLE
        } finally {
            _working.value = false
        }
    }

    /** Restores the previewed plan; true when something was written (the caller reloads and syncs). */
    suspend fun restore(): Boolean {
        val p = plan ?: return false
        if (_working.value) return false
        _working.value = true
        try {
            val report = withContext(io) { restorer().restore(p) }
            plan = null; file = null
            _lines.value = BackupText.reportLines(report)
            _status.value = BackupText.reportStatus(report)
            _step.value = Step.DONE
            return report.failure == null && (report.new > 0 || report.updated > 0 || report.deleted > 0 || report.licenseRestored)
        } catch (e: CancellationException) {
            throw e
        } catch (e: PhoneRestoreException) {
            _error.value = e.message
            return false
        } catch (e: Exception) {
            _error.value = BackupText.UNREADABLE
            return false
        } finally {
            _working.value = false
        }
    }

    override fun toString(): String = "RestoreFlow(step=${_step.value}, working=${_working.value})"
}
