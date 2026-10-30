package app.localgatekeys.android.backup

import app.localgatekeys.android.R
import app.localgatekeys.android.generator.PassphraseWordlist
import app.localgatekeys.android.i18n.Txt
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
 * Settings › Backup copy, resolved through [t]. The restore lines and statuses are the desktop's
 * (`app/phone_backup_web.py`); the rest is new Android copy in the same style (the iPhone has no backup screens yet).
 * Everything here is shown on screen only: nothing is written into a backup file ([fileName] is a fixed English name).
 */
class BackupText(private val t: Txt) {
    /** A failed backup read in the person's language, by the core's stable reason code (its English is for logs). */
    fun failure(reason: String): String = t.s(
        when (reason) {
            "not-a-backup" -> R.string.backup_failure_not_a_backup
            "unsupported-version" -> R.string.backup_failure_unsupported_version
            "bad-kdf" -> R.string.backup_failure_bad_kdf
            "wrong-password-or-damaged" -> R.string.backup_failure_wrong_password
            "bad-payload" -> R.string.backup_failure_bad_payload
            "too-large" -> R.string.backup_failure_too_large
            else -> R.string.backup_failure_other
        },
    )

    val section: String get() = t.s(R.string.backup_section)
    val export: String get() = t.s(R.string.backup_export)
    val restore: String get() = t.s(R.string.backup_restore)
    val footer: String get() = t.s(R.string.backup_footer)

    /** The fresh unlock before an export (the prompt's title). */
    val exportReason: String get() = t.s(R.string.backup_export_reason)
    val exportTitle: String get() = t.s(R.string.backup_export_title)
    val exportHint: String get() = t.s(R.string.backup_export_hint)
    val password: String get() = t.s(R.string.phone_backup_password)
    val confirm: String get() = t.s(R.string.backup_confirm)
    val exportButton: String get() = t.s(R.string.export_sheet_export)
    val working: String get() = t.s(R.string.backup_working)
    val saved: String get() = t.s(R.string.backup_saved)
    val exportFailed: String get() = t.s(R.string.backup_export_failed)
    val writeFailed: String get() = t.s(R.string.backup_write_failed)

    val restoreTitle: String get() = t.s(R.string.backup_restore_title)
    val choose: String get() = t.s(R.string.backup_choose)
    val chooseHint: String get() = t.s(R.string.backup_choose_hint)
    val enterPassword: String get() = t.s(R.string.backup_enter_password)
    val openButton: String get() = t.s(R.string.common_preview)
    val restoreButton: String get() = t.s(R.string.phone_backup_restore)
    val opening: String get() = t.s(R.string.backup_opening)
    val readFailed: String get() = t.s(R.string.backup_read_failed)
    val unreadable: String get() = t.s(R.string.backup_unreadable)

    // Desktop wording.
    val tooManyAttempts: String get() = t.s(R.string.phone_backup_web_too_many_attempts_try_again)
    val previewReady: String get() = t.s(R.string.phone_backup_web_preview_is_ready_review_it)
    val done: String get() = t.s(R.string.phone_backup_web_phone_backup_restored)

    /** Why a restore cannot go ahead ([PhoneRestoreException.reason]). */
    fun restoreError(reason: String): String = when (reason) {
        PhoneRestoreException.SAME_DEVICE -> t.s(R.string.backup_same_device)
        PhoneRestoreException.UNREADABLE -> unreadable
        else -> t.s(R.string.backup_vault_locked)
    }

    fun fromLine(header: BackupHeader): String =
        t.s(if (header.platform == "ios") R.string.backup_from_ios else R.string.backup_from_android, date(header.createdAt, ZoneOffset.UTC))

    private fun skipped(count: Int, willBe: Boolean) =
        t.plural(if (willBe) R.plurals.backup_skipped_will else R.plurals.backup_skipped_were, count, count)
    private fun deletedLine(count: Int) = t.plural(R.plurals.backup_deleted, count, count)
    private fun missingLine(count: Int, willBe: Boolean) =
        t.plural(if (willBe) R.plurals.backup_missing_will else R.plurals.backup_missing_were, count, count)

    /** Export: documents whose file is missing here or does not fit in one backup (160 MiB of files). */
    fun leftOutLine(count: Int) = t.plural(R.plurals.backup_left_out, count, count)

    private fun heldBackLine(count: Int) = t.plural(R.plurals.backup_held_back, count, count, ItemLimit.FREE_ITEMS)

    /** The text after a successful save, with the left-out files when there are any. */
    fun savedText(leftOut: Int): String = if (leftOut > 0) saved + " " + leftOutLine(leftOut) else saved

    /**
     * The desktop's preview lines. Its deletion line ("moved to the trash (deleted on the phone)") is Android copy here,
     * because this phone has no trash: "deleted (deleted before the backup was made)".
     */
    fun planLines(p: RestorePlan): List<String> = buildList {
        add(t.plural(R.plurals.backup_plan_new, p.new, p.new))
        add(t.plural(R.plurals.backup_plan_updated, p.updated, p.updated))
        add(t.plural(R.plurals.backup_already_up_to_date, p.unchanged, p.unchanged))
        if (p.deleted > 0) add(deletedLine(p.deleted))
        if (p.skipped > 0) add(skipped(p.skipped, willBe = true))
        if (p.filesFromBackup > 0) add(t.plural(R.plurals.backup_files_from_backup, p.filesFromBackup, p.filesFromBackup))
        if (p.filesMissing > 0) add(missingLine(p.filesMissing, willBe = true))
        if (p.heldBack > 0) add(heldBackLine(p.heldBack))
    }

    fun reportLines(r: RestoreReport): List<String> = if (r.failure != null) {
        emptyList()
    } else {
        buildList {
            add(t.plural(R.plurals.backup_plan_new, r.new, r.new))
            add(t.plural(R.plurals.backup_plan_updated, r.updated, r.updated))
            if (r.deleted > 0) add(deletedLine(r.deleted))
            if (r.files > 0) add(t.plural(R.plurals.backup_files_restored, r.files, r.files))
            if (r.filesRefused > 0) add(t.plural(R.plurals.backup_files_refused, r.filesRefused, r.filesRefused))
            if (r.filesMissing > 0) add(missingLine(r.filesMissing, willBe = false))
            if (r.heldBack > 0) add(heldBackLine(r.heldBack))
        }
    }

    private fun sentence(text: String) = t.s(R.string.backup_sentence, text)

    /** The desktop's result status, with its fatal reasons. */
    fun reportStatus(r: RestoreReport): String {
        r.failure?.let {
            val why = if (it == "busy") t.s(R.string.backup_fatal_busy) else t.s(R.string.backup_fatal_default)
            return t.s(R.string.backup_nothing_restored, why)
        }
        val changed = r.new > 0 || r.updated > 0 || r.deleted > 0
        if (r.skipped > 0 && !changed && !r.licenseRestored) return t.s(R.string.backup_nothing_restored, skipped(r.skipped, willBe = false))
        var status = done
        if (r.skipped > 0) status += " " + sentence(skipped(r.skipped, willBe = false))
        if (r.licenseRestored) {
            status += " " + t.s(R.string.phone_backup_web_your_pro_licence_was_restored)
            if (r.heldBack > 0) status += " " + t.plural(R.plurals.backup_restore_again, r.heldBack, r.heldBack)
        }
        return status
    }

    private fun date(epochSeconds: Long, zone: ZoneId): String = Companion.date(epochSeconds, zone)

    companion object {
        /** `LocalGateKeys-Backup-YYYY-MM-DD.lgkm` for the day [epochSeconds] falls on in [zone]. A file name: never translated. */
        fun fileName(epochSeconds: Long, zone: ZoneId = ZoneId.systemDefault()): String = "LocalGateKeys-Backup-${date(epochSeconds, zone)}.lgkm"

        private fun date(epochSeconds: Long, zone: ZoneId): String =
            DateTimeFormatter.ofPattern("uuuu-MM-dd", Locale.ROOT).format(Instant.ofEpochSecond(epochSeconds).atZone(zone))
    }
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

    private val LABEL_IDS = intArrayOf(
        R.string.strength_label_0, R.string.strength_label_1, R.string.strength_label_2, R.string.strength_label_3, R.string.strength_label_4,
    )

    fun check(password: String, confirm: String, t: Txt, strength: StrengthEstimator = estimator): Result {
        val score = if (password.isEmpty()) 0 else strength.estimate(password).score
        val label = t.s(LABEL_IDS[score.coerceIn(0, LABEL_IDS.lastIndex)])
        return when {
            password.codePointCount(0, password.length) < MIN_LENGTH -> Result(false, score, label, t.plural(R.plurals.backup_password_min_length, MIN_LENGTH, MIN_LENGTH))
            score < MIN_SCORE -> Result(false, score, label, t.s(R.string.sync_too_easy_to_guess_add))
            password != confirm -> Result(false, score, label, t.s(R.string.sync_the_two_passwords_do_not))
            else -> Result(true, score, label, t.s(R.string.sync_good))
        }
    }

    /** The problem to show, or null when the password may be used. */
    fun problem(password: String, confirm: String, t: Txt, strength: StrengthEstimator = estimator): String? =
        check(password, confirm, t, strength).let { if (it.ok) null else it.message }
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
    private val export: (String) -> BackupExport,
    private val io: CoroutineContext,
    private val t: Txt,
    /** The password gate (seam): the problem to show, or null. */
    private val check: (String, String) -> String? = { p, c -> BackupPasswordCheck.problem(p, c, t) },
) {
    private val text = BackupText(t)
    private val _password = MutableStateFlow("")
    val password: StateFlow<String> = _password.asStateFlow()
    private val _confirm = MutableStateFlow("")
    val confirm: StateFlow<String> = _confirm.asStateFlow()
    private val _working = MutableStateFlow(false)
    val working: StateFlow<Boolean> = _working.asStateFlow()
    private val _message = MutableStateFlow<String?>(null)
    /** The check's or the export's problem, or the saved confirmation. */
    val message: StateFlow<String?> = _message.asStateFlow()
    private var leftOut = 0
    private val _saved = MutableStateFlow(false)
    val saved: StateFlow<Boolean> = _saved.asStateFlow()

    fun updatePassword(text: String) { _password.value = text; _message.value = null }
    fun updateConfirm(text: String) { _confirm.value = text; _message.value = null }

    /** The desktop's strength label for the typed password ("Strength: Fair"); null while empty. */
    fun strengthText(): String? = _password.value.takeIf { it.isNotEmpty() }?.let { t.s(R.string.backup_strength, BackupPasswordCheck.check(it, it, t).label) }

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
                val made = withContext(io) { export(pw) }
                clear()
                leftOut = made.filesLeftOut
                made.bytes
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            _message.value = text.exportFailed
            null
        } finally {
            _working.value = false
        }
    }

    /** The picker wrote the file ([ok]) or could not. */
    fun written(ok: Boolean) {
        _saved.value = ok
        _message.value = when {
            !ok -> text.writeFailed
            else -> text.savedText(leftOut)
        }
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
    private val t: Txt,
    private val read: (ByteArray, String) -> PhoneBackup = PhoneBackupFormat::read,
) {
    private val text = BackupText(t)
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
            _error.value = text.readFailed
            return
        }
        val header = try {
            PhoneBackupFormat.inspect(bytes)
        } catch (e: PhoneBackupException) {
            _error.value = text.failure(e.reason)
            return
        }
        file = bytes
        _from.value = text.fromLine(header)
        _step.value = Step.PASSWORD
    }

    /** Decrypts with the typed password and plans the restore (nothing is written). */
    suspend fun open() {
        val bytes = file ?: return
        if (_working.value) return
        if (_password.value.isEmpty()) {
            _error.value = text.enterPassword
            return
        }
        if (attempts.blocked()) {
            _error.value = text.tooManyAttempts
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
                _error.value = text.failure(e.reason)
                return
            }
            attempts.succeeded()
            val p = withContext(io) { restorer().plan(backup) }
            plan = p
            _lines.value = text.planLines(p)
            _status.value = text.previewReady
            _step.value = Step.PREVIEW
        } catch (e: CancellationException) {
            throw e
        } catch (e: PhoneRestoreException) {
            _error.value = text.restoreError(e.reason)
        } catch (e: Exception) {
            _error.value = text.unreadable
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
            _lines.value = text.reportLines(report)
            _status.value = text.reportStatus(report)
            _step.value = Step.DONE
            return report.failure == null && (report.new > 0 || report.updated > 0 || report.deleted > 0 || report.licenseRestored)
        } catch (e: CancellationException) {
            throw e
        } catch (e: PhoneRestoreException) {
            _error.value = text.restoreError(e.reason)
            return false
        } catch (e: Exception) {
            _error.value = text.unreadable
            return false
        } finally {
            _working.value = false
        }
    }

    override fun toString(): String = "RestoreFlow(step=${_step.value}, working=${_working.value})"
}
