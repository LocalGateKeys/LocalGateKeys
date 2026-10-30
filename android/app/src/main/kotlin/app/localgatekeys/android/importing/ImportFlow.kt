package app.localgatekeys.android.importing

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.core.importing.GenericCsv
import app.localgatekeys.core.importing.GenericCsvMapping
import app.localgatekeys.core.importing.ImportDetect
import app.localgatekeys.core.importing.ImportException
import app.localgatekeys.core.importing.ImportFormat
import app.localgatekeys.core.importing.ImportOptions
import app.localgatekeys.core.importing.ImportSource
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.sync.ItemStore
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext

/** The import page's copy: resource ids for fixed text, functions for text with the format's name. */
object ImportText {
    @StringRes val SECTION = R.string.import_section
    @StringRes val BUTTON = R.string.import_button
    @StringRes val FOOTER = R.string.import_footer
    @StringRes val TITLE = R.string.home_import
    @StringRes val CHOOSE = R.string.import_choose
    @StringRes val CHOOSE_HINT = R.string.import_choose_hint
    @StringRes val READ_FAILED = R.string.share_the_file_could_not_be
    @StringRes val TOO_LARGE = R.string.import_too_large
    @StringRes val NOT_RECOGNISED = R.string.import_not_recognised
    @StringRes val ENTER_PASSWORD = R.string.import_enter_password
    @StringRes val OPENING = R.string.import_sheet_opening
    @StringRes val SAVING = R.string.import_sheet_importing
    @StringRes val IMPORT = R.string.home_import
    @StringRes val MAPPING_HINT = R.string.import_mapping_hint
    @StringRes val CONTINUE = R.string.import_continue
    @StringRes val SAVE_FAILED = R.string.import_save_failed

    fun unsupported(f: ImportFormat, t: Txt): String = t.s(R.string.import_unsupported, f.label)

    fun detected(f: ImportFormat, t: Txt): String = t.s(R.string.import_detected, f.label)

    fun passwordPrompt(f: ImportFormat, t: Txt): String = t.s(R.string.import_password_prompt, f.label)

    /** The core's reason code shown in the person's language (the core's English is for logs only). */
    fun failure(e: ImportException, t: Txt): String = t.s(
        when (e.kind) {
            ImportException.Kind.TOO_LARGE -> R.string.import_failure_too_large
            ImportException.Kind.TOO_MANY_ROWS -> R.string.import_failure_too_many_rows
            ImportException.Kind.UNKNOWN_FORMAT -> R.string.detect_the_file_could_not_be
            ImportException.Kind.NEEDS_PASSWORD -> R.string.import_failure_needs_password
            ImportException.Kind.WRONG_PASSWORD -> R.string.bitwarden_wrong_password_or_corrupted_export
            ImportException.Kind.MALFORMED, ImportException.Kind.UNSUPPORTED -> R.string.import_failure_malformed
        },
    )
}

/**
 * Settings › Import from a file: choose a file (the Storage Access Framework picker, read by the screen with the 64 MB
 * cap), give its password or choose its columns where needed, review the rows ([ImportReview]: Add / Skip / Replace,
 * the free plan's limit) and save them in one store commit. [onChanged] runs after a commit that wrote something (the
 * editor's hook: the list reloads and sync is told). The file's bytes, the password and the parsed rows live in memory
 * only and are dropped when the import ends; toString shows none of them.
 */
class ImportFlow(
    private val store: () -> ItemStore,
    private val isPro: () -> Boolean,
    private val clock: UnixClock,
    private val random: RandomSource,
    private val io: CoroutineContext,
    private val t: Txt,
    private val onChanged: () -> Unit = {},
) {
    enum class Step { CHOOSE, PASSWORD, MAPPING, REVIEW, DONE }

    data class State(
        val step: Step = Step.CHOOSE,
        val format: ImportFormat? = null,
        val working: Boolean = false,
        val error: String? = null,
        /** The CSV header and the chosen columns ([Step.MAPPING]). */
        val header: List<String> = emptyList(),
        val mapping: GenericCsvMapping = GenericCsvMapping(),
        val rows: List<ImportRow> = emptyList(),
        val issues: List<String> = emptyList(),
        val summary: String = "",
        val canImport: Boolean = false,
        val outcome: ImportOutcome? = null,
    ) {
        override fun toString(): String = "ImportFlow.State(step=$step, format=$format, rows=${rows.size}, working=$working)"
    }

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()
    private val _password = MutableStateFlow("")
    val password: StateFlow<String> = _password.asStateFlow()

    private var file: ByteArray? = null
    private var review: ImportReview? = null

    fun updatePassword(text: String) {
        _password.value = text
        _state.update { it.copy(error = null) }
    }

    /** A file the picker returned ([bytes] read with the 64 MB cap + 1, null when unreadable) and its display name. */
    suspend fun chose(bytes: ByteArray?, name: String) {
        reset()
        if (bytes == null) return fail(t.s(ImportText.READ_FAILED))
        if (bytes.size > ImportSource.MAX_ARCHIVE_BYTES) return fail(t.s(ImportText.TOO_LARGE))
        val format = withContext(io) { ImportDetect.detect(bytes, name) } ?: return fail(t.s(ImportText.NOT_RECOGNISED))
        if (!format.supported) return fail(ImportText.unsupported(format, t))
        file = bytes
        _state.update { it.copy(format = format) }
        when {
            format.needsPassword -> _state.update { it.copy(step = Step.PASSWORD) }
            format == ImportFormat.GENERIC -> {
                val header = try {
                    withContext(io) { GenericCsv.header(bytes) }
                } catch (e: ImportException) {
                    return fail(ImportText.failure(e, t))
                }
                _state.update { it.copy(step = Step.MAPPING, header = header, mapping = GenericCsv.suggestMapping(header)) }
            }
            else -> parse(ImportOptions())
        }
    }

    /** Opens the encrypted file with the typed password (cleared at once; a wrong one asks again). */
    suspend fun open() {
        if (_state.value.working || file == null) return
        val pw = _password.value
        if (pw.isEmpty()) return fail(t.s(ImportText.ENTER_PASSWORD), keepStep = true)
        _password.value = ""
        parse(ImportOptions(password = pw))
    }

    fun choose(mapping: GenericCsvMapping) = _state.update { it.copy(mapping = mapping, error = null) }

    /** Reads the generic CSV with the chosen columns. */
    suspend fun applyMapping() {
        if (_state.value.working || file == null) return
        parse(ImportOptions(mapping = _state.value.mapping))
    }

    private suspend fun parse(options: ImportOptions) {
        val bytes = file ?: return
        val format = _state.value.format ?: return
        _state.update { it.copy(working = true, error = null) }
        try {
            val r = withContext(io) {
                val result = ImportSource.candidates(bytes, format, options)
                ImportReview(result, store().load(), isPro(), clock, random, t)
            }
            review = r
            publish(r, Step.REVIEW)
        } catch (e: CancellationException) {
            throw e
        } catch (e: ImportException) {
            // A wrong password asks again; any other problem stays on the step it came from.
            _state.update { it.copy(error = if (e.kind == ImportException.Kind.NEEDS_PASSWORD) ImportText.passwordPrompt(format, t) else ImportText.failure(e, t)) }
        } catch (e: Exception) {
            _state.update { it.copy(error = t.s(ImportText.NOT_RECOGNISED)) }
        } finally {
            _state.update { it.copy(working = false) }
        }
    }

    private fun publish(r: ImportReview, step: Step) = _state.update {
        it.copy(step = step, rows = r.rows, issues = r.issues, summary = r.summary, canImport = r.willImport > 0)
    }

    fun set(decision: ImportDecision, rowId: Int) {
        val r = review ?: return
        r.set(decision, rowId)
        publish(r, Step.REVIEW)
    }

    fun setAllExisting(decision: ImportDecision) {
        val r = review ?: return
        r.setAllExisting(decision)
        publish(r, Step.REVIEW)
    }

    /** Saves the reviewed rows in one commit; true when something was written. */
    suspend fun commit(): Boolean {
        val r = review ?: return false
        if (_state.value.working) return false
        _state.update { it.copy(working = true, error = null) }
        try {
            val outcome = withContext(io) { r.commit(store()) }
            file = null; review = null
            _state.value = State(step = Step.DONE, format = _state.value.format, outcome = outcome)
            val changed = outcome.created + outcome.updated > 0
            if (changed) onChanged()
            return changed
        } catch (e: CancellationException) {
            throw e
        } catch (e: ImportReviewException) {
            _state.update { it.copy(error = e.text(t), working = false) }
        } catch (e: Exception) {
            _state.update { it.copy(error = t.s(ImportText.SAVE_FAILED), working = false) }
        }
        return false
    }

    /** Drops the file, the password and the rows. */
    fun reset() {
        file = null; review = null
        _password.value = ""
        _state.value = State()
    }

    private fun fail(message: String, keepStep: Boolean = false) {
        if (!keepStep) { file = null; review = null }
        _state.update { if (keepStep) it.copy(error = message) else State(error = message) }
    }

    override fun toString(): String = "ImportFlow(state=${_state.value})"
}
