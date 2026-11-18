package app.localgatekeys.android.importing

import app.localgatekeys.core.sync.itemRecords
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import java.util.UUID
import app.localgatekeys.core.importing.ImportUndo
import app.localgatekeys.android.history.CommitOrigin
import app.localgatekeys.android.trash.PhoneTrash
import app.localgatekeys.android.trash.LocalDataHosting
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
    /** Feature pack 2026-11-15 (contract section 6.1): where the last import's undo journal is kept; null: no Undo. */
    private val local: LocalDataHosting? = null,
    /** Recently deleted, for the items an undo removes. */
    private val trash: PhoneTrash? = null,
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
        /** The switch report after the import (contract section 6.1): counts read back from what the commit wrote. */
        val report: SwitchReport? = null,
        /** The import can be undone (one level, 7 days, this phone only). */
        val canUndo: Boolean = false,
        /** What the undo did ("Import undone. ..."). */
        val undone: String? = null,
    ) {
        override fun toString(): String = "ImportFlow.State(step=$step, format=$format, rows=${rows.size}, working=$working)"
    }

    /** The last import's journal is still usable (one level, 7 days, this phone only). */
    private fun undoAvailable(): Boolean = local?.localData?.lastImport?.usable(clock.now) == true

    private val _state = MutableStateFlow(State(canUndo = undoAvailable()))
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
        // Text exports (CSV, JSON, CXF) are read at most to the 8 MiB cap + 1 ([ImportRead]); only zip archives and
        // KeePass databases go further.
        if (bytes.size > ImportSource.MAX_SOURCE_BYTES && !ImportRead.isBinary(bytes)) {
            return fail(t.s(R.string.import_failure_too_large))
        }
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
            val rows = r.rows
            val notes = r.issues
            var report: SwitchReport? = null
            val outcome = withContext(io) {
                // The journal is built from the import's own commit: the snapshot it was based on and the records it
                // wrote, never a reload, so an item a sync brings in meanwhile is never taken for one the import
                // created (and trashed by Undo), nor a later edit taken for what the import wrote.
                val written = CapturingStore(store())
                val o = CommitOrigin.with("import") { r.commit(written) }
                // The switch report counts only what this commit wrote (nothing written: nothing arrived).
                report = runCatching {
                    val base = written.base
                    val after = written.after
                    if (base != null && after != null) SwitchReport.build(rows, recordsOf(base), recordsOf(after)) else SwitchReport.build(rows, emptyMap(), emptyMap())
                }.getOrNull()
                // The undo journal (best effort: an import never fails because of it).
                local?.let { l ->
                    runCatching {
                        val base = written.base ?: return@runCatching
                        val after = written.after ?: return@runCatching
                        val j = ImportUndo.journal(UUID.randomUUID().toString(), clock.now, _state.value.format?.name?.lowercase() ?: "", recordsOf(base), recordsOf(after))
                        if (j.created.isNotEmpty() || j.replaced.isNotEmpty()) synchronized(l) { l.localData?.let { d -> l.commitLocalData(d.withLastImport(j)) } }
                    }
                }
                o
            }
            file = null; review = null
            _state.value = State(
                step = Step.DONE, format = _state.value.format, outcome = outcome, report = report, issues = notes,
                canUndo = local?.localData?.lastImport?.usable(clock.now) == true,
            )
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

    /**
     * Undo this import (contract section 6.1): items it created go to Recently deleted, items it replaced get their
     * earlier version back; anything changed since the import is kept. One level: the journal is then dropped.
     */
    suspend fun undo() {
        val l = local ?: return
        val j = l.localData?.lastImport?.takeIf { it.usable(clock.now) } ?: run {
            // Expired (7 days) or gone (a newer import, an undo elsewhere): the button goes away.
            _state.update { it.copy(canUndo = false) }
            return
        }
        try {
            val (trashed, kept) = withContext(io) {
                val snap = store().load()
                val plan = ImportUndo.plan(j, recordsOf(snap), clock.now)
                if (plan.restore.isNotEmpty()) {
                    val records = LinkedHashMap(snap.records)
                    for ((id, rec) in plan.restore) {
                        val ns = ((snap.records[id] as? JsonValue.Obj)?.fields?.get("ns") as? JsonValue.Str)?.v?.let { Namespace.fromWire(it) } ?: continue
                        records[id] = Wrapper.make(ns, JsonValue.Obj(rec))
                    }
                    CommitOrigin.with("restore") { store().commit(StoreChange(snap.revision, records, snap.meta, snap.sync)) }
                }
                var n = 0
                for (id in plan.trash) if (PhoneTrash.deleteItem(id, store(), clock, trash) == SaveResult.SAVED) n++
                synchronized(l) { l.localData?.let { d -> l.commitLocalData(d.withLastImport(null)) } }
                n to plan.kept.size
            }
            val text = t.plural(R.plurals.import_undone, trashed, trashed) + if (kept > 0) " " + t.plural(R.plurals.import_undo_kept_changed, kept, kept) else ""
            _state.update { it.copy(canUndo = false, undone = text) }
            onChanged()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            _state.update { it.copy(error = t.s(ImportText.SAVE_FAILED)) }
        }
    }

    /**
     * Rereads whether the last import can still be undone, for the start and Done pages (contract section 6.1: the undo
     * stays reachable from the import page for 7 days after leaving the Done page, and goes away once it expires).
     */
    fun refreshUndo() {
        val available = undoAvailable()
        _state.update { if (it.step == Step.CHOOSE || it.step == Step.DONE) it.copy(canUndo = available && it.undone == null) else it }
    }

    /** Drops the file, the password and the rows. */
    fun reset() {
        file = null; review = null
        _password.value = ""
        _state.value = State(canUndo = undoAvailable())
    }

    private fun fail(message: String, keepStep: Boolean = false) {
        if (!keepStep) { file = null; review = null }
        _state.update { if (keepStep) it.copy(error = message) else State(error = message, canUndo = undoAvailable()) }
    }

    override fun toString(): String = "ImportFlow(state=${_state.value})"
}

/**
 * The bounded read of a chosen file: at most [ImportSource.MAX_SOURCE_BYTES] + 1 bytes, so a text export past the
 * import cap is refused without being read whole; only a zip archive (.1pux, Proton Pass, Dashlane) or a KeePass
 * database (.kdbx) is read further, up to [ImportSource.MAX_ARCHIVE_BYTES] + 1.
 */
object ImportRead {
    private val ZIP_MAGIC = byteArrayOf(0x50, 0x4B, 0x03, 0x04)

    private val KDBX_MAGIC = byteArrayOf(0x03, 0xD9.toByte(), 0xA2.toByte(), 0x9A.toByte())

    private fun starts(head: ByteArray, magic: ByteArray): Boolean = head.size >= magic.size && magic.indices.all { head[it] == magic[it] }

    fun isZip(head: ByteArray): Boolean = starts(head, ZIP_MAGIC)

    /** A zip archive or a KeePass database: the formats allowed past the text cap. */
    fun isBinary(head: ByteArray): Boolean = starts(head, ZIP_MAGIC) || starts(head, KDBX_MAGIC)

    fun read(input: java.io.InputStream): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        var limit = ImportSource.MAX_SOURCE_BYTES + 1
        var checked = false
        while (out.size() < limit) {
            val n = input.read(buf, 0, minOf(buf.size, limit - out.size()))
            if (n < 0) break
            out.write(buf, 0, n)
            if (!checked && out.size() >= ZIP_MAGIC.size) {
                checked = true
                if (isBinary(out.toByteArray().copyOf(ZIP_MAGIC.size))) limit = ImportSource.MAX_ARCHIVE_BYTES + 1
            }
        }
        return out.toByteArray()
    }
}

/** The live entry and item records of [s] (id -> record), for the import's undo journal. */
/**
 * Passes loads and commits through to [inner] and remembers the last successful commit: [base], the snapshot it was
 * based on (the load whose revision it named), and [after], the snapshot it wrote.
 */
internal class CapturingStore(private val inner: ItemStore) : ItemStore {
    private var loaded: StoreSnapshot? = null
    var base: StoreSnapshot? = null
        private set
    var after: StoreSnapshot? = null
        private set

    override fun load(): StoreSnapshot = inner.load().also { loaded = it }

    override fun commit(change: StoreChange) {
        inner.commit(change)
        val l = loaded
        if (l != null && l.revision == change.baseRevision) {
            base = l
            after = StoreSnapshot(change.records, change.meta, change.sync, change.baseRevision + 1)
        } else {
            base = null
            after = null
        }
    }
}

internal fun recordsOf(s: StoreSnapshot): Map<String, Map<String, JsonValue>> {
    val out = LinkedHashMap<String, Map<String, JsonValue>>()
    for ((id, w) in s.itemRecords) {
        if (s.meta[id]?.deleted == true) continue
        val f = (w as? JsonValue.Obj)?.fields ?: continue
        val ns = (f["ns"] as? JsonValue.Str)?.v
        if (ns != Namespace.ENTRY.wire && ns != Namespace.ITEM.wire) continue
        out[id] = (f["record"] as? JsonValue.Obj)?.fields ?: continue
    }
    return out
}
