package app.localgatekeys.android.backup

import app.localgatekeys.android.access.AccessGate
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.exporting.CxfDiagnostic
import app.localgatekeys.core.exporting.CxfExport
import app.localgatekeys.core.exporting.CxfExportException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreSnapshot
import java.time.Instant
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import app.localgatekeys.core.sync.itemRecords

/**
 * Settings › Export to a CXF file: the person picks logins, notes and passkeys, reads the plaintext warnings, then
 * Export asks for the owner's fingerprint, face or screen lock ([confirmOwner]) before anything leaves the vault.
 * Declined: nothing is made and no save picker opens. Passed: the core builds the whole file in memory (passkey private
 * keys released only now, from the snapshot read after the check), and the screen hands the bytes to the "save as"
 * picker; [written] reports the result and the bytes are cleared. The rows show titles only; toString shows no values.
 */
class CxfExportFlow(
    private val store: () -> ItemStore,
    private val confirmOwner: suspend () -> Boolean,
    private val clock: UnixClock,
    private val random: RandomSource,
    private val io: CoroutineContext,
    private val t: Txt,
    /** Travel mode's hidden ids on this phone (contract section 2.3): left out of the file, with a count. */
    private val hidden: () -> Set<String> = { emptySet() },
) {
    enum class Kind { LOGIN, NOTE, PASSKEY }

    /** One item the file can hold: its id, title and kind. */
    data class Choice(val id: String, val title: String, val kind: Kind, val detail: String)

    data class State(
        val choices: List<Choice> = emptyList(),
        val selected: Set<String> = emptySet(),
        val loaded: Boolean = false,
        val working: Boolean = false,
        val message: String? = null,
        val saved: Boolean = false,
        /** What the file left out (custom fields, passkey notes, items of other kinds), in the person's language. */
        val notes: List<String> = emptyList(),
        /** Logins left out before the list: view only on phones (contract section 4.3). */
        val leftOut: Int = 0,
        /** Items left out before the list: hidden by travel mode (contract section 2.3). */
        val travelLeftOut: Int = 0,
    ) {
        val passkeySelected: Boolean get() = choices.any { it.kind == Kind.PASSKEY && it.id in selected }

        override fun toString(): String = "CxfExportFlow.State(choices=${choices.size}, selected=${selected.size}, working=$working, saved=$saved)"
    }

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()

    private var pending: ByteArray? = null
    private var pendingCount = 0

    /** Lists the live logins, notes and passkeys (by title); nothing is selected at first. */
    suspend fun load() {
        val (choices, counts) = withContext(io) {
            val snap = store().load()
            val all = choices(snap).size
            val hiddenIds = hidden()
            val noTravel = choices(snap, emptySet()).size
            val kept = choices(snap, hiddenIds)
            kept to Pair(all - noTravel, noTravel - kept.size)
        }
        _state.update { it.copy(choices = choices, leftOut = counts.first, travelLeftOut = counts.second, selected = it.selected.filter { id -> choices.any { c -> c.id == id } }.toSet(), loaded = true) }
    }

    fun toggle(id: String) = _state.update {
        if (it.working || it.saved) return@update it
        it.copy(selected = if (id in it.selected) it.selected - id else it.selected + id, message = null)
    }

    fun selectAll(all: Boolean) = _state.update {
        if (it.working || it.saved) it else it.copy(selected = if (all) it.choices.map { c -> c.id }.toSet() else emptySet(), message = null)
    }

    /** The warnings shown above the list: the CSV export's plaintext warnings, and the passkey one when a passkey is chosen. */
    fun warnings(s: State = _state.value): List<String> = listOfNotNull(
        t.s(R.string.cxf_export_plaintext),
        t.s(R.string.cxf_export_totp),
        if (s.passkeySelected) t.s(R.string.cxf_export_passkey_keys) else null,
        if (s.leftOut > 0) t.plural(R.plurals.access_export_left_out, s.leftOut, s.leftOut) else null,
        if (s.travelLeftOut > 0) t.plural(R.plurals.travel_export_left_out, s.travelLeftOut, s.travelLeftOut) else null,
        t.s(R.string.cxf_export_delete_after),
    )

    /**
     * The file's bytes, or null (the reason is in the state's message). Asks for the owner check first; a refusal (or a
     * lock) ends the export with nothing made.
     */
    suspend fun make(): ByteArray? {
        val s = _state.value
        if (s.working || s.saved) return null
        val ids = s.choices.map { it.id }.filter { it in s.selected }
        if (ids.isEmpty()) {
            _state.update { it.copy(message = t.s(R.string.cxf_export_choose)) }
            return null
        }
        _state.update { it.copy(working = true, message = null) }
        try {
            // Checked before the owner prompt so a selection that cannot be written does not ask for it.
            withContext(io) { CxfExport.plan(store().load(), ids) }
            if (!confirmOwner()) {
                _state.update { it.copy(message = t.s(R.string.cxf_export_declined)) }
                return null
            }
            val result = withContext(io) {
                val snapshot = store().load()
                val plan = CxfExport.plan(snapshot, ids)
                val released = if (plan.passkeys.isEmpty()) emptyMap() else CxfExport.privateKeys(snapshot, plan.passkeys.keys)
                CxfExport.finish(plan, released, clock.now, random)
            }
            clear()
            pending = result.bytes
            pendingCount = result.count
            _state.update { it.copy(notes = result.diagnostics.map { d -> diagnostic(d, t) }) }
            return result.bytes
        } catch (e: CancellationException) {
            throw e
        } catch (e: CxfExportException) {
            _state.update { it.copy(message = failure(e, t)) }
        } catch (e: Exception) {
            _state.update { it.copy(message = t.s(R.string.cxf_export_failed)) }
        } finally {
            _state.update { it.copy(working = false) }
        }
        return null
    }

    /**
     * The save picker's answer: true once written, false when the write failed, null when dropped (the vault locked
     * while the picker was open, or another save was pending). The bytes are cleared either way.
     */
    fun written(ok: Boolean?) {
        clear()
        val count = pendingCount
        _state.update {
            when (ok) {
                true -> it.copy(saved = true, message = t.plural(R.plurals.cxf_export_saved, count, count))
                false -> it.copy(message = t.s(R.string.cxf_export_failed), notes = emptyList())
                null -> it.copy(notes = emptyList())
            }
        }
    }

    /** The person closed the save picker without choosing a place: not a failure; the bytes are cleared, nothing shown. */
    fun cancelled() {
        clear()
        _state.update { it.copy(message = null, notes = emptyList()) }
    }

    /** Zeroes the file's bytes if they are still held (the screen leaving, an activity recreated mid-picker). */
    fun clear() {
        pending?.fill(0)
        pending = null
    }

    override fun toString(): String = "CxfExportFlow(state=${_state.value})"

    companion object {
        /** The file name the save picker suggests: `LocalGateKeys-CXF-YYYY-MM-DD.json`. */
        fun fileName(now: Long, zone: java.time.ZoneId = java.time.ZoneId.systemDefault()): String =
            "LocalGateKeys-CXF-" + Instant.ofEpochSecond(now).atZone(zone).toLocalDate() + ".json"

        private fun str(v: JsonValue?): String = (v as? JsonValue.Str)?.v ?: ""

        /** The live logins, notes and passkeys of [s], by title. */
        internal fun choices(s: StoreSnapshot, hidden: Set<String>? = null): List<Choice> {
            val out = ArrayList<Choice>()
            for ((id, wrapper) in s.itemRecords) {
                if (s.meta[id]?.deleted == true) continue
                val w = (wrapper as? JsonValue.Obj)?.fields ?: continue
                val r = (w["record"] as? JsonValue.Obj)?.fields ?: continue
                // [hidden] non-null: the export's list, without travel-hidden items and view-only-on-phones logins.
                if (hidden != null && (id in hidden || (str(w["ns"]) == Namespace.ENTRY.wire && AccessGate.effective(r).phoneView))) continue
                val ns = str(w["ns"])
                val kind = str(r["kind"])
                when {
                    ns == Namespace.ENTRY.wire && (kind == "web" || kind == "desktop") -> {
                        val origin = str((r["scope"] as? JsonValue.Obj)?.fields?.get("origin"))
                        val title = str(r["label"]).ifEmpty { origin }
                        out.add(Choice(id, title, Kind.LOGIN, listOf(origin.removePrefix("https://"), str(r["username"])).filter { it.isNotEmpty() && it != title }.joinToString(" · ")))
                    }
                    ns == Namespace.ITEM.wire && kind == "note" -> out.add(Choice(id, str(r["title"]), Kind.NOTE, ""))
                    ns == Namespace.ITEM.wire && kind == "passkey" -> {
                        val p = (r["payload"] as? JsonValue.Obj)?.fields ?: emptyMap()
                        out.add(Choice(id, str(r["title"]).ifEmpty { str(p["relying_party_id"]) }, Kind.PASSKEY, str(p["user_name"])))
                    }
                }
            }
            return out.sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.title })
        }

        fun diagnostic(d: CxfDiagnostic, t: Txt): String = if (d.kind == CxfDiagnostic.Kind.KIND_SKIPPED && d.title.isEmpty()) {
            t.s(R.string.cxf_export_item_gone)
        } else t.s(
            when (d.kind) {
                CxfDiagnostic.Kind.FIELDS_LEFT_OUT -> R.string.cxf_export_fields_left_out
                CxfDiagnostic.Kind.KIND_SKIPPED -> R.string.cxf_export_kind_skipped
                CxfDiagnostic.Kind.PASSKEY_NOTES_LEFT_OUT -> R.string.cxf_export_passkey_notes_left_out
            },
            d.title,
        )

        fun failure(e: CxfExportException, t: Txt): String = when (e.kind) {
            CxfExportException.Kind.CHOOSE_ITEMS -> t.s(R.string.cxf_export_choose)
            CxfExportException.Kind.PASSKEY_KEY_MISSING -> t.s(R.string.cxf_export_passkey_key_missing, e.title)
            CxfExportException.Kind.NOTHING_TO_EXPORT -> t.s(R.string.cxf_export_nothing)
        }
    }
}
