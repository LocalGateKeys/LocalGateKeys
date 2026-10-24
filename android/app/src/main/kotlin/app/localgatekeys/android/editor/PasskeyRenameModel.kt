package app.localgatekeys.android.editor

import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.NormaliseException
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The only edits the phone makes to a passkey: a new title, or delete. Every other field (the key, the credential id,
 * the relying party) stays byte for byte as stored, so the passkey keeps signing in. Port of `PasskeyRenameModel` in
 * `ios/App/Editor/PasskeyEditor.swift`. [save] and [delete] use the store: call them off the main thread.
 */
class PasskeyRenameModel(private val store: ItemStore, item: VaultItem, private val clock: UnixClock) {
    private val id = item.id
    private val original: String = (item.record["title"] as? JsonValue.Str)?.v ?: ""

    private val _title = MutableStateFlow(original)
    val title: StateFlow<String> = _title.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: String? get() = _error.value
    val errorFlow: StateFlow<String?> = _error.asStateFlow()

    private val _alreadyRemoved = MutableStateFlow(false)
    /** Delete found the passkey gone already: the screen says so and closes. */
    val alreadyRemoved: Boolean get() = _alreadyRemoved.value
    val alreadyRemovedFlow: StateFlow<Boolean> = _alreadyRemoved.asStateFlow()

    fun setTitle(t: String) {
        _title.value = t
    }

    /**
     * Sets `title` and the `updated_at` stamp on the stored record and nothing else; the next sync view bumps it once
     * for this device. The same title writes nothing.
     */
    fun save(): SaveResult {
        _error.value = null
        val title = _title.value
        if (WebsiteInput.trimmed(title).isEmpty()) {
            _error.value = "Enter a name."
            return SaveResult.INVALID
        }
        if (title == original) return SaveResult.UNCHANGED
        return try {
            val snap = store.load()
            val w = (snap.records[id] as? JsonValue.Obj)?.fields
            val r = (w?.get("record") as? JsonValue.Obj)?.fields
            if (w == null || w["ns"] != JsonValue.Str(Namespace.ITEM.wire) || r == null || r["kind"] != JsonValue.Str("passkey")) {
                _error.value = "This passkey is no longer on this phone."
                return SaveResult.FAILED
            }
            val changed = LinkedHashMap(r)
            changed["title"] = JsonValue.Str(title)
            changed["updated_at"] = JsonValue.Int(clock.now)
            val record = Normalise.normalForm(Namespace.ITEM, JsonValue.Obj(changed))
            val records = LinkedHashMap(snap.records)
            records[id] = Wrapper.make(Namespace.ITEM, record)
            store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
            SaveResult.SAVED
        } catch (e: NormaliseException) {
            if (e.kind == NormaliseException.Kind.REJECTED) {
                _error.value = e.detail
                SaveResult.INVALID
            } else {
                _error.value = SAVE_FAILED
                SaveResult.FAILED
            }
        } catch (_: Exception) {
            _error.value = SAVE_FAILED
            SaveResult.FAILED
        }
    }

    fun clearAlreadyRemoved() {
        _alreadyRemoved.value = false
    }

    /** Removes the item and writes its tombstone, as for every other item ([EditorModel.delete]). */
    fun delete(): SaveResult {
        val r = EditorModel.delete(id, store, clock)
        if (r == SaveResult.FAILED) _error.value = "The passkey could not be deleted on this device."
        _alreadyRemoved.value = r == SaveResult.UNCHANGED
        return r
    }

    override fun toString(): String = "PasskeyRenameModel(id=$id)"

    companion object {
        const val SAVE_FAILED = "The passkey could not be saved on this device."
        const val TITLE = "Edit passkey"
        const val FOOTER = "Only the name can be changed. The passkey itself stays as it is."
        const val DELETE = "Delete passkey"
        const val DELETE_TITLE = "Delete this passkey?"
        const val DELETE_MESSAGE = "You will no longer be able to sign in to this website with it."
    }
}
