package app.localgatekeys.android.history

import app.localgatekeys.android.collections.CollectionsModel
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.trash.LocalDataHosting
import app.localgatekeys.core.access.AccessRules
import app.localgatekeys.core.history.HistoryException
import app.localgatekeys.core.history.ItemHistory
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.TravelMode

/**
 * What the feature pack 2026-11-15 pages need from this unlock: its never-synced local data, the history recorder,
 * Pro, the owner check and what follows a travel mode change (fill index rebuild, list reload).
 */
class FeatureSeams(
    val local: LocalDataHosting,
    val history: HistoryRecorder,
    val isPro: () -> Boolean,
    val confirmOwner: suspend () -> Boolean,
    val onTravelChanged: (TravelMode.Setting) -> Unit,
    /** A duress session: no Travel mode row (contract section 2.4). */
    val duress: Boolean = false,
    /**
     * The lock's one-trip allowance for a system screen the app opens itself (Ruling 21, as the folder pickers use it):
     * the Passkey check's "Open settings" calls [willOpenSystemScreen] first, and [systemScreenClosed] when the screen
     * could not be opened. Returning from Settings ends the allowance (foreground).
     */
    val willOpenSystemScreen: () -> Unit = {},
    val systemScreenClosed: () -> Boolean = { true },
) {
    val travel: TravelMode.Setting get() = local.localData?.travelMode ?: TravelMode.Setting.OFF

    override fun toString(): String = "FeatureSeams"

    enum class TravelCheck { OK, OWNER, NEEDS_PRO, UNCHANGED }

    companion object {
        /**
         * Whether restoring [path] of [row] onto item [id] would loosen or remove one of its access rules
         * (`scope.access`, `policy.*`): that needs the owner's check, as in the Access rules sheet (scan A-M2).
         * Unreadable counts as yes.
         */
        fun restoreLoosens(store: ItemStore, id: String, row: ItemHistory.Row, path: String, clock: UnixClock): Boolean = try {
            val current = ((store.load().records[id] as? JsonValue.Obj)?.fields?.get("record") as? JsonValue.Obj)?.fields
            current == null || AccessRules.tightens(ItemHistory.restoreField(current, row.record, path, clock.now), current)
        } catch (e: HistoryException) {
            false // refused by the restore itself
        } catch (e: Exception) {
            true
        }

        /**
         * Restores one field of item [id] from history [row] (contract section 1.6) as an edit that syncs. FAILED when
         * it would loosen an access rule without [ownerConfirmed] ([restoreLoosens]).
         */
        fun restoreField(store: ItemStore, id: String, row: ItemHistory.Row, path: String, clock: UnixClock, ownerConfirmed: Boolean = false): SaveResult = try {
            val snap = store.load()
            val w = (snap.records[id] as? JsonValue.Obj)?.fields
            val ns = (w?.get("ns") as? JsonValue.Str)?.v?.let { Namespace.fromWire(it) }
            val current = (w?.get("record") as? JsonValue.Obj)?.fields
            if (ns == null || current == null || snap.meta[id]?.deleted == true || CollectionsModel.itemIsReadOnly(id, snap)) {
                SaveResult.FAILED
            } else {
                val restored = ItemHistory.restoreField(current, row.record, path, clock.now)
                if (!ownerConfirmed && AccessRules.tightens(restored, current)) return SaveResult.FAILED
                val records = LinkedHashMap(snap.records)
                records[id] = Wrapper.make(ns, JsonValue.Obj(restored))
                CommitOrigin.with("restore") { store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync)) }
                SaveResult.SAVED
            }
        } catch (e: HistoryException) {
            SaveResult.INVALID
        } catch (e: Exception) {
            SaveResult.FAILED
        }

        /**
         * Travel mode's new [wanted] setting against [old] (contract section 2.4): OWNER when it turns off (strict
         * re-auth), NEEDS_PRO when it turns on or changes the set without Pro, else OK.
         */
        fun travelCheck(old: TravelMode.Setting, wanted: TravelMode.Setting, isPro: Boolean): TravelCheck = when {
            old.copy(since = 0) == wanted.copy(since = 0) -> TravelCheck.UNCHANGED
            old.on && !wanted.on -> TravelCheck.OWNER
            // Taking a collection or tag out of the hidden set while on shows its items again: the same strict check
            // as turning it off (scan W-M2), so swapping the set can never be a way around it. Adding still needs Pro.
            old.on && narrows(old, wanted) -> if (!isPro && widens(old, wanted)) TravelCheck.NEEDS_PRO else TravelCheck.OWNER
            !isPro -> TravelCheck.NEEDS_PRO
            else -> TravelCheck.OK
        }

        /** Whether [wanted] leaves out a collection or tag [old] hides (tags compared folded). */
        private fun narrows(old: TravelMode.Setting, wanted: TravelMode.Setting): Boolean =
            !wanted.collections.containsAll(old.collections) ||
                !wanted.tags.map(TravelMode::fold).toSet().containsAll(old.tags.map(TravelMode::fold))

        private fun widens(old: TravelMode.Setting, wanted: TravelMode.Setting): Boolean =
            !old.collections.containsAll(wanted.collections) ||
                !old.tags.map(TravelMode::fold).toSet().containsAll(wanted.tags.map(TravelMode::fold))
    }
}
