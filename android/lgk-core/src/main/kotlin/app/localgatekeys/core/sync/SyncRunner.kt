package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.Engine
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.RecordException
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.records.Wrapper

/**
 * One sync run shared by every transport: local view -> fold peer views -> one apply (desktop `runner.run_merge`).
 *
 * Pure: it never touches the store. The returned report carries the new `records` and `meta`, which the
 * transport commits only once every read and check has succeeded.
 */
object SyncRunner {
    /**
     * Folds [views] into the local view of [store] and applies the outcome.
     *
     * - A peer state whose version vector is implausible next to the local state of that id
     *   ([Plausibility.implausibleVv]; audit M-6) is quarantined before the fold (`implausible-vv`, detail
     *   `<device>:<item>`). Known devices: [device], the views' devices and [known].
     * - A view the engine rejects as a whole is dropped (`bad-peer-data`).
     * - A single peer record that cannot be stored is quarantined (`bad-peer-record`, or `update-needed`
     *   for a newer wrapper schema; detail `<device>:<item>`); the rest of that view merges.
     * - An apply that still fails gives `apply-failed`; nothing is applied but `ownStates` carries the local view.
     * - A store that cannot be read for sync gives `local-data` and no `ownStates` (publish nothing).
     */
    fun run(
        store: StoreSnapshot,
        views: List<PeerView>,
        device: String,
        now: Long,
        licenseKeys: Map<String, ByteArray> = emptyMap(),
        known: Set<String> = emptySet(),
    ): RunReport {
        val issues = ArrayList<SyncIssue>()
        val local = try {
            SyncMeta.localView(store.records, store.meta, device, now)
        } catch (e: Exception) {
            issues.add(SyncIssue("local-data", (e.message ?: e.toString())))
            return RunReport(issues = issues)
        }
        val localSkipped = local.skipped.entries.sortedWith { a, b -> Scalars.compare(a.key, b.key) }.map { it.key to it.value }
        val knownAll = known + device + views.map { it.deviceId }
        val plausible = views.map { view ->
            val kept = view.states.filter { s ->
                val why = Plausibility.implausibleVv(s.vv, local.states[s.itemId]?.vv, knownAll)
                if (why != null) issues.add(SyncIssue("implausible-vv", "${view.deviceId}:${s.itemId}"))
                why == null
            }
            if (kept.size == view.states.size) view else PeerView(view.deviceId, kept)
        }
        val fold = Engine.fold(local.states, plausible, device) { state -> check(state, licenseKeys) }
        for (dev in fold.badViews) issues.add(SyncIssue("bad-peer-data", dev))
        for (q in fold.quarantined) {
            val kind = if (q.reason == "update-needed") "update-needed" else "bad-peer-record"
            issues.add(SyncIssue(kind, "${q.device}:${q.item}"))
        }
        val applied = try {
            SyncMeta.applyRemote(fold.outcome, store.records, local.meta, device, now, licenseKeys)
        } catch (e: Exception) {
            issues.add(SyncIssue("apply-failed", (e.message ?: e.toString())))
            return RunReport(
                skipped = localSkipped, issues = issues, ownStates = sorted(local.states),
                records = store.records, meta = local.meta,
            )
        }
        val final = try {
            SyncMeta.localView(applied.records, applied.meta, device, now)
        } catch (e: Exception) {
            issues.add(SyncIssue("local-data", (e.message ?: e.toString())))
            return RunReport(skipped = localSkipped, issues = issues)
        }
        val skipped = (localSkipped + final.skipped.entries.map { it.key to it.value }).toSet()
            .sortedWith { a, b ->
                val c = Scalars.compare(a.first, b.first)
                if (c != 0) c else Scalars.compare(a.second, b.second)
            }
        return RunReport(
            applied = applied.applied, deleted = applied.deleted, conflicts = applied.conflicts,
            skipped = skipped, issues = issues, ownStates = sorted(final.states),
            licenses = applied.licenses, records = applied.records, meta = final.meta,
        )
    }

    internal fun sorted(states: Map<String, ItemState>): List<ItemState> = states.values.sortedWith { a, b -> Scalars.compare(a.itemId, b.itemId) }

    /**
     * The bridge's refusal for a state the fold wants to store, or null (plays the desktop per-record apply check,
     * `vault_bridge.check_remote_state`; phone restore uses it to leave unreadable backup states out before the free cap).
     */
    fun check(state: ItemState, licenseKeys: Map<String, ByteArray>): String? {
        if (state.deleted) return null
        val item = state.item ?: return null
        val isCopy: Boolean
        if (item is JsonValue.Obj) {
            // applyRemote drops these without a word: a licence this build cannot verify, or a licence conflict copy.
            // (a copy never carries a `lic:` id; a `lic:` state with a top-level id is refused below).
            isCopy = item.fields["id"] != null && !Wrapper.isLicenseId(state.itemId)
            if (item.fields["ns"] == JsonValue.Str(Namespace.LICENSE.wire) && (licenseKeys.isEmpty() || isCopy)) return null
        } else {
            isCopy = false
        }
        return try {
            Wrapper.unwrap(state, isCopy, licenseKeys)
            null
        } catch (e: RecordException) {
            e.reason ?: "bad-remote"
        } catch (e: Exception) {
            "bad-remote"
        }
    }
}
