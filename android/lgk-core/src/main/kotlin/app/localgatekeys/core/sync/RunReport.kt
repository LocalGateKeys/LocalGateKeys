package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.SyncMeta

/** Result of one run (desktop `runner.RunReport`). */
data class RunReport(
    val applied: Int = 0,
    val deleted: Int = 0,
    val conflicts: Int = 0,
    /** Stored records that cannot be published (id, reason), sorted. */
    val skipped: List<Pair<String, String>> = emptyList(),
    val issues: List<SyncIssue> = emptyList(),
    /** This device's post-apply view (sorted by id) to publish, or null when nothing should be published. */
    val ownStates: List<ItemState>? = null,
    /** Set by a transport that wrote its own file. */
    val wrote: Boolean = false,
    /** Licence bundles received in this run that verified. */
    val licenses: List<JsonValue> = emptyList(),
    /** The store content after the run (records and meta), committed by the transport; null when unchanged/unknown. */
    val records: Map<String, JsonValue>? = null,
    val meta: Map<String, SyncMeta>? = null,
) {
    /** Counts only: states, licences and records hold plaintext. */
    override fun toString(): String =
        "RunReport(applied=$applied, deleted=$deleted, conflicts=$conflicts, skipped=${skipped.size}, issues=${issues.size}, " +
            "ownStates=${ownStates?.size}, wrote=$wrote, licenses=${licenses.size}, records=${records?.size}, meta=${meta?.size})"
}
