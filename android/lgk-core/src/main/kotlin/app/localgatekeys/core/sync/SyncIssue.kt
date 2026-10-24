package app.localgatekeys.core.sync

/** Something a run skipped or refused; [kind] is a stable code (desktop `runner.SyncIssue`), [detail] free text. */
data class SyncIssue(val kind: String, val detail: String = "") {
    override fun toString(): String = if (detail.isEmpty()) kind else "$kind: $detail"
}
