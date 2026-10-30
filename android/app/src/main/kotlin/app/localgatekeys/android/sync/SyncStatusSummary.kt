package app.localgatekeys.android.sync

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import java.text.DateFormat
import java.util.Date

/**
 * "Sync status you can tap" (UX plan 2026-10-27 workstream 6): the vault header's pill ("Synced 2 min ago · 3 devices"
 * with a green, orange or red dot) and the sheet's device rows. Pure: built from the coordinator's state.
 */
data class SyncStatusSummary(val pill: String, val dot: Dot, val devices: List<Device>) {
    enum class Dot { GREEN, ORANGE, RED }

    enum class Route(@StringRes val label: Int) {
        WIFI(R.string.nav_type_wifi), FOLDER(R.string.sync_cloud_folder), BOTH(R.string.sync_route_both),
    }

    /** One other device: [lastSynced] is when this phone last accepted its changes (null: never). */
    data class Device(val id: String, val name: String, val route: Route, val lastSynced: Long?, val warning: String?)

    companion object {
        const val DAY = 86_400L
        const val STALE_DAYS = 30L
        @StringRes val TITLE = R.string.command_sync_status_title
        @StringRes val THIS_DEVICE = R.string.sync_this_device
        @StringRes val SYNC_NOW = R.string.sync_status_page_sync_now
        @StringRes val OPEN_SETTINGS = R.string.sync_status_page_open_settings
        @StringRes val NEVER = R.string.login_more_never
        @StringRes val NOT_SEEN = R.string.sync_status_not_seen_in30_days

        /** Null when this phone does not sync. */
        fun of(
            membership: SyncCoordinator.Membership,
            issues: List<SyncWording.IssueView>,
            lastSyncedAt: Long?,
            now: Long,
            t: Txt,
        ): SyncStatusSummary? {
            val words = SyncWording(t)
            if (!membership.joined) return null
            val wifi = membership.peer?.deviceId
            val folder = if (membership.hasFolder) membership.members else emptyList()
            val ids = (folder + listOfNotNull(wifi)).filter { it != membership.deviceId }.distinct().sorted()
            val devices = ids.map { id ->
                val route = when {
                    id == wifi && id in folder -> Route.BOTH
                    id == wifi -> Route.WIFI
                    else -> Route.FOLDER
                }
                val at = membership.peerSyncedAt[id]
                val warning = if (at != null && now - at > STALE_DAYS * DAY) t.s(NOT_SEEN) else null
                Device(id, words.shortID(id), route, at, warning)
            }
            val dot = when {
                issues.any { it.severity == SyncWording.Severity.ERROR } -> Dot.RED
                lastSyncedAt == null || now - lastSyncedAt > DAY -> Dot.ORANGE
                issues.any { it.severity == SyncWording.Severity.WARNING } || devices.any { it.warning != null } -> Dot.ORANGE
                else -> Dot.GREEN
            }
            val count = devices.size + 1
            val time = if (lastSyncedAt == null) t.s(R.string.status_sync_never) else t.s(R.string.sync_status_synced, ago(now - lastSyncedAt, t))
            return SyncStatusSummary("$time · ${t.plural(R.plurals.sync_pill_devices, count, count)}", dot, devices)
        }

        /** "just now", "2 min ago", "3 h ago", "4 days ago". */
        fun ago(seconds: Long, t: Txt): String {
            val s = maxOf(0L, seconds)
            return when {
                s < 60 -> t.s(R.string.overview_age_just_now)
                s < 3600 -> t.s(R.string.sync_status_min_ago, s / 60)
                s < DAY -> t.s(R.string.sync_status_h_ago, s / 3600)
                else -> t.plural(R.plurals.sync_ago_days, (s / DAY).toInt(), s / DAY)
            }
        }

        /** "Last synced 14:02 (12 min ago)" or "Never". */
        fun lastSyncedText(at: Long?, now: Long, t: Txt, format: DateFormat = DateFormat.getTimeInstance(DateFormat.SHORT)): String =
            if (at == null) t.s(NEVER) else t.s(R.string.sync_last_synced_at, format.format(Date(at * 1000)), ago(now - at, t))

        /** The dot's spoken name (TalkBack). */
        fun dotDescription(dot: Dot, t: Txt): String = t.s(
            when (dot) {
                Dot.GREEN -> R.string.sync_dot_green
                Dot.ORANGE -> R.string.status_sync_attention
                Dot.RED -> R.string.sync_dot_red
            },
        )
    }
}
