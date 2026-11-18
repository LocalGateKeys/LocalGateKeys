package app.localgatekeys.wear

import android.app.KeyguardManager
import android.content.Context
import androidx.concurrent.futures.ResolvableFuture
import androidx.wear.protolayout.LayoutElementBuilders
import androidx.wear.protolayout.ResourceBuilders
import androidx.wear.protolayout.TimelineBuilders
import androidx.wear.tiles.EventBuilders
import androidx.wear.tiles.RequestBuilders
import androidx.wear.tiles.TileBuilders
import androidx.wear.tiles.TileService
import com.google.common.util.concurrent.ListenableFuture

/**
 * Sub-plan 06: the pinned-codes tile. Bound only by the system's tile host (BIND_TILE_PROVIDER, see the manifest).
 *
 * It draws what [WatchCodesStore] holds: codes only while they are valid (the timeline switches to hidden digits at
 * the earliest expiry, so no expired code stays on screen), the last known titles with their age when the phone is
 * out of reach, and no titles at all after the phone's vault locked. A locked watch never gets digits. Being shown,
 * added or tapped asks the phone for fresh codes.
 */
class CodesTileService : TileService() {

    override fun onTileRequest(requestParams: RequestBuilders.TileRequest): ListenableFuture<TileBuilders.Tile> {
        if (requestParams.currentState.lastClickableId == CodesTileLayout.CLICK_REFRESH) PhoneCodesClient.requestCodes(this)
        return immediate(tile(this, System.currentTimeMillis()))
    }

    override fun onTileResourcesRequest(requestParams: RequestBuilders.ResourcesRequest): ListenableFuture<ResourceBuilders.Resources> =
        immediate(ResourceBuilders.Resources.Builder().setVersion(RESOURCES_VERSION).build())

    override fun onTileAddEvent(requestParams: EventBuilders.TileAddEvent) {
        PhoneCodesClient.requestCodes(this)
    }

    override fun onTileEnterEvent(requestParams: EventBuilders.TileEnterEvent) {
        PhoneCodesClient.requestCodes(this)
    }

    companion object {
        private const val RESOURCES_VERSION = "1"

        /** The system asks again this often; a message from the phone asks at once. */
        const val FRESHNESS_MILLIS = 30_000L

        private fun <T> immediate(value: T): ListenableFuture<T> = ResolvableFuture.create<T>().also { it.set(value) }

        fun tile(context: Context, nowMillis: Long): TileBuilders.Tile {
            val input = WatchCodesStore.of(context).input()
            val watchLocked = context.getSystemService(KeyguardManager::class.java)?.isDeviceLocked != false
            val texts = ResourceTexts(context)
            val model = CodesTileLayout.model(input, watchLocked)
            val timeline = TimelineBuilders.Timeline.Builder()
            val known = input as? TileInput.Known
            val shownFor = known?.codes?.filter { it.code?.isNotEmpty() == true }?.minOfOrNull { it.validForMillis }
            if (known != null && shownFor != null && shownFor > 0 && model.rows.any { it.shown }) {
                val end = nowMillis + shownFor
                timeline.addTimelineEntry(entry(CodesTileLayout.layout(model, texts), nowMillis, end))
                // From the earliest expiry: the same titles, digits hidden, until the phone sends new codes.
                val hidden = CodesTileLayout.model(
                    TileInput.Known(known.codes.map { PinnedCode(it.title, it.code?.takeIf(String::isEmpty)) }, known.ageSeconds),
                    watchLocked,
                )
                timeline.addTimelineEntry(entry(CodesTileLayout.layout(hidden, texts), end, null))
            } else {
                timeline.addTimelineEntry(entry(CodesTileLayout.layout(model, texts), null, null))
            }
            return TileBuilders.Tile.Builder()
                .setResourcesVersion(RESOURCES_VERSION)
                .setFreshnessIntervalMillis(FRESHNESS_MILLIS)
                .setTileTimeline(timeline.build())
                .build()
        }

        private fun entry(root: LayoutElementBuilders.LayoutElement, start: Long?, end: Long?): TimelineBuilders.TimelineEntry {
            val b = TimelineBuilders.TimelineEntry.Builder().setLayout(LayoutElementBuilders.Layout.fromLayoutElement(root))
            if (start != null || end != null) {
                val interval = TimelineBuilders.TimeInterval.Builder()
                if (start != null) interval.setStartMillis(start)
                if (end != null) interval.setEndMillis(end)
                b.setValidity(interval.build())
            }
            return b.build()
        }
    }
}

/** The tile's words from this app's string resources (the watch's language). */
class ResourceTexts(private val context: Context) : TileTexts {
    override fun noData() = context.getString(R.string.tile_no_data)
    override fun locked() = context.getString(R.string.tile_locked)
    override fun lockedImmediately() = context.getString(R.string.tile_locked_immediately)
    override fun empty() = context.getString(R.string.tile_empty)
    override fun watchLocked() = context.getString(R.string.tile_watch_locked)
    override fun updatedNow() = context.getString(R.string.tile_updated_now)
    override fun updatedMinutes(n: Long) = context.getString(R.string.tile_updated_minutes, n)
    override fun updatedHours(n: Long) = context.getString(R.string.tile_updated_hours, n)
    override fun updatedDays(n: Long) = context.getString(R.string.tile_updated_days, n)
}
