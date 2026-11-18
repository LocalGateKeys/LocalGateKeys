package app.localgatekeys.android.widget

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import app.localgatekeys.android.LgkApp
import app.localgatekeys.android.MainActivity
import app.localgatekeys.android.R
import app.localgatekeys.android.codes.PinnedCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The Quick Settings tile (sub-plan 06): a tap copies the first pinned code, a long press opens the app's Codes row.
 *
 * Quick Settings opens over the lock screen, so the rules are the codes widget's and stricter:
 * - Codes and titles are read only while this process holds the vault key, before its auto-lock deadline, and only
 *   with the keyguard gone ([isLocked]). A process the system starts just for the tile has no vault key and reads
 *   nothing: the pin list alone says [TileState.Locked] or [TileState.Empty].
 * - On the lock screen the tile shows the locked state (no title) and a tap first asks the system to unlock the phone
 *   ([unlockAndRun]); only then is the state read again and a code copied, or the app opened to unlock the vault.
 * - The code is computed at the tap (never a stale one) and copied through the app's one [LgkApp.clipboard]: marked
 *   sensitive, cleared after the Settings timeout and at lock (Ruling 14's ownership check applies).
 * - The tile never shows a code. While a title shows, a timer re-reads at the auto-lock deadline; when the panel
 *   closes the tile is reset to its name (the system draws the last label first at the next pull-down), and every
 *   lock and erase asks the system for a refresh ([requestRefresh]).
 * - A tap copies the code of the pin whose title was shown; if the first pin changed since, it only refreshes.
 *
 * Exported only to the system (BIND_QUICK_SETTINGS_TILE); nothing here is stored, logged or sent anywhere.
 */
class CopyCodeTileService : TileService() {
    private val handler = Handler(Looper.getMainLooper())
    private val refreshAtDeadline = Runnable { refresh() }
    private var refreshJob: Job? = null
    private var listening = false

    /** The pin whose title the tile shows now; null when it shows none. */
    private var shownId: String? = null

    /** True after a copy, until the panel closes: the subtitle says "Copied". */
    private var copied = false

    private val app: LgkApp get() = application as LgkApp

    override fun onStartListening() {
        super.onStartListening()
        listening = true
        copied = false
        refresh()
    }

    override fun onStopListening() {
        listening = false
        handler.removeCallbacks(refreshAtDeadline)
        refreshJob?.cancel(); refreshJob = null
        // The system keeps the last label and draws it at the next pull-down (maybe on the lock screen) before this
        // service refreshes it: leave no title behind.
        qsTile?.let { tile ->
            tile.state = Tile.STATE_INACTIVE
            tile.label = text(TileState.CLOSED_LABEL_RES)
            tile.subtitle = null
            tile.updateTile()
        }
        shownId = null
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        val shown = shownId
        // The lock screen never copies or reveals: the system asks for the phone's unlock first.
        // The callback runs once the keyguard is dismissed, but isLocked can still read true for a moment then: the
        // read after it must not take the phone for locked (that showed Locked again and copied nothing).
        if (isLocked) unlockAndRun { tap(shown, deviceUnlocked = true) } else tap(shown)
    }

    /** A string in the app's current language (a language change shows at once, without a restart). */
    private fun text(res: Int): String = appLocaleContext(this).getString(res)

    private fun refresh() {
        refreshJob?.cancel()
        refreshJob = app.appScope.launch { show(read()) }
    }

    /** [shown]: the pin whose title the tapped tile showed; a different first pin now only refreshes the tile. */
    private fun tap(shown: String?, deviceUnlocked: Boolean = false) {
        app.appScope.launch {
            val read = read(deviceUnlocked)
            val code = TileState.codeToCopy(read.state, read.codes, shown)
            when {
                code != null -> {
                    app.clipboard.copy(code)
                    copied = true
                    show(read)
                }
                read.state is TileState.Ready -> show(read) // the pins changed since: show the new first pin
                else -> {
                    show(read)
                    openApp()
                }
            }
        }
    }

    private class Read(val state: TileState, val codes: List<PinnedCode>, val deadline: Long?) {
        override fun toString(): String = "Read(state=$state)"
    }

    /** The current state; the vault is read (off the main thread) only when the phone and the vault are both unlocked. */
    private suspend fun read(deviceUnlocked: Boolean = false): Read {
        val deviceLocked = !deviceUnlocked && isLocked
        val deadline = app.vaultLockDeadline()
        val now = System.currentTimeMillis() / 1000
        val codes = if (!deviceLocked && deadline != null && now < deadline) {
            withContext(Dispatchers.IO) { app.pinnedCodes.codes(now) }
        } else {
            app.pinnedCodes.ids().map { PinnedCode(it, "", null, 0) }
        }
        return Read(TileState.from(codes, deviceLocked), codes, deadline)
    }

    private fun show(read: Read) {
        handler.removeCallbacks(refreshAtDeadline)
        if (!listening) return
        val tile = qsTile ?: return
        val state = read.state
        shownId = TileState.shownId(state)
        tile.state = if (state.active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = TileState.labelRes(state)?.let(::text) ?: when (state) {
            is TileState.Ready -> state.title
            is TileState.NoCode -> state.title
            else -> text(R.string.tile_codes_name)
        }
        tile.subtitle = text(if (copied && state is TileState.Ready) R.string.tile_codes_copied else TileState.subtitleRes(state))
        tile.updateTile()
        // A shown title goes at the auto-lock deadline even while the panel stays open.
        val deadline = read.deadline
        if ((state is TileState.Ready || state is TileState.NoCode) && deadline != null && deadline != Long.MAX_VALUE) {
            handler.postDelayed(refreshAtDeadline, maxOf(deadline * 1000 - System.currentTimeMillis() + 100, 100))
        }
    }

    companion object {
        /** Asks the system to bind the tile and re-render it (a lock or an erase); harmless when it is not added. */
        fun requestRefresh(context: Context) {
            try {
                requestListeningState(context, ComponentName(context, CopyCodeTileService::class.java))
            } catch (e: RuntimeException) {
                // not added, or the system refused: the closed tile carries no title anyway
            }
        }
    }

    /** Opens the app the way its launcher icon does (it asks for the vault's unlock itself) and closes the panel. */
    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java)
            .setAction(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
        } catch (e: RuntimeException) {
            // The system refused the start: the tile stays as it is.
        }
    }
}
