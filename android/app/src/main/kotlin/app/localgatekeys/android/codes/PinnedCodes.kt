package app.localgatekeys.android.codes

import app.localgatekeys.android.access.AccessGate
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.vault.TotpState
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.TravelMode

/**
 * The open vault's records for the codes widget, or null when the vault is locked (or counts as locked: past the
 * auto-lock deadline). Never cached: each call reads the encrypted store through the key the app process holds.
 */
fun interface StoreSnapshotProvider {
    fun snapshot(): StoreSnapshot?
}

/**
 * One pinned code. [code] null: the vault is locked (no title either, the titles live in the vault too). [code]
 * empty: the item's two-factor settings do not give a code (the widget shows a dash). Never shows the code.
 */
data class PinnedCode(val id: String, val title: String, val code: String?, val secondsRemaining: Int) {
    override fun toString(): String = "PinnedCode(id=$id, shown=${code != null}, secondsRemaining=$secondsRemaining)"
}

/** What a pin tap did. */
enum class PinResult { PINNED, UNPINNED, NEEDS_PRO, FULL }

/**
 * The home-screen widget's pinned codes (Android side of sub-plan 06).
 *
 * Only item ids are stored ([AppSettings.pinnedCodeIds], this phone only). The secrets and titles are never copied
 * out of the vault: [codes] reads them from the store while the app process holds the vault key, so they are as
 * protected as the vault itself (the vault key wrapping) and a locked vault shows nothing.
 *
 * Rules: pinning is Pro, unpinning is always allowed, showing an already pinned code is not re-gated; at most
 * [MAX_PINS] ids in pin order; a pin whose item was deleted or lost its two-factor secret is dropped at the next read
 * of the open vault (every commit, sync and unlock reads it).
 *
 * Sub-plan 08: while [frozen] (a duress session is open) the pins belong to the real vault, whose items the open store
 * does not hold: the widget shows them as locked, nothing is pruned and no pin changes (a pin tap ends as [PinResult.FULL]).
 */
class PinnedCodes(
    private val settings: AppSettings,
    private val store: StoreSnapshotProvider,
    private val frozen: () -> Boolean = { false },
    /**
     * Travel mode on this phone (feature pack section 2.3): hidden items are left out, their pins kept for later.
     * Null (the setting cannot be read) leaves every code out (fail closed, scan A-M4).
     */
    private val travel: () -> TravelMode.Setting? = { TravelMode.Setting.OFF },
) {
    private val lock = Any()

    /** The pinned ids in pin order (cleaned: no duplicates, no malformed ids, at most [MAX_PINS]). */
    fun ids(): List<String> = synchronized(lock) { clean(settings.pinnedCodeIds) }

    fun isPinned(id: String): Boolean = id in ids()

    /** True when [id] was pinned or unpinned; false when pinning needs Pro, the list is full or the id is malformed. */
    fun toggle(id: String, isPro: Boolean): Boolean = pin(id, isPro).let { it == PinResult.PINNED || it == PinResult.UNPINNED }

    fun pin(id: String, isPro: Boolean): PinResult = synchronized(lock) {
        if (frozen()) return if (isPro) PinResult.FULL else PinResult.NEEDS_PRO
        val current = clean(settings.pinnedCodeIds)
        if (id in current) {
            settings.pinnedCodeIds = current - id
            return PinResult.UNPINNED
        }
        if (!isPro) return PinResult.NEEDS_PRO
        if (current.size >= MAX_PINS || !valid(id)) return PinResult.FULL
        settings.pinnedCodeIds = current + id
        PinResult.PINNED
    }

    /**
     * The pinned codes at [now] (Unix seconds). Locked: one entry per pin with a null code and no title. Unlocked:
     * the live pinned items with their current code; pins whose item is gone or has no two-factor secret are removed
     * from the list first. Empty when nothing is pinned.
     */
    fun codes(now: Long): List<PinnedCode> {
        val pins = ids()
        if (pins.isEmpty()) return emptyList()
        if (frozen()) return pins.map { PinnedCode(it, "", null, 0) }
        val snap = try {
            store.snapshot()
        } catch (e: Exception) {
            null // a store that is closing or unreadable counts as locked; nothing is pruned
        }
        if (snap == null) return pins.map { PinnedCode(it, "", null, 0) }
        val items = VaultItem.items(snap).associateBy { it.id }
        val live = pins.filter { items[it]?.hasTotp == true }
        if (live != pins) prune(pins, live)
        val setting = try {
            travel()
        } catch (e: Exception) {
            null
        } ?: return emptyList()
        val hidden = TravelMode.hiddenIds(snap, setting)
        val today = AccessGate.today()
        // A login with access rules (re-authenticate, copy once, view only...) keeps its pin but shows no code here.
        return live.filter { it !in hidden && AccessGate.mayQuickCopy(items.getValue(it).record, today) }.map { id ->
            val item = items.getValue(id)
            val state = TotpState.of(item, now)
            PinnedCode(id, title(item), state?.code ?: "", state?.secondsRemaining ?: 0)
        }
    }

    /** Writes [live] only when the stored list is still [seen] (a pin made meanwhile is kept). */
    private fun prune(seen: List<String>, live: List<String>) = synchronized(lock) {
        val current = clean(settings.pinnedCodeIds)
        settings.pinnedCodeIds = if (current == seen) live else current.filter { it !in seen || it in live }
    }

    private fun title(item: VaultItem): String =
        VaultItem.safeDisplay(item.title.ifBlank { item.target }.ifBlank { item.username }, TITLE_LENGTH).trim()

    companion object {
        /** The widget shows at most four codes (Global Constraints). */
        const val MAX_PINS = 4

        private const val TITLE_LENGTH = 40

        /** Ids are stored comma separated: no separators, no whitespace or control characters, a sane length. */
        internal fun valid(id: String): Boolean =
            id.isNotEmpty() && id.length <= 128 && id.none { it == ',' || it.isWhitespace() || it.isISOControl() }

        internal fun clean(ids: List<String>): List<String> = ids.filter(::valid).distinct().take(MAX_PINS)
    }
}
