package app.localgatekeys.android.vault

import app.localgatekeys.core.primitives.UnixClock

/**
 * One tile of the Codes row. The code is computed from the clock on every read, so there is no stale code to show;
 * a tile whose item changed gets a new model ([modelFor]) and so never shows or copies the old item's code.
 */
class CodeTileModel(val item: VaultItem, private val clock: UnixClock) {
    /** The code now, or null when the item has no usable secret (the tile shows a dash). */
    val state: TotpState? get() = TotpState.of(item, clock.now)

    /** Hands the plain code to [sink]; false when there is none. */
    fun copy(sink: (String) -> Unit): Boolean {
        val s = state ?: return false
        sink(s.code)
        return true
    }

    companion object {
        /** The tile keeps its model while the item is the same; an edited item gets a fresh one. */
        fun modelFor(item: VaultItem, current: CodeTileModel?, clock: UnixClock): CodeTileModel =
            if (current != null && current.item == item) current else CodeTileModel(item, clock)

        /** "123 456": a six-digit code split 3+3; other lengths are shown as they are. */
        fun grouped(code: String): String = if (code.length == 6) code.substring(0, 3) + " " + code.substring(3) else code

        /** The countdown turns orange in the last seven seconds. */
        fun isUrgent(secondsRemaining: Int): Boolean = secondsRemaining <= 7
    }
}
