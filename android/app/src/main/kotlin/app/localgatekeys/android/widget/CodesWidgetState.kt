package app.localgatekeys.android.widget

import app.localgatekeys.android.codes.PinnedCode
import app.localgatekeys.android.vault.CodeTileModel

/** What the codes widget shows. */
sealed interface CodesWidgetState {
    /** Nothing is pinned: how to pin a code. */
    object Empty : CodesWidgetState

    /** Pins exist but no digits may show: the vault is locked, past its auto-lock time, or the screen is off/locked. */
    object Locked : CodesWidgetState

    /**
     * [Locked] while Auto-lock is "Immediately": the vault locks whenever the app leaves the screen, so unlocking
     * cannot help; the widget says to set Auto-lock to 1 minute or longer instead.
     */
    object LockedImmediately : CodesWidgetState

    /** The current codes, at most four, each valid until the next refresh at its period boundary. */
    class Codes(val rows: List<Row>) : CodesWidgetState {
        override fun toString(): String = "Codes(rows=${rows.size})"
    }

    /** [code] is grouped for reading ("123 456"); "—" when the item's settings give no code. Never shows the code. */
    class Row(val id: String, val title: String, val code: String) {
        override fun toString(): String = "Row(id=$id)"
    }

    companion object {
        /**
         * The state for [codes] (from `PinnedCodes.codes`). [visible]: the vault is open and before its lock deadline,
         * and the screen is on and not behind the keyguard; otherwise pinned codes show as [Locked], or as
         * [LockedImmediately] when [lockImmediately] (Auto-lock "Immediately").
         */
        fun of(codes: List<PinnedCode>, visible: Boolean, lockImmediately: Boolean = false): CodesWidgetState = when {
            codes.isEmpty() -> Empty
            !visible || codes.any { it.code == null } -> if (lockImmediately) LockedImmediately else Locked
            else -> Codes(
                codes.map { c ->
                    val code = c.code.orEmpty()
                    Row(c.id, c.title, if (code.isEmpty()) "—" else CodeTileModel.grouped(code))
                },
            )
        }

        /**
         * Milliseconds from [nowMillis] until the widget must refresh: the first period boundary among [codes] (an
         * expired code is never left on screen) or the lock [deadline] (Unix seconds), whichever is first; at least
         * 100 ms. Null when nothing time-bound is shown.
         */
        fun nextRefreshDelay(codes: List<PinnedCode>, deadline: Long?, nowMillis: Long): Long? {
            val now = nowMillis / 1000
            var next = Long.MAX_VALUE
            for (c in codes) if (!c.code.isNullOrEmpty() && c.secondsRemaining > 0) next = minOf(next, (now + c.secondsRemaining) * 1000)
            if (deadline != null && deadline != Long.MAX_VALUE) next = minOf(next, deadline * 1000)
            if (next == Long.MAX_VALUE) return null
            return maxOf(next - nowMillis + MARGIN_MILLIS, MARGIN_MILLIS)
        }

        /** Refreshes land just after the boundary, so the new code is already the current one. */
        private const val MARGIN_MILLIS = 100L
    }
}
