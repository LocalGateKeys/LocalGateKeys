package app.localgatekeys.android.widget

import app.localgatekeys.android.R
import app.localgatekeys.android.codes.PinnedCode

/**
 * What the Quick Settings tile shows (sub-plan 06). The tile never shows a code: a ready tile shows the first pinned
 * code's title and copies its code when tapped. Quick Settings opens over the lock screen too, so a locked phone, a
 * locked vault or a vault past its auto-lock time all show [Locked] (no title either).
 */
sealed interface TileState {
    /** Tile.STATE_ACTIVE (true) or Tile.STATE_INACTIVE (false). */
    val active: Boolean

    /** Nothing is pinned: a tap opens the app (pin a code on an item). */
    object Empty : TileState {
        override val active = false
    }

    /** Pins exist but nothing may be read or copied now: a tap unlocks the phone, then opens the app to unlock. */
    object Locked : TileState {
        override val active = false
    }

    /** [title]'s code is copied by a tap. Never holds the code. */
    class Ready(val id: String, val title: String) : TileState {
        override val active = true
        override fun toString(): String = "Ready(id=$id)"
    }

    /** The pinned items' two-factor settings give no code: the first one's [title]; a tap opens the app. */
    class NoCode(val title: String) : TileState {
        override val active = false
        override fun toString(): String = "NoCode"
    }

    companion object {
        /**
         * The state for [codes] (from `PinnedCodes.codes`, read only while the vault is open and before its auto-lock
         * deadline). [deviceLocked]: the keyguard is showing, so nothing from the vault is shown, not even a title.
         * Ready: the first pinned code that gives digits. One pin without a read (a null code: the vault is locked or
         * its read failed) makes the whole tile [Locked], the widget's rule.
         */
        fun from(codes: List<PinnedCode>, deviceLocked: Boolean = false): TileState = when {
            codes.isEmpty() -> Empty
            deviceLocked || codes.any { it.code == null } -> Locked
            else -> codes.firstOrNull { !it.code.isNullOrEmpty() }?.let { Ready(it.id, it.title) } ?: NoCode(codes.first().title)
        }

        /**
         * The code a tap on [state] copies: the live code for its item in [codes] (read at the tap); null otherwise.
         * [shownId]: the pin whose title the tapped tile showed (null when it showed no title, e.g. on the lock screen).
         * When the first pin changed since, nothing is copied (the tile is refreshed instead), so a tap never copies a
         * code for another item than the one on screen.
         */
        fun codeToCopy(state: TileState, codes: List<PinnedCode>, shownId: String? = null): String? {
            val r = state as? Ready ?: return null
            if (shownId != null && shownId != r.id) return null
            return codes.firstOrNull { it.id == r.id }?.code?.takeIf { it.isNotEmpty() }
        }

        /** The pin id whose title [state] puts on the tile; null when the tile shows no title. */
        fun shownId(state: TileState): String? = (state as? Ready)?.id

        /**
         * The label a tile keeps once the panel closes. The system draws a tile's last label before the service can
         * refresh it, possibly on the lock screen, so a closed tile carries no title: the tile's name, no subtitle,
         * inactive.
         */
        val CLOSED_LABEL_RES: Int get() = R.string.tile_codes_name

        /** The tile's label: the title when there is one, otherwise what to do. */
        fun labelRes(state: TileState): Int? = when (state) {
            Empty -> R.string.tile_codes_empty
            Locked -> R.string.tile_codes_locked
            is Ready, is NoCode -> null
        }

        /** The tile's second line (Android 10+). */
        fun subtitleRes(state: TileState): Int = when (state) {
            Empty -> R.string.tile_codes_name
            Locked -> R.string.tile_codes_locked_subtitle
            is Ready -> R.string.tile_codes_tap_to_copy
            is NoCode -> R.string.tile_codes_no_code
        }
    }
}
