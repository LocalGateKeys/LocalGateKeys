package app.localgatekeys.android.ui.sync

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncWording
import androidx.compose.runtime.staticCompositionLocalOf
import app.localgatekeys.android.pro.ProModel

/** The phone's Pro state for the Sync screen's Remove buttons (provided by `MainActivity`; null: not Pro, no upgrade sheet). */
val LocalProModel = staticCompositionLocalOf<ProModel?> { null }

/** The device-removal sheets' wording that depends on who stays (pure, so it is unit tested). */
object RemovalText {
    /** A member's name for display: the keyring name through the desktop's sanitizer, or its short id when unreadable. */
    fun displayName(id: String, membership: SyncCoordinator.Membership, words: SyncWording): String =
        words.deviceLabel(id, membership.names)

    /**
     * The names that get the new sync key: the other members that are neither removed nor unconfirmed, then this phone
     * ([thisPhone]). [name] turns a member id into its display name.
     */
    fun keepers(members: List<String>, removed: Set<String>, unconfirmed: Set<String>, thisPhone: String, name: (String) -> String): List<String> =
        members.filter { it !in removed && it !in unconfirmed }.map(name) + thisPhone

    /** The ids behind [keepers] (without this phone): what the rotation gets as its keep list. */
    fun keeperIds(members: List<String>, removed: Set<String>, unconfirmed: Set<String>): List<String> =
        members.filter { it !in removed && it !in unconfirmed }

    /** The unconfirmed members that are not being removed and so lose access with the key change. */
    fun losingAccess(members: List<String>, removed: Set<String>, unconfirmed: Set<String>, name: (String) -> String): List<String> =
        members.filter { it in unconfirmed && it !in removed }.map(name)

    /** "The new sync key goes only to: ...", plus the unconfirmed warning when some unconfirmed members stay in the group. */
    fun keepText(
        members: List<String>,
        removed: Set<String>,
        unconfirmed: Set<String>,
        thisPhone: String,
        t: Txt,
        name: (String) -> String,
    ): String {
        val keep = t.s(R.string.sync_new_key_goes_only_to, keepers(members, removed, unconfirmed, thisPhone, name).joinToString(", "))
        val losing = losingAccess(members, removed, unconfirmed, name)
        if (losing.isEmpty()) return keep
        return keep + "\n\n" + t.s(R.string.sync_not_confirmed_lose_access, losing.joinToString(", "))
    }
}
