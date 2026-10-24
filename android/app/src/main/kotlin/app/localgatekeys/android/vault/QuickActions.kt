package app.localgatekeys.android.vault

import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.core.sync.StoreSnapshot

/** One entry of the long-press menu on a row. [confirmation] is the toast after a copy (null: nothing is copied). */
data class QuickAction(val kind: Kind, val label: String, val confirmation: String?) {
    enum class Kind { COPY_USERNAME, COPY_PASSWORD, COPY_CODE, OPEN_WEBSITE }
}

object QuickActions {
    /** Copy what the item holds without opening it, and open its website. */
    fun forItem(item: VaultItem): List<QuickAction> = buildList {
        if (item.username.isNotEmpty()) add(QuickAction(QuickAction.Kind.COPY_USERNAME, "Copy username", "Username copied"))
        if (item.copyablePassword != null) add(QuickAction(QuickAction.Kind.COPY_PASSWORD, "Copy password", "Password copied"))
        if (item.hasTotp) add(QuickAction(QuickAction.Kind.COPY_CODE, "Copy 2FA code", "Code copied"))
        if (item.openableUrl != null) add(QuickAction(QuickAction.Kind.OPEN_WEBSITE, "Open website", null))
    }
}

/** Creating needs a free slot or Pro; existing items are never blocked. */
object NewItemGate {
    enum class Decision { OPEN_EDITOR, UPGRADE }

    fun decide(snapshot: StoreSnapshot?, isPro: Boolean): Decision =
        if (snapshot == null || ItemLimit.allows(ItemLimit.Action.CREATE, snapshot, isPro)) Decision.OPEN_EDITOR else Decision.UPGRADE
}

/**
 * How the screens copy: MainActivity routes it to the shared secret clipboard (sensitive, expiring, cleared on lock)
 * and the copy confirmation.
 */
fun interface Copier {
    /** Copies [text]; [confirmation] is what the user is told ("Code copied"). */
    fun copy(text: String, confirmation: String)
}
