package app.localgatekeys.android.vault

import app.localgatekeys.android.R
import app.localgatekeys.android.access.AccessGate
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.core.sync.StoreSnapshot

/** One entry of the long-press menu on a row. [confirmation] is the toast after a copy (null: nothing is copied). */
data class QuickAction(val kind: Kind, @StringRes val label: Int, @StringRes val confirmation: Int?) {
    enum class Kind { COPY_USERNAME, COPY_PASSWORD, COPY_CODE, OPEN_WEBSITE }
}

object QuickActions {
    /** Copy what the item holds without opening it, and open its website. */
    fun forItem(item: VaultItem, today: String = AccessGate.today()): List<QuickAction> = buildList {
        // Secrets of a login with access rules are copied from its detail screen only (owner check, copy once).
        val secrets = AccessGate.mayQuickCopy(item.record, today)
        // View only on phones: nothing is copied from it, the username neither (as the detail screen and the iPhone).
        val viewOnly = item.isLogin && AccessGate.effective(item.record, today).phoneView
        if (item.username.isNotEmpty() && !viewOnly) add(QuickAction(QuickAction.Kind.COPY_USERNAME, R.string.detail_pane_copy_username, R.string.quick_username_copied))
        if (secrets && item.copyablePassword != null) add(QuickAction(QuickAction.Kind.COPY_PASSWORD, R.string.detail_pane_copy_password, R.string.quick_password_copied))
        if (secrets && item.hasTotp) add(QuickAction(QuickAction.Kind.COPY_CODE, R.string.detail_pane_copy_code, R.string.quick_code_copied))
        if (item.openableUrl != null) add(QuickAction(QuickAction.Kind.OPEN_WEBSITE, R.string.detail_pane_open_website, null))
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
