package app.localgatekeys.android.vault

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes

/** The list's sections: Logins, Cards and notes, then everything else. */
object VaultGroup {
    private val cardsAndNotes = setOf("card", "note", "identity", "bank_account")

    /** Title (a string resource) and items per non-empty section, each in the chosen order (newest modified first by default). */
    fun groups(items: List<VaultItem>, sort: VaultSort = VaultSort()): List<Pair<Int, List<VaultItem>>> {
        val sorted = sort.apply(items)
        return listOf(
            R.string.nav_type_web to sorted.filter { it.isLogin },
            R.string.group_cards_and_notes to sorted.filter { it.kind in cardsAndNotes },
            R.string.group_other to sorted.filter { !it.isLogin && it.kind !in cardsAndNotes },
        ).filter { it.second.isNotEmpty() }
    }
}

/** The pinned Codes row: shown when Settings allow it and some item has a two-factor secret; newest first, like the list. */
object CodesRow {
    fun items(items: List<VaultItem>, showCodesRow: Boolean, t: Txt): List<VaultItem> =
        if (showCodesRow) VaultSearch.apply(items, "", VaultFilter.All, t).filter { it.hasTotp } else emptyList()
}
