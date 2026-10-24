package app.localgatekeys.android.vault

/** The list's sections: Logins, Cards and notes, then everything else. */
object VaultGroup {
    private val cardsAndNotes = setOf("card", "note", "identity", "bank_account")

    /** Title and items per non-empty section, each newest first. */
    fun groups(items: List<VaultItem>): List<Pair<String, List<VaultItem>>> {
        val sorted = VaultSearch.apply(items, "", VaultFilter.All)
        return listOf(
            "Logins" to sorted.filter { it.isLogin },
            "Cards and notes" to sorted.filter { it.kind in cardsAndNotes },
            "Other" to sorted.filter { !it.isLogin && it.kind !in cardsAndNotes },
        ).filter { it.second.isNotEmpty() }
    }
}

/** The pinned Codes row: shown when Settings allow it and some item has a two-factor secret; newest first, like the list. */
object CodesRow {
    fun items(items: List<VaultItem>, showCodesRow: Boolean): List<VaultItem> =
        if (showCodesRow) VaultSearch.apply(items, "", VaultFilter.All).filter { it.hasTotp } else emptyList()
}
