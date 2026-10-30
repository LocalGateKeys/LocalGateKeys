package app.localgatekeys.android.vault

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.core.primitives.Scalars
import java.text.Normalizer

/** The list's sort options (`scripts/make_sort_vectors.py` names in [raw]). */
enum class VaultSortOption(val raw: String, @StringRes val label: Int) {
    TITLE_ASC("title_asc", R.string.sort_menu_title_asc),
    TITLE_DESC("title_desc", R.string.sort_menu_title_desc),
    MODIFIED_DESC("modified_desc", R.string.sort_menu_modified),
    CREATED_DESC("created_desc", R.string.sort_menu_created),
    ;

    companion object {
        fun of(raw: String?): VaultSortOption? = entries.firstOrNull { it.raw == raw }
    }
}

/**
 * The vault list sort rule shared by every app (version 1, pinned by `tests/vectors/vault_sort/cases.json`): title key
 * is NFKD without combining marks (Mn), lowercased, compared by code points; missing timestamps count as 0; ties go by
 * title key, then id, ascending (Z–A reverses only the title compare). [favoritesFirst] puts favorites first, each group
 * sorted the same way. Only the plain list is sorted: a search keeps its relevance order.
 */
data class VaultSort(val option: VaultSortOption = VaultSortOption.MODIFIED_DESC, val favoritesFirst: Boolean = false) {
    fun apply(items: List<VaultItem>): List<VaultItem> {
        val keyed = items.map { it to titleKey(it.title) }
        val byTitle = Comparator<Pair<VaultItem, String>> { a, b -> Scalars.compare(a.second, b.second) }
        val byId = Comparator<Pair<VaultItem, String>> { a, b -> Scalars.compare(a.first.id, b.first.id) }
        val base = when (option) {
            VaultSortOption.TITLE_ASC -> byTitle.then(byId)
            VaultSortOption.TITLE_DESC -> byTitle.reversed().then(byId)
            VaultSortOption.MODIFIED_DESC -> compareByDescending<Pair<VaultItem, String>> { it.first.updatedAt }.then(byTitle).then(byId)
            VaultSortOption.CREATED_DESC -> compareByDescending<Pair<VaultItem, String>> { it.first.createdAt }.then(byTitle).then(byId)
        }
        val sorted = keyed.sortedWith(base).map { it.first }
        return if (favoritesFirst) sorted.filter { it.favorite } + sorted.filter { !it.favorite } else sorted
    }

    companion object {
        private val marks = Regex("""\p{Mn}+""")

        /** NFKD, combining marks (Mn) dropped, lowercased (Python `str.lower`, simple case mapping per code point). */
        fun titleKey(title: String): String {
            val stripped = marks.replace(Normalizer.normalize(title, Normalizer.Form.NFKD), "")
            val out = StringBuilder(stripped.length)
            var i = 0
            while (i < stripped.length) {
                val cp = stripped.codePointAt(i)
                i += Character.charCount(cp)
                out.appendCodePoint(Character.toLowerCase(cp))
            }
            return out.toString()
        }
    }
}
