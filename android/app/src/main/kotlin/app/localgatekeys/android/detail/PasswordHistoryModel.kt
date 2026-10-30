package app.localgatekeys.android.detail

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.records.PasswordHistory
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The login detail's Password history (UX plan workstream 8): past passwords masked; Reveal asks the owner once
 * ([confirmOwner]: fingerprint, face or screen lock) and then shows them all until the screen closes; Copy goes through
 * the secret clipboard. Restore is the screen's (it writes through the store). Main thread only.
 */
class PasswordHistoryModel(
    item: VaultItem,
    private val clipboard: SecretClipboard,
    private val confirmOwner: (suspend () -> Boolean)? = null,
) {
    val entries: List<PasswordHistory.Entry> = if (item.isLogin) PasswordHistory.entries(item.record) else emptyList()

    private val _revealed = MutableStateFlow(false)
    val revealed: StateFlow<Boolean> = _revealed.asStateFlow()

    /** Reveal needs the owner check; without one (no seam) nothing can be revealed. */
    val canReveal: Boolean get() = confirmOwner != null

    fun display(index: Int): String = if (_revealed.value) entries[index].password else ItemDetailModel.MASK

    /** Shows the passwords after a passed owner check; hides them again when already shown. */
    suspend fun toggleReveal(): Boolean {
        if (_revealed.value) {
            _revealed.value = false
            return true
        }
        val check = confirmOwner ?: return false
        val ok = try {
            check()
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            throw e
        } catch (e: Exception) {
            false
        }
        _revealed.value = ok
        return ok
    }

    fun copy(index: Int) {
        clipboard.copy(entries[index].password)
    }

    override fun toString(): String = "PasswordHistoryModel(entries=${entries.size}, revealed=${_revealed.value})"

    companion object {
        @StringRes val TITLE = R.string.login_more_password_history
        @StringRes val RESTORE = R.string.login_more_restore_this
        @StringRes val RESTORE_TITLE = R.string.password_history_restore_title
        @StringRes val RESTORE_TEXT = R.string.password_history_restore_text
        @StringRes val RESTORE_FAILED = R.string.password_history_restore_failed
        @StringRes val REVEAL_REASON = R.string.password_history_reveal_reason

        /** "Password history (3)": the detail row. */
        fun rowLabel(count: Int, t: Txt): String = t.s(R.string.password_history_row, count)

        /** "Changed 3 Jan 2026, 10:15": the date in the person's locale. */
        fun changedText(
            at: Long, t: Txt, format: DateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT),
        ): String = t.s(R.string.password_history_changed, format.format(Date(at * 1000)))
    }
}
