package app.localgatekeys.android.settings

import androidx.annotation.StringRes
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The phone's setup steps (UX plan 2026-10-27 workstream 4, Android's version of the shared list). Creating the vault
 * happens before the app opens, so it is always done; the others can each be skipped.
 */
enum class SetupStep(
    val raw: String,
    @StringRes private val titleRes: Int,
    @StringRes private val textRes: Int,
    @StringRes private val actionRes: Int,
) {
    CREATE("create", R.string.setup_create_title, R.string.setup_create_text, R.string.common_continue),
    UNLOCK("unlock", R.string.setup_unlock_title, R.string.setup_unlock_text, R.string.setup_unlock_action),
    IMPORT("import", R.string.setup_import_title, R.string.setup_import_text, R.string.security_moving_import_action),
    APP_PASSWORD("app-password", R.string.setup_app_password_title, R.string.setup_app_password_text, R.string.setup_app_password_action),
    AUTOFILL("autofill", R.string.setup_autofill_title, R.string.setup_autofill_text, R.string.setup_autofill_action),
    ;

    fun title(t: Txt): String = t.s(titleRes)
    fun text(t: Txt): String = t.s(textRes)
    fun action(t: Txt): String = t.s(actionRes)

    companion object {
        fun of(raw: String): SetupStep? = entries.firstOrNull { it.raw == raw }
    }
}

/**
 * Onboarding progress on this phone ([AppSettings], not synced): the pages run once (Skip on every page, Skip setup on
 * the first); skipped steps stay on the vault's "Finish setting up · n of 5" card until done or hidden; Settings ›
 * Show setup again opens the pages and the card again. Main thread only.
 */
class Onboarding(private val settings: AppSettings, private val t: Txt) {
    private val _done = MutableStateFlow(settings.setupDone.mapNotNull(SetupStep::of).toSet() + SetupStep.CREATE)
    val done: StateFlow<Set<SetupStep>> = _done.asStateFlow()

    private val _pagesOpen = MutableStateFlow(!settings.setupSeen)
    /** The full-screen setup pages are showing. */
    val pagesOpen: StateFlow<Boolean> = _pagesOpen.asStateFlow()

    private val _cardHidden = MutableStateFlow(settings.setupCardHidden)
    val cardHidden: StateFlow<Boolean> = _cardHidden.asStateFlow()

    val remaining: List<SetupStep> get() = SetupStep.entries.filter { it !in _done.value }

    /** "Finish setting up · 3 of 5" while steps remain, the pages are closed and the card is not hidden; else null. */
    fun cardText(): String? {
        if (_pagesOpen.value || _cardHidden.value || remaining.isEmpty()) return null
        return cardText(_done.value.size, SetupStep.entries.size)
    }

    fun complete(step: SetupStep) {
        if (step in _done.value) return
        _done.value = _done.value + step
        settings.setupDone = _done.value.filter { it != SetupStep.CREATE }.map { it.raw }.toSet()
    }

    /** The pages were finished or skipped: they do not open again by themselves. */
    fun closePages() {
        _pagesOpen.value = false
        settings.setupSeen = true
    }

    fun hideCard() {
        _cardHidden.value = true
        settings.setupCardHidden = true
    }

    /** Settings › Show setup again: the pages open at the first open step and the card can show again. */
    fun showAgain() {
        _cardHidden.value = false
        settings.setupCardHidden = false
        _pagesOpen.value = true
    }

    /** The page to show first: the first step not done (the Create page when everything is done). */
    fun firstPage(): SetupStep = remaining.firstOrNull() ?: SetupStep.CREATE

    /** The step after [step] that is not done; null at the end. */
    fun next(step: SetupStep): SetupStep? = SetupStep.entries.drop(step.ordinal + 1).firstOrNull { it !in _done.value }

    override fun toString(): String = "Onboarding(done=${_done.value.size}, open=${_pagesOpen.value}, hidden=${_cardHidden.value})"

    val skip: String get() = t.s(R.string.onboarding_page_skip)
    val skipSetup: String get() = t.s(R.string.onboarding_page_skip_setup)
    val hide: String get() = t.s(R.string.home_hide)
    val showAgain: String get() = t.s(R.string.onboarding_show_again)

    fun cardText(done: Int, total: Int): String = t.s(R.string.onboarding_card_text, done, total)

    fun pageCount(step: SetupStep): String = t.s(R.string.onboarding_page_count, step.ordinal + 1, SetupStep.entries.size)
}
