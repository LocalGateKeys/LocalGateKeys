package app.localgatekeys.android.settings

import app.localgatekeys.android.pro.ItemLimit
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Settings copy (ios/App/Settings/SettingsView.swift, "iPhone" -> "phone"). */
object SettingsText {
    const val DATA_NOT_COLLECTED = "Data not collected — LocalGateKeys has no analytics and no servers."
    /**
     * The website's legal pages. They name the Windows app, the browser extensions, the helper and the iPhone only:
     * they must be updated for Android and Google Play before release (carried to Task 15).
     */
    const val PRIVACY_POLICY_URL = "https://localgatekeys.app/legal/privacy.html"
    const val LICENCE_AGREEMENT_URL = "https://localgatekeys.app/legal/eula.html"
    const val GENERATOR_FOOTER = "The generator starts from the options you used last."
    const val ERASE_BUTTON = "Erase this phone's vault"
    const val ERASE_FOOTER = "Deletes the vault on this phone only. Your PC and the sync folder are not changed."

    fun syncStatus(joined: Boolean, lastSyncedAt: Long?, shortTime: (Long) -> String): String = when {
        !joined -> "Not set up"
        lastSyncedAt == null -> "On"
        else -> "Last synced ${shortTime(lastSyncedAt)}"
    }

    fun proStatus(isPro: Boolean): String = if (isPro) "Pro is active" else "Free (up to ${ItemLimit.FREE_ITEMS} items)"

    /** "<short> (<build>)", or just the short version when there is no build number. */
    fun version(name: String, code: String): String = if (code.isEmpty()) name else "$name ($code)"
}

/** For the app's theme: dark or light for [systemDark] (System follows it). */
fun Appearance.isDark(systemDark: Boolean): Boolean = when (this) {
    Appearance.SYSTEM -> systemDark
    Appearance.LIGHT -> false
    Appearance.DARK -> true
}

/**
 * The initials field's text (Swift `InitialsField`). Typing is never rewritten (the setting keeps at most two letters,
 * so binding to it directly would turn "John" into "JO" mid-word); [submit] stores "John Doe" as "JD".
 */
class InitialsField(private val settings: AppSettings) {
    var text: String = settings.initials

    fun submit() {
        settings.initials = text
        text = settings.initials
    }
}

/**
 * Settings › Autofill (Swift `AutoFillStatusModel`): whether LocalGateKeys is the enabled autofill service, re-checked
 * whenever the screen resumes (the person usually comes back from system settings), and the "Open Autofill settings"
 * failure shown instead of swallowed.
 */
class AutofillStatusModel(
    private val isEnabled: suspend () -> Boolean,
    private val open: suspend () -> Unit,
) {
    private val _enabled = MutableStateFlow<Boolean?>(null)
    val enabled: StateFlow<Boolean?> = _enabled.asStateFlow()
    private val _openError = MutableStateFlow<String?>(null)
    val openError: StateFlow<String?> = _openError.asStateFlow()

    suspend fun refresh() {
        val on = try {
            isEnabled()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            false
        }
        _enabled.value = on
        if (on) _openError.value = null
    }

    suspend fun openSettings() {
        try {
            open()
            _openError.value = null
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            _openError.value = OPEN_FAILED_MESSAGE
        }
    }

    companion object {
        const val OPEN_FAILED_MESSAGE =
            "Autofill settings could not be opened. In the Settings app, search for Autofill service and choose LocalGateKeys."

        fun statusText(enabled: Boolean?): String = when (enabled) {
            null -> "…"
            true -> "On"
            false -> "Off"
        }
    }
}

/** A third-party notice shown under Settings › About › Acknowledgements. */
data class Acknowledgement(val name: String, val licence: String, val text: String) {
    /** The licence text is long: only the name and licence id. */
    override fun toString(): String = "Acknowledgement($name, $licence)"

    companion object {
        /** Asset paths under `assets/` of each notice's text. */
        const val APACHE = "licenses/apache-2.0.txt"

        /**
         * What the app ships (the release runtime classpath): [load] reads a bundled asset's text. AndroidX and ZXing are
         * Apache-2.0; Argon2 runs through argon2kt (MIT) over the reference C code (CC0); the core uses Bouncy Castle.
         */
        fun all(load: (String) -> String): List<Acknowledgement> = listOf(
            Acknowledgement("argon2kt", "MIT", load("licenses/argon2kt-LICENSE.txt")),
            Acknowledgement("phc-winner-argon2", "CC0-1.0", load("licenses/phc-winner-argon2-LICENSE.txt")),
            Acknowledgement("Bouncy Castle", "MIT", load("licenses/bouncycastle-LICENSE.txt")),
            Acknowledgement("AndroidX and Jetpack Compose", "Apache-2.0", load(APACHE)),
            Acknowledgement("Kotlin and kotlinx.coroutines", "Apache-2.0", load(APACHE)),
            Acknowledgement("ZXing", "Apache-2.0", load(APACHE)),
        )
    }
}
