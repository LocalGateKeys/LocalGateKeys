package app.localgatekeys.android.settings

import app.localgatekeys.android.R
import app.localgatekeys.android.backup.BackupPasswordCheck
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.crypto.AppPasswordRecord
import app.localgatekeys.core.crypto.Bip39
import app.localgatekeys.core.password.StrengthEstimator
import app.localgatekeys.core.primitives.RandomSource

/**
 * What Settings > Security needs for the app password (Task 7). MainActivity builds it over
 * [app.localgatekeys.android.unlock.AppPasswordController] and the open vault's local key. Passwords cross as the
 * typed text only and are never stored.
 */
class AppPasswordSeams(
    val isOn: suspend () -> Boolean,
    val biometricOn: suspend () -> Boolean,
    /** The phone has a strong biometric enrolled (the shortcut can be offered). */
    val biometricAvailable: () -> Boolean,
    val prepare: suspend (password: String) -> AppPasswordRecord.Created,
    /** False when the fingerprint shortcut could not be set (the password is on anyway). */
    val commit: suspend (AppPasswordRecord.Created, biometric: Boolean) -> Boolean,
    val change: suspend (current: String, new: String) -> Unit,
    val turnOff: suspend (current: String) -> Unit,
    val setBiometric: suspend (Boolean) -> Unit,
) {
    override fun toString(): String = "AppPasswordSeams"
}

/** The rules and words of the app-password screens, free of Compose. */
class AppPasswordText(private val t: Txt) {
    val section: String get() = t.s(R.string.app_password_section)
    val toggle: String get() = t.s(R.string.app_password_toggle)
    val biometricToggle: String get() = t.s(R.string.app_password_biometric)
    val change: String get() = t.s(R.string.app_password_change)
    val footerOff: String get() = t.s(R.string.app_password_footer_off)
    val footerOn: String get() = t.s(R.string.app_password_footer_on)
    val phraseWarning: String get() = t.s(R.string.app_password_phrase_warning)

    /**
     * Why [password] cannot be used (null: it can): the desktop strength rule already used for backup passwords
     * ([BackupPasswordCheck]: 12+ characters, `estimate_strength` score 3+, both entries equal).
     */
    fun problem(password: String, confirm: String, strength: StrengthEstimator = BackupPasswordCheck.estimator): String? =
        BackupPasswordCheck.problem(password, confirm, t, strength)

    /** The strength label to show under the field. */
    fun label(password: String, strength: StrengthEstimator = BackupPasswordCheck.estimator): String =
        BackupPasswordCheck.check(password, password, t, strength).label

    companion object {
        /** Three distinct word positions (0-based, ascending) to type back. */
        fun confirmPositions(random: RandomSource): List<Int> {
            val picked = sortedSetOf<Int>()
            while (picked.size < 3) {
                val b = random.bytes(1)[0].toInt() and 0xff
                if (b < 240) picked += b % Bip39.WORD_COUNT // no modulo bias: 240 = 10 x 24
            }
            return picked.toList()
        }

        /** The typed words match the phrase at [positions] (case and surrounding spaces ignored). */
        fun confirms(phrase: String, positions: List<Int>, typed: List<String>): Boolean {
            val words = phrase.split(" ")
            return positions.size == typed.size && positions.indices.all { words[positions[it]] == typed[it].trim().lowercase() }
        }
    }
}
