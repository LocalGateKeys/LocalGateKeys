package app.localgatekeys.android.pro

import app.localgatekeys.core.json.JsonValue

/** Pro-only features. On the phone only two-factor codes need a check here. */
object ProFeatures {
    val totpMessage: String = "Adding or changing two-factor codes needs LocalGateKeys Pro. Codes you already saved keep working."

    /** Whether saving [new] over [old] needs Pro: adding or changing a code does; keeping or removing one never does. */
    fun totpChangeNeedsPro(new: JsonValue?, old: JsonValue?): Boolean {
        if (new == null || new == JsonValue.Null) return false
        return new != old
    }
}
