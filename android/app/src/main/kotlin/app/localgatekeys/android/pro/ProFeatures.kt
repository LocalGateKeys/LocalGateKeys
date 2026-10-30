package app.localgatekeys.android.pro

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.json.JsonValue

/** Pro-only features. On the phone only two-factor codes need a check here. */
object ProFeatures {
    /** Shown under the 2FA field; the editor tells it apart by `EditorState.totpNeedsPro`, never by this text. */
    fun totpMessage(t: Txt): String = t.s(R.string.login_editor_needs_pro)

    /** Whether saving [new] over [old] needs Pro: adding or changing a code does; keeping or removing one never does. */
    fun totpChangeNeedsPro(new: JsonValue?, old: JsonValue?): Boolean {
        if (new == null || new == JsonValue.Null) return false
        return new != old
    }
}
