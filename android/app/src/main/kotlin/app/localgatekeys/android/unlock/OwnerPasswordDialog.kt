package app.localgatekeys.android.unlock

import android.app.AlertDialog
import android.text.InputType
import android.widget.EditText
import android.widget.FrameLayout
import androidx.fragment.app.FragmentActivity
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.crypto.AppPasswordRecord
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume

/**
 * The app password asked over the current screen for [OwnerGate] (audit A1; the iPhone's alert in `AppPasswordGate`):
 * [reason], then [problem] (the last try's message) when there is one. The typed password as NFC UTF-8 bytes, or null
 * when cancelled or no activity is started.
 */
object OwnerPasswordDialog {
    suspend fun ask(activity: FragmentActivity?, t: Txt, reason: String, problem: String?): ByteArray? =
        withContext(Dispatchers.Main.immediate) {
            val act = activity ?: return@withContext null
            if (act.isFinishing || act.isDestroyed) return@withContext null
            suspendCancellableCoroutine { cont ->
                val field = EditText(act).apply {
                    inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                    hint = t.s(R.string.app_password_field)
                    isSingleLine = true
                }
                val pad = (20 * act.resources.displayMetrics.density).toInt()
                val box = FrameLayout(act).apply { setPadding(pad, 0, pad, 0); addView(field) }
                var answered = false
                fun answer(value: ByteArray?) {
                    if (answered) return
                    answered = true
                    field.text?.clear()
                    if (cont.isActive) cont.resume(value) else value?.fill(0)
                }
                val dialog = AlertDialog.Builder(act)
                    .setTitle(t.s(R.string.owner_check_title))
                    .setMessage(if (problem != null) "$reason\n\n$problem" else reason)
                    .setView(box)
                    .setNegativeButton(t.s(R.string.common_cancel)) { _, _ -> answer(null) }
                    .setPositiveButton(t.s(R.string.owner_check_confirm)) { _, _ ->
                        answer(AppPasswordRecord.passwordBytes(field.text ?: ""))
                    }
                    .setOnCancelListener { answer(null) }
                    .setOnDismissListener { answer(null) }
                    .create()
                cont.invokeOnCancellation { act.runOnUiThread { dialog.dismiss() } }
                dialog.show()
                field.requestFocus()
            }
        }
}
