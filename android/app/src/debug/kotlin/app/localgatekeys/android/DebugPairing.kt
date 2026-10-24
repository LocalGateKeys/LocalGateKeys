package app.localgatekeys.android

import android.content.Intent

/**
 * Debug builds only (Ruling D; the release source set has a stub that ignores it): `lgk.debug.pairing=<QR text>` hands
 * the Sync tab a pairing code as if the camera had scanned it, so the emulator can pair without a camera. The text is
 * joined once per activity, after the unlock.
 */
object DebugPairing {
    const val EXTRA = "lgk.debug.pairing"

    fun textFrom(intent: Intent?): String? = text(intent?.getStringExtra(EXTRA))

    /** The trimmed code, or null when there is none. */
    fun text(extra: String?): String? = extra?.trim()?.takeIf { it.isNotEmpty() }
}
