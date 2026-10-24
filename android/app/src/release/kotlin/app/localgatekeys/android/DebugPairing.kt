package app.localgatekeys.android

import android.content.Intent

/** Release builds take no pairing code from the launch intent (the debug source set has the real one). */
object DebugPairing {
    @Suppress("UNUSED_PARAMETER")
    fun textFrom(intent: Intent?): String? = null
}
