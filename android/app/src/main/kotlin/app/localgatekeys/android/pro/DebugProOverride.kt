package app.localgatekeys.android.pro

import java.io.File

/**
 * Debug builds only: Pro without a Play purchase, for emulator testing. On when the marker file exists in the app's
 * files folder, which only `adb shell run-as` can create (it works on debuggable builds only):
 *
 *     adb shell run-as app.localgatekeys.android.debug touch files/debug-pro
 *
 * Remove the file and restart the app to go back to free. Release builds never wrap ([wrapIfDebug] returns the store).
 */
class DebugProOverride(
    private val store: ProPurchasing,
    private val marker: File,
) : ProPurchasing by store {
    private fun on(): Boolean = marker.exists()

    override suspend fun isEntitled(): Boolean = on() || store.isEntitled()

    override suspend fun restore(): Boolean = on() || store.restore()

    companion object {
        const val MARKER = "debug-pro"

        fun wrapIfDebug(debug: Boolean, store: ProPurchasing, filesDir: File): ProPurchasing =
            if (debug) DebugProOverride(store, File(filesDir, MARKER)) else store
    }
}
