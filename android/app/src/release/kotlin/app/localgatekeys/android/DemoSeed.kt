package app.localgatekeys.android

import android.content.Intent
import app.localgatekeys.core.sync.ItemStore

/** Release builds have no demo data: this does nothing (the debug source set has the real one). */
object DemoSeed {
    @Suppress("UNUSED_PARAMETER")
    fun seedIfRequested(intent: Intent?, store: ItemStore) = Unit
}
