package app.localgatekeys.android.unlock

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build

/** Tells the lock model when the screen turns off (Ruling 21: during a system-screen trip that locks). Main thread. */
interface ScreenOffWatching {
    /** Starts watching; [onScreenOff] runs on the main thread each time the screen turns off, until [stop]. */
    fun start(onScreenOff: () -> Unit)

    fun stop()

    companion object {
        val NONE = object : ScreenOffWatching {
            override fun start(onScreenOff: () -> Unit) {}
            override fun stop() {}
        }
    }
}

/** [ScreenOffWatching] through an `ACTION_SCREEN_OFF` receiver, registered only while watching. */
class ScreenOffReceiver(context: Context) : ScreenOffWatching {
    private val app = context.applicationContext
    private var receiver: BroadcastReceiver? = null

    override fun start(onScreenOff: () -> Unit) {
        stop()
        val r = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action == Intent.ACTION_SCREEN_OFF) onScreenOff()
            }
        }
        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
        // A protected system broadcast: it still arrives with RECEIVER_NOT_EXPORTED.
        if (Build.VERSION.SDK_INT >= 33) app.registerReceiver(r, filter, Context.RECEIVER_NOT_EXPORTED) else app.registerReceiver(r, filter)
        receiver = r
    }

    override fun stop() {
        val r = receiver ?: return
        receiver = null
        try {
            app.unregisterReceiver(r)
        } catch (e: IllegalArgumentException) {
            // not registered
        }
    }
}
