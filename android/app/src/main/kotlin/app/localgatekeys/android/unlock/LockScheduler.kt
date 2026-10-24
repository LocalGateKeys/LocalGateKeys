package app.localgatekeys.android.unlock

import android.os.Handler
import android.os.Looper
import android.os.SystemClock

/** A one-shot timer that can be cancelled. */
interface LockTimer {
    fun cancel()
}

/** Starts one-shot timers for the idle lock. The app uses [HandlerLockScheduler]; tests advance a manual one. */
interface LockScheduler {
    fun schedule(afterSeconds: Long, action: () -> Unit): LockTimer
}

/**
 * Main-thread one-shot timers. They do not run while the process is frozen in the background, so
 * [AppLockModel.willEnterForeground] re-checks the wall-clock deadlines when the app comes back.
 */
class HandlerLockScheduler(private val handler: Handler = Handler(Looper.getMainLooper())) : LockScheduler {
    override fun schedule(afterSeconds: Long, action: () -> Unit): LockTimer {
        val token = Any()
        handler.postAtTime({ action() }, token, SystemClock.uptimeMillis() + afterSeconds * 1000L)
        return object : LockTimer {
            override fun cancel() = handler.removeCallbacksAndMessages(token)
        }
    }
}
