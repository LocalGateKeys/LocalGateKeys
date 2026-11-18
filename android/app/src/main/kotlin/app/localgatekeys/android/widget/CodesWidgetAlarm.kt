package app.localgatekeys.android.widget

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent

/**
 * The second fallback for a process that dies with codes on the widget: an alarm to the widget's own private receiver.
 *
 * WorkManager's job alone was not enough. JobScheduler limits how many jobs an app may run (on Android 10, 20 in ten
 * minutes), and the widget's own Glance updates use jobs too, so after a few minutes with codes on screen the fallback
 * job waited for quota and a killed app's widget kept its digits for minutes. Alarms have no such job count. The alarm
 * starts a new process, which has no vault key, so the widget then shows the locked state.
 */
object CodesWidgetAlarm {
    const val ACTION_REFRESH = "app.localgatekeys.android.widget.REFRESH"

    /** How late the system may deliver the alarm (an inexact window: no exact-alarm permission needed). */
    const val WINDOW_MILLIS = 5_000L

    private fun intent(context: Context, flags: Int): PendingIntent? = PendingIntent.getBroadcast(
        context, 0,
        Intent(context, CodesWidgetReceiver::class.java).setAction(ACTION_REFRESH),
        flags or PendingIntent.FLAG_IMMUTABLE,
    )

    /** Arms (or moves) the alarm [delayMillis] from now. */
    fun arm(context: Context, delayMillis: Long, nowMillis: Long = System.currentTimeMillis()) {
        val alarms = context.getSystemService(AlarmManager::class.java) ?: return
        val pi = intent(context, PendingIntent.FLAG_UPDATE_CURRENT) ?: return
        try {
            alarms.setWindow(AlarmManager.RTC, nowMillis + delayMillis, WINDOW_MILLIS, pi)
        } catch (e: RuntimeException) {
            // too many alarms or refused: the in-process timer and the WorkManager job remain
        }
    }

    fun cancel(context: Context) {
        val pi = intent(context, PendingIntent.FLAG_NO_CREATE) ?: return
        context.getSystemService(AlarmManager::class.java)?.cancel(pi)
        pi.cancel()
    }

    /** True while an alarm is armed (for tests). */
    fun isArmed(context: Context): Boolean = intent(context, PendingIntent.FLAG_NO_CREATE) != null
}
