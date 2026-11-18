package app.localgatekeys.android.reminders

import android.Manifest
import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import app.localgatekeys.android.MainActivity
import app.localgatekeys.android.R
import app.localgatekeys.android.settings.SharedPrefsStore
import java.io.File
import java.time.ZoneId

/**
 * The Android side of the reminders: the alarm book, the alarm clock, the notification and the two receivers.
 * Everything here works without the vault (a receiver runs while the app is locked or not running); the reminder rows
 * themselves are in the encrypted local data ([LocalReminderStore]), which only an unlocked vault can read.
 */
object ReminderSystem {
    const val PREFS_FILE = "reminders"
    const val CHANNEL_ID = "reminders"

    /** The notification tap: opens the app (locked: unlock first, then the reminder's item). */
    const val ACTION_OPEN_ITEM = "app.localgatekeys.android.action.OPEN_REMINDER_ITEM"
    /** The reminder's id (not the item's: the item is looked up in the encrypted rows after the unlock). */
    const val EXTRA_REMINDER_ID = "app.localgatekeys.android.extra.REMINDER_ID"

    internal const val ACTION_FIRE = "app.localgatekeys.android.action.REMINDER_FIRE"

    /** The plain row file of the first build ([LegacyReminderFile]): moved into the local data and deleted on unlock. */
    fun legacyRowsFile(context: Context) = File(context.noBackupFilesDir, "reminders.json")

    /** The armed alarms (reminder ids, days, a name only when names are on); in noBackupFilesDir, never in a backup. */
    fun alarmsFile(context: Context) = File(context.noBackupFilesDir, "reminder-alarms.json")

    fun alarms(context: Context): ReminderAlarms = ReminderAlarms(alarmsFile(context), SystemAlarmSetter(context.applicationContext))

    fun prefs(context: Context): ReminderPrefs =
        ReminderPrefs(SharedPrefsStore(context.applicationContext.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)))

    /**
     * Erase vault, Start fresh and device removal: cancels the alarms, deletes the alarm file, an old plain row file and
     * the setting and takes down any reminder notification still showing (the encrypted rows go with the vault folder).
     * True when nothing is left. Needs no unlocked vault.
     */
    fun wipe(context: Context): Boolean {
        val legacy = legacyRowsFile(context)
        val ok = Reminders.wipe(null, alarms(context), prefs(context)) && (!legacy.exists() || legacy.delete())
        try {
            context.getSystemService(NotificationManager::class.java)?.cancelAll()
        } catch (e: RuntimeException) {
            // Best effort.
        }
        return ok
    }

    /** True when a notification could be shown now: the permission (Android 13+) and the app's notifications are on. */
    fun notificationsAllowed(context: Context): Boolean {
        if (Build.VERSION.SDK_INT >= 33 &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return false
        return context.getSystemService(NotificationManager::class.java)?.areNotificationsEnabled() ?: false
    }

    /** The reminder id a notification tap carries, or null for any other intent (a request only: the activity is exported). */
    fun reminderIdOf(intent: Intent?): String? =
        if (intent?.action == ACTION_OPEN_ITEM) intent.getStringExtra(EXTRA_REMINDER_ID)?.takeIf { it.isNotEmpty() && it.length <= 64 } else null

    internal fun ensureChannel(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java) ?: return
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(CHANNEL_ID, context.getString(R.string.reminder_channel_name), NotificationManager.IMPORTANCE_DEFAULT)
        channel.lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        nm.createNotificationChannel(channel)
    }

    /**
     * Shows one reminder; false when it could not be shown (notifications off or not allowed yet). Private visibility
     * with the generic text as the public version: a lock screen that hides sensitive content shows the generic text,
     * but where the phone allows sensitive notifications on the lock screen (Android 16's default) the full text (the
     * item's name, when names are on) shows there too. Settings › Reminders says so.
     */
    internal fun show(context: Context, entry: AlarmEntry): Boolean {
        if (!notificationsAllowed(context)) return false
        ensureChannel(context)
        val nm = context.getSystemService(NotificationManager::class.java) ?: return false
        val title = context.getString(R.string.app_name)
        val anonymous = context.getString(R.string.reminder_anonymous_body)
        val body = entry.name?.let { context.getString(R.string.reminder_named_body, it) } ?: anonymous
        val open = Intent(context, MainActivity::class.java)
            .setAction(ACTION_OPEN_ITEM)
            .putExtra(EXTRA_REMINDER_ID, entry.id)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val tap = PendingIntent.getActivity(context, entry.id.hashCode(), open, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val public = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_reminder).setContentTitle(title).setContentText(anonymous).build()
        val n = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_reminder)
            .setContentTitle(title)
            .setContentText(body)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(public)
            .setCategory(Notification.CATEGORY_REMINDER)
            .setContentIntent(tap)
            .setAutoCancel(true)
            .build()
        return try {
            nm.notify(entry.id.hashCode(), n)
            true
        } catch (e: SecurityException) {
            false
        }
    }
}

/** `AlarmManager` alarms that survive Doze but are not exact (no exact-alarm permission). */
internal class SystemAlarmSetter(private val context: Context) : AlarmSetter {
    private val manager get() = context.getSystemService(AlarmManager::class.java)

    private fun intent(id: String) = Intent(context, ReminderAlarmReceiver::class.java)
        .setAction(ReminderSystem.ACTION_FIRE)
        .setData(Uri.parse("lgk-reminder:$id"))

    override fun set(id: String, atMillis: Long) {
        val pi = PendingIntent.getBroadcast(context, 0, intent(id), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        try {
            manager?.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, atMillis, pi)
        } catch (e: SecurityException) {
            // No alarm: the reminder still shows in the app's Upcoming list.
        }
    }

    override fun cancel(id: String) {
        val pi = PendingIntent.getBroadcast(context, 0, intent(id), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_NO_CREATE)
        if (pi != null) {
            manager?.cancel(pi)
            pi.cancel()
        }
    }
}

/**
 * An alarm went off: show its notification (text only, no vault needed) and forget the alarm. When it could not be
 * shown (notifications not allowed, for example the Allow dialog is still open), nothing is recorded: the reminder stays
 * due and comes with the next plan or a later alarm.
 */
class ReminderAlarmReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ReminderSystem.ACTION_FIRE) return
        val id = intent.data?.schemeSpecificPart?.takeIf { it.isNotEmpty() } ?: return
        val duress = (context.applicationContext as? app.localgatekeys.android.LgkApp)?.duress
        ReminderDelivery.fire(
            ReminderSystem.alarms(context), id,
            withheld = { duress?.servicesBlocked() ?: false },
            show = { ReminderSystem.show(context, it) },
            today = { ReminderDays.text(java.time.LocalDate.now(ZoneId.systemDefault())) },
        )
    }
}

/**
 * What an alarm does when it goes off (sub-plan 08, re-review 5a): while a duress session is open or the real vault is
 * held, the real vault's reminders post nothing (not even the anonymous text: a reminder for an item the open vault does
 * not hold is a tell), and the entry stays so the reminder comes with the next plan after the real unlock. Otherwise
 * the notification is shown and, once shown, the day is recorded (the next re-plan sends no second one that day).
 */
internal object ReminderDelivery {
    /** True when a notification was posted. */
    fun fire(alarms: ReminderAlarms, id: String, withheld: () -> Boolean, show: (AlarmEntry) -> Boolean, today: () -> String): Boolean {
        val entry = alarms.entry(id) ?: return false // cancelled meanwhile
        if (withheld()) return false
        if (!show(entry)) return false
        alarms.fired(id, today())
        return true
    }
}

/** Alarms are forgotten by a restart, an update and (for 09:00) a clock or time zone change: arm them again. */
class ReminderBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED,
            Intent.ACTION_TIMEZONE_CHANGED, Intent.ACTION_TIME_CHANGED -> ReminderSystem.alarms(context).rearm()
        }
    }
}
