package app.localgatekeys.android.duress

import app.localgatekeys.android.reminders.AlarmSetter
import app.localgatekeys.android.reminders.ReminderAlarms
import app.localgatekeys.android.share.ShareInbox
import app.localgatekeys.core.primitives.UnixClock
import java.io.File

/**
 * The second vault's own copies of this phone's shared extras (sub-plan 08, review 5a #4), all inside its folder
 * `.lgk-d`, so a duress session never reads or rewrites the real vault's: the reminders' alarm book (and no system
 * alarm: the real vault's alarms stay armed as they were) and the received-share inbox.
 */
object DuressPlaces {
    fun reminderAlarms(files: DuressFiles): ReminderAlarms = ReminderAlarms(File(files.dir, "reminder-alarms.json"), NoAlarms)

    fun shareInbox(files: DuressFiles, clock: UnixClock): ShareInbox =
        ShareInbox(File(files.dir, "share-inbox"), File(files.dir, "share-opened.json"), clock)

    private object NoAlarms : AlarmSetter {
        override fun set(id: String, atMillis: Long) {}
        override fun cancel(id: String) {}
    }
}
