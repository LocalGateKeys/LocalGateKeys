package app.localgatekeys.android.reminders

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import java.io.File
import java.io.IOException
import java.time.Instant
import java.time.ZoneId

/**
 * One notification that is due: the reminder's id, the local day it is due ("YYYY-MM-DD", at 09:00; null = in a few
 * seconds, because it became due today after 09:00) and the item's name ONLY when the person turned item names on in
 * Settings (null: the text is the anonymous "A reminder is due"). Nothing else: no item id, never a secret. The tap
 * finds the item from the reminder id in the encrypted rows after the unlock.
 */
data class AlarmEntry(val id: String, val day: String?, val name: String?)

/** The system alarm clock (tests use a fake). */
interface AlarmSetter {
    fun set(id: String, atMillis: Long)
    fun cancel(id: String)
}

/**
 * The alarms of the reminders. [book] is a small plain file of what re-arming needs: the armed entries (reminder ids,
 * days, and a name only when names are on) and the days notifications went out (reminder id and day, so a re-plan the
 * same day sends no second one). The system forgets alarms on a restart, and the boot receiver re-arms from the file
 * without the vault, which is locked then; the reminders themselves stay in the encrypted local data. It is the only
 * place the app keeps text for a notification, so [wipe] deletes it with the alarms.
 *
 * The alarms are inexact and allowed in Doze (`setAndAllowWhileIdle`): no exact-alarm permission is needed, and a
 * reminder may come a little late. A missed one (the phone was off at 09:00) comes a few seconds after the phone is
 * back. All methods are safe to call from the app and from a receiver at once.
 */
class ReminderAlarms(
    private val book: File,
    private val setter: AlarmSetter,
    private val nowMillis: () -> Long = System::currentTimeMillis,
    private val zone: () -> ZoneId = { ZoneId.systemDefault() },
) {
    private val lock get() = ReminderFiles.lockFor(book)

    private class Book(val alarms: List<AlarmEntry>, val notified: Map<String, String>)

    /**
     * Replaces all armed alarms with [entries] (the newest plan wins). Notified days before today are dropped, and an
     * entry whose notification already went out on its day (the receiver recorded it, maybe while this plan was being
     * made) is not armed again: one notification per reminder and day.
     */
    fun replaceAll(entries: List<AlarmEntry>) = synchronized(lock) {
        val old = read()
        for (e in old.alarms) setter.cancel(e.id)
        val today = ReminderDays.text(Instant.ofEpochMilli(nowMillis()).atZone(zone()).toLocalDate())
        val notified = old.notified.filterValues { it >= today }
        val armed = entries.filterNot { e -> notified[e.id] == (e.day ?: today) }
        write(Book(armed, notified))
        for (e in armed) setter.set(e.id, triggerAt(e))
    }

    /** Arms every entry of the book again (after a restart, an update or a clock or time zone change). */
    fun rearm() = synchronized(lock) {
        for (e in read().alarms) setter.set(e.id, triggerAt(e))
    }

    fun entry(id: String): AlarmEntry? = synchronized(lock) { read().alarms.firstOrNull { it.id == id } }

    fun entries(): List<AlarmEntry> = synchronized(lock) { read().alarms }

    /** Reminder id to the day ("YYYY-MM-DD") its notification last went out, as the receiver recorded it. */
    fun notified(): Map<String, String> = synchronized(lock) { read().notified }

    /**
     * The notification for [id] went out on [day] (or its reminder is gone: [day] null): forget the alarm, remember the
     * day. Not called when the notification could not be shown (not allowed yet): the entry stays, so a restart re-arms
     * it and the next plan (unlock, any reminder change) brings it again.
     */
    fun fired(id: String, day: String? = null) = synchronized(lock) {
        val old = read()
        setter.cancel(id)
        val notified = if (day == null) old.notified else old.notified + (id to day)
        write(Book(old.alarms.filterNot { it.id == id }, notified))
    }

    /** Cancels every alarm and deletes the book; true when nothing is left. */
    fun wipe(): Boolean = synchronized(lock) {
        for (e in read().alarms) setter.cancel(e.id)
        !book.exists() || book.delete()
    }

    internal fun triggerAt(e: AlarmEntry): Long {
        val now = nowMillis()
        val soon = now + SOON_MILLIS
        val day = e.day?.let { ReminderDays.date(it) } ?: return soon
        val at = day.atTime(ReminderTime.HOUR, 0).atZone(zone()).toInstant().toEpochMilli()
        return if (at <= now) soon else at
    }

    private fun read(): Book {
        val none = Book(emptyList(), emptyMap())
        if (!book.exists()) return none
        return try {
            val root = CanonicalJson.parse(book.readBytes()) as? JsonValue.Obj ?: return none
            val alarms = ((root.fields["alarms"] as? JsonValue.Arr)?.items ?: emptyList()).mapNotNull { v ->
                val f = (v as? JsonValue.Obj)?.fields ?: return@mapNotNull null
                fun str(k: String) = (f[k] as? JsonValue.Str)?.v
                val id = str("id")?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
                val day = str("day")?.takeIf { ReminderDays.dayNumber(it) != null }
                AlarmEntry(id, day, str("name"))
            }
            val notified = ((root.fields["notified"] as? JsonValue.Arr)?.items ?: emptyList()).mapNotNull { v ->
                val f = (v as? JsonValue.Obj)?.fields ?: return@mapNotNull null
                val id = (f["id"] as? JsonValue.Str)?.v?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
                val day = (f["day"] as? JsonValue.Str)?.v?.takeIf { ReminderDays.dayNumber(it) != null } ?: return@mapNotNull null
                id to day
            }.toMap()
            Book(alarms, notified)
        } catch (e: Exception) {
            none
        }
    }

    private fun write(b: Book) {
        val rows = b.alarms.map { e ->
            val m = linkedMapOf<String, JsonValue>("id" to JsonValue.Str(e.id))
            e.day?.let { m["day"] = JsonValue.Str(it) }
            e.name?.let { m["name"] = JsonValue.Str(it) }
            JsonValue.Obj(m)
        }
        val notified = b.notified.toSortedMap().map { (id, day) ->
            JsonValue.Obj(mapOf("id" to JsonValue.Str(id), "day" to JsonValue.Str(day)))
        }
        val root = mapOf("v" to JsonValue.Int(2), "alarms" to JsonValue.Arr(rows), "notified" to JsonValue.Arr(notified))
        try {
            ReminderFiles.writeAtomically(book, CanonicalJson.encode(JsonValue.Obj(root), Dialect.UTF8))
        } catch (e: IOException) {
            // The alarms are still armed in the system; only the restart copy is stale.
        }
    }

    companion object {
        const val SOON_MILLIS = 5_000L
    }
}

/** When the daily notification comes. */
object ReminderTime {
    const val HOUR = 9
}
