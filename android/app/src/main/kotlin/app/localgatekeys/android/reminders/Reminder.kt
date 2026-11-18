package app.localgatekeys.android.reminders

import java.time.DateTimeException
import java.time.LocalDate

/**
 * Day arithmetic for reminders (a port of `ReminderDays` in `ios/App/Reminders/PhoneReminders.swift`): "YYYY-MM-DD"
 * dates, day numbers since 1970-01-01, effective date = due minus lead (a snoozed one not before its snooze date).
 */
object ReminderDays {
    private val shape = Regex("""\d{4}-\d{2}-\d{2}""")

    fun text(date: LocalDate): String = "%04d-%02d-%02d".format(date.year, date.monthValue, date.dayOfMonth)

    /** Days since 1970-01-01 of a "YYYY-MM-DD" date; null when it is not a real calendar date. */
    fun dayNumber(s: String): Long? {
        if (!shape.matches(s)) return null
        return try {
            LocalDate.of(s.substring(0, 4).toInt(), s.substring(5, 7).toInt(), s.substring(8, 10).toInt()).toEpochDay()
        } catch (e: DateTimeException) {
            null
        }
    }

    fun text(day: Long): String = text(LocalDate.ofEpochDay(day))

    fun date(s: String): LocalDate? = dayNumber(s)?.let { LocalDate.ofEpochDay(it) }

    /** Due minus lead; a snoozed reminder not before its snooze date. Null when the due date is invalid. */
    fun effectiveDay(r: Reminder): Long? {
        var day = dayNumber(r.dueDate) ?: return null
        day -= r.leadDays
        if (r.status == Reminder.Status.SNOOZED) dayNumber(r.snoozeUntil)?.let { day = maxOf(day, it) }
        return day
    }

    /** The last day of a card's "MM/YY" (or "MM/YYYY") expiry month, as "YYYY-MM-DD"; null when it isn't one. */
    fun cardExpiryDay(expiry: String): String? {
        val parts = expiry.replace(" ", "").split('/')
        if (parts.size != 2) return null
        val m = parts[0].toIntOrNull() ?: return null
        if (m !in 1..12) return null
        var y = parts[1].toIntOrNull() ?: return null
        when (parts[1].length) {
            2 -> y += 2000
            4 -> Unit
            else -> return null
        }
        if (y !in 1..9999 || parts[1].startsWith("-") || parts[1].startsWith("+")) return null
        return text(LocalDate.of(y, m, 1).let { it.withDayOfMonth(it.lengthOfMonth()) })
    }
}

/**
 * One expiry reminder: content-free (an item id, a due date, a lead time and a state; never a title or a secret).
 * Typed items only, never logins (the iPhone and Windows rule).
 */
data class Reminder(
    val id: String,
    val itemId: String,
    /** "YYYY-MM-DD". */
    val dueDate: String,
    val leadDays: Int,
    val status: Status = Status.ACTIVE,
    /** "YYYY-MM-DD" while [status] is SNOOZED. */
    val snoozeUntil: String = "",
    /** The day (YYYY-MM-DD) a notification last went out for it; stops a second one the same day. */
    val lastNotified: String = "",
) {
    enum class Status(val wire: String) {
        ACTIVE("active"), SNOOZED("snoozed"), DISMISSED("dismissed");

        companion object {
            fun of(wire: String?): Status = entries.firstOrNull { it.wire == wire } ?: ACTIVE
        }
    }

    companion object {
        const val MAX_LEAD_DAYS = 3650
    }
}
