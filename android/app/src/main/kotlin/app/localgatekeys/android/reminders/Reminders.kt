package app.localgatekeys.android.reminders

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.settings.KeyValueStore
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.json.JsonValue
import java.io.IOException
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** The one reminder setting. Never synced; removed by [wipe] with the rest. */
class ReminderPrefs(private val store: KeyValueStore) {
    /** Name the item in the notification. Off by default: the text is then only "A reminder is due". */
    var showItemNames: Boolean
        get() = store.getBoolean(KEY_SHOW_NAMES) ?: false
        set(v) = store.putBoolean(KEY_SHOW_NAMES, v)

    fun wipe() = store.remove(KEY_SHOW_NAMES, durable = true)

    companion object {
        const val KEY_SHOW_NAMES = "settings.reminderShowNames"
    }
}

/**
 * Which notifications to plan (pure, so it is tested without a phone). One per not-dismissed reminder of a live typed
 * item whose effective day is today or later; one that became due today after 09:00 is planned "soon" once a day.
 */
object ReminderPlanner {
    /** [day] null: in a few seconds. [name] is the item's name, or null for the anonymous text. */
    data class Planned(val reminder: Reminder, val day: String?, val name: String?)

    fun plan(
        reminders: List<Reminder>,
        /** Live typed items: id to the name shown when [showNames] is on. */
        names: Map<String, String>,
        today: Long,
        pastNine: Boolean,
        showNames: Boolean,
    ): List<Planned> = reminders.mapNotNull { r ->
        if (r.status == Reminder.Status.DISMISSED) return@mapNotNull null
        val name = names[r.itemId] ?: return@mapNotNull null
        val day = ReminderDays.effectiveDay(r) ?: return@mapNotNull null
        if (day < today) return@mapNotNull null
        val whenDue: String? = if (day == today && pastNine) {
            if (r.lastNotified == ReminderDays.text(today)) return@mapNotNull null
            null
        } else {
            ReminderDays.text(day)
        }
        Planned(r, whenDue, if (showNames && name.isNotEmpty()) name else null)
    }
}

/**
 * Expiry reminders (a port of `PhoneReminders` in `ios/App/Reminders/PhoneReminders.swift`): content-free rows (item id,
 * due date, lead days, state) for typed items, never logins, kept in the encrypted local data ([LocalReminderStore]). Each change re-plans one local notification per active
 * reminder at 09:00 on its effective day ([ReminderAlarms]; no network, no push service). The notification never holds
 * a secret and names the item only when [ReminderPrefs.showItemNames] is on.
 *
 * Build it on unlock and give it the vault's live items through [items] (once the vault is loaded: an empty list
 * would cancel every alarm). [wipe] on Erase vault, Start fresh and device removal.
 */
class Reminders(
    private val store: ReminderStore,
    private val alarms: ReminderAlarms?,
    private val prefs: ReminderPrefs,
    private val txt: Txt,
    private val nowMillis: () -> Long = System::currentTimeMillis,
    private val zone: () -> ZoneId = { ZoneId.systemDefault() },
    private val newId: () -> String = { UUID.randomUUID().toString() },
) {
    data class Row(val id: String, val itemId: String, val title: String, val due: String, val effectiveDay: Long, val overdue: Boolean)

    enum class Failure { NOT_TYPED, INVALID_DATE, SAVE }

    private val versionFlow = MutableStateFlow(0)
    private val messageFlow = MutableStateFlow<String?>(null)

    /** Counts up on every change of the rows (the UI re-reads on it). */
    val version: StateFlow<Int> get() = versionFlow

    /** The last save failure, shown under the reminder; null when the last change worked. */
    val message: StateFlow<String?> get() = messageFlow

    /** The vault's live items (kept current by the app); a change re-plans the notifications. */
    @Volatile var items: List<VaultItem> = emptyList()
        set(value) {
            val changed = field != value
            field = value
            if (changed) {
                versionFlow.value++
                reschedule()
            }
        }

    fun today(): LocalDate = Instant.ofEpochMilli(nowMillis()).atZone(zone()).toLocalDate()

    private fun todayNumber(): Long = today().toEpochDay()

    private fun title(item: VaultItem): String = item.title.ifEmpty { item.kindLabel(txt) }

    private fun liveTyped(): Map<String, VaultItem> =
        items.filter { canHaveReminder(it) }.associateBy { it.id }

    private fun stored(): List<Reminder> {
        val live = liveTyped().keys
        return store.load().filter { it.itemId in live }
    }

    /** Overdue first, then upcoming within [days] (default: ten years), by effective day. */
    fun rows(days: Int = 3650): List<Row> {
        val t = todayNumber()
        val live = liveTyped()
        return stored().mapNotNull { r ->
            if (r.status == Reminder.Status.DISMISSED) return@mapNotNull null
            val e = ReminderDays.effectiveDay(r) ?: return@mapNotNull null
            if (e > t + days) return@mapNotNull null
            val item = live[r.itemId] ?: return@mapNotNull null
            Row(r.id, r.itemId, title(item), r.dueDate, e, e < t)
        }.sortedWith(compareBy<Row> { it.effectiveDay }.thenBy { it.id })
    }

    fun reminderFor(itemId: String): Reminder? = stored().firstOrNull { it.itemId == itemId && it.status != Reminder.Status.DISMISSED }

    /**
     * The item a notification's reminder belongs to (the tap carries only the reminder id); null when the reminder is
     * gone. Read from the rows directly, so it works before [items] is set; the shell drops an item that is gone.
     */
    fun itemIdForReminder(reminderId: String): String? = store.load().firstOrNull { it.id == reminderId }?.itemId

    /** A card's suggested due date (the last day of its expiry month), when it has no reminder yet. */
    fun suggestion(item: VaultItem): String? {
        if (item.kind != "card" || reminderFor(item.id) != null) return null
        val payload = (item.record["payload"] as? JsonValue.Obj)?.fields
        val expiry = (payload?.get("expiry") as? JsonValue.Str)?.v
            ?: (item.record["expiry"] as? JsonValue.Str)?.v ?: return null
        val day = ReminderDays.cardExpiryDay(expiry) ?: return null
        val n = ReminderDays.dayNumber(day) ?: return null
        return if (n >= todayNumber()) day else null
    }

    // changes

    /** Adds a reminder, or replaces the item's active one; null when it worked. */
    fun set(itemId: String, dueDate: String, leadDays: Int): Failure? {
        val item = items.firstOrNull { it.id == itemId }
        if (item == null || !canHaveReminder(item)) return Failure.NOT_TYPED
        if (ReminderDays.dayNumber(dueDate) == null) return Failure.INVALID_DATE
        val row = Reminder(newId(), itemId, dueDate, leadDays.coerceIn(0, Reminder.MAX_LEAD_DAYS))
        return if (save { all -> all.filterNot { it.itemId == itemId && it.status != Reminder.Status.DISMISSED } + row }) {
            reschedule()
            null
        } else {
            Failure.SAVE
        }
    }

    fun complete(id: String) = change(id) { it.copy(status = Reminder.Status.DISMISSED, snoozeUntil = "") }

    fun snooze(id: String, days: Int = 1) {
        val until = ReminderDays.text(todayNumber() + days)
        change(id) { it.copy(status = Reminder.Status.SNOOZED, snoozeUntil = until) }
    }

    fun delete(id: String) {
        if (save { all -> all.filterNot { it.id == id } }) reschedule()
    }

    private fun change(id: String, edit: (Reminder) -> Reminder) {
        if (save { all -> all.map { if (it.id == id) edit(it) else it } }) reschedule()
    }

    private fun save(change: (List<Reminder>) -> List<Reminder>): Boolean = try {
        store.update(change)
        messageFlow.value = null
        versionFlow.value++
        true
    } catch (e: IOException) {
        messageFlow.value = txt.s(R.string.reminder_save_failed)
        false
    }

    // notifications

    /** Replaces the armed alarms with the current plan (the newest call wins). */
    fun reschedule() {
        val alarms = alarms ?: return
        val now = Instant.ofEpochMilli(nowMillis()).atZone(zone())
        val t = now.toLocalDate().toEpochDay()
        val live = liveTyped()
        // Notifications the receiver sent while the vault was locked: kept in the encrypted rows from now on.
        val sent = alarms.notified()
        if (sent.isNotEmpty() && store.load().any { r -> sent[r.id]?.let { it > r.lastNotified } == true }) {
            try {
                store.update { all -> all.map { r -> sent[r.id]?.takeIf { it > r.lastNotified }?.let { r.copy(lastNotified = it) } ?: r } }
            } catch (e: IOException) {
                // Kept in the alarm book until a later save works.
            }
        }
        val planned = ReminderPlanner.plan(
            stored(), live.mapValues { title(it.value) }, t, now.hour >= ReminderTime.HOUR, prefs.showItemNames,
        )
        // A "soon" notification is the one of the day, but it counts only once it was shown: the receiver records it in
        // the book (kept in the rows from the next plan), and the book never arms an entry already notified that day.
        // Marked here instead, a notification that could not be shown (not allowed yet) was lost for the day.
        alarms.replaceAll(planned.map { AlarmEntry(it.reminder.id, it.day, it.name) })
    }

    /** Cancels the alarms and deletes every reminder and the setting; true when nothing is left. */
    fun wipe(): Boolean = Companion.wipe(store, alarms, prefs)

    companion object {
        /** Typed items only; a login is never given a reminder (the iPhone and Windows rule). */
        fun canHaveReminder(item: VaultItem): Boolean = !item.isLogin

        /** The lead times offered, in days. */
        val leadChoices = listOf(0, 1, 7, 14, 30, 60, 90)

        /** Erase vault, Start fresh, device removal: no alarm, no row, no setting stays. */
        fun wipe(store: ReminderStore?, alarms: ReminderAlarms?, prefs: ReminderPrefs?): Boolean {
            val a = alarms?.wipe() ?: true
            val s = store?.wipe() ?: true
            prefs?.wipe()
            return a && s
        }
    }
}
