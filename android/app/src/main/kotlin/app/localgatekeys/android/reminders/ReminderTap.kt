package app.localgatekeys.android.reminders

import kotlinx.coroutines.flow.MutableStateFlow

/**
 * A reminder notification's tap, delivered to the open vault: [pending] holds the tapped reminder's id (set on a fresh
 * start or in `onNewIntent`), [find] looks up its item in the encrypted rows, [open] shows the item.
 *
 * The request is cleared only after the lookup, and only if it is still the same one. Clearing it first changed the
 * key of the effect running this, which cancelled the lookup before [open] (release check 2026-11-01: a tap while the
 * app was unlocked and in front opened nothing). A cancelled run leaves the request pending for the next run.
 */
object ReminderTap {
    suspend fun deliver(pending: MutableStateFlow<String?>, find: suspend (String) -> String?, open: (String) -> Unit) {
        val id = pending.value ?: return
        val itemId = find(id)
        pending.compareAndSet(id, null)
        itemId?.let(open)
    }
}
