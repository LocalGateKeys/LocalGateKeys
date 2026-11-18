package app.localgatekeys.android.ui.reminders

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.reminders.ReminderDays
import app.localgatekeys.android.reminders.ReminderPrefs
import app.localgatekeys.android.reminders.ReminderSystem
import app.localgatekeys.android.reminders.Reminders
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.ui.theme.lgkSwitchColors
import app.localgatekeys.android.vault.VaultItem
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/** "YYYY-MM-DD" as the person's own short date format; the raw text when it is not a date. */
internal fun reminderDateText(day: String): String =
    ReminderDays.date(day)?.format(DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM)) ?: day

@Composable
private fun Group(title: String?, footer: String?, tag: String, content: @Composable ColumnScope.() -> Unit) {
    val c = LgkTheme.colors
    Column(Modifier.fillMaxWidth().testTag(tag)) {
        if (title != null) {
            Text(
                title, color = c.secondaryText, style = MaterialTheme.typography.labelLarge,
                modifier = Modifier.padding(start = 4.dp, bottom = 6.dp).semantics { heading() },
            )
        }
        Column(Modifier.fillMaxWidth().lgkGroupSurface().padding(horizontal = 16.dp, vertical = 4.dp), content = content)
        if (footer != null) {
            Text(footer, color = c.secondaryText, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 4.dp, end = 4.dp, top = 6.dp))
        }
    }
}

/**
 * Asks for the notification permission (Android 13+) and only when called: the app calls it when the first reminder is
 * saved. Below Android 13, or when it is already granted, calling it does nothing. Reminders are saved either way; with
 * notifications off they still show in Upcoming. [onGranted] runs when the person allows them (re-plan: a reminder due
 * now, whose alarm went off while the Allow dialog was still open, then comes after all).
 */
@Composable
fun rememberAskForNotifications(onGranted: () -> Unit = {}): () -> Unit {
    val context = LocalContext.current
    val granted by rememberUpdatedState(onGranted)
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok -> if (ok) granted() }
    return remember(context, launcher) {
        {
            if (Build.VERSION.SDK_INT >= 33 &&
                context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) {
                launcher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }
}

/**
 * The item detail's Reminder section (typed items only; nothing for a login): the active reminder, or Add (a card
 * suggests the last day of its expiry month). Put it in the detail screen after the fields.
 */
@Composable
fun ItemReminderSection(reminders: Reminders, item: VaultItem, modifier: Modifier = Modifier) {
    if (!Reminders.canHaveReminder(item)) return
    val c = LgkTheme.colors
    val version by reminders.version.collectAsState()
    val message by reminders.message.collectAsState()
    var editing by remember { mutableStateOf(false) }
    val ask = rememberAskForNotifications { reminders.reschedule() }
    val current = remember(version, item.id) { reminders.reminderFor(item.id) }
    val suggested = remember(version, item.id, current) { if (current == null) reminders.suggestion(item) else null }
    Column(modifier) {
        Group(stringResource(R.string.reminder_section), null, "item-reminder") {
            if (current != null) {
                ValueRow(stringResource(R.string.reminder_due), reminderDateText(current.dueDate))
                if (current.leadDays > 0) ValueRow(stringResource(R.string.reminder_remind_me), leadText(current.leadDays))
                ActionRow(stringResource(R.string.reminder_change), "item-reminder-change") { editing = true }
                ActionRow(stringResource(R.string.reminder_remove), "item-reminder-remove", danger = true) { reminders.delete(current.id) }
            } else if (suggested != null) {
                Text(
                    stringResource(R.string.reminder_card_expires, reminderDateText(suggested)),
                    color = c.secondaryText, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(vertical = 12.dp),
                )
                ActionRow(stringResource(R.string.reminder_suggest_button), "item-reminder-add") { editing = true }
            } else {
                ActionRow(stringResource(R.string.reminder_add), "item-reminder-add") { editing = true }
            }
            message?.let {
                Text(it, color = c.danger, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(bottom = 8.dp).testTag("item-reminder-error"))
            }
        }
    }
    if (editing) {
        ReminderEditorDialog(reminders, item, onSaved = { ask() }, onClose = { editing = false })
    }
}

@Composable
private fun ValueRow(label: String, value: String) {
    val c = LgkTheme.colors
    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Text(value, color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun ActionRow(label: String, tag: String, danger: Boolean = false, onClick: () -> Unit) {
    val c = LgkTheme.colors
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Button, onClick = onClick).testTag(tag),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, color = if (danger) c.danger else c.accentText, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun leadText(days: Int): String =
    if (days == 0) stringResource(R.string.reminder_on_the_day) else pluralStringResource(R.plurals.reminder_days_before, days, days)

/** Due date and how many days before to be reminded. [onSaved] runs after a successful save (the permission ask). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReminderEditorDialog(reminders: Reminders, item: VaultItem, onSaved: () -> Unit, onClose: () -> Unit) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    val existing = remember(item.id) { reminders.reminderFor(item.id) }
    val start = remember(item.id) {
        existing?.let { ReminderDays.date(it.dueDate) } ?: reminders.suggestion(item)?.let { ReminderDays.date(it) } ?: reminders.today()
    }
    var due by remember { mutableStateOf(start) }
    var lead by remember { mutableStateOf(existing?.leadDays ?: if (reminders.suggestion(item) != null) 30 else 0) }
    var picking by remember { mutableStateOf(false) }
    var failed by remember { mutableStateOf(false) }
    val failText by reminders.message.collectAsState()
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(item.title.ifEmpty { item.kindLabel(txt) }, color = c.text) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()).testTag("reminder-editor"), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Row(
                    Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Button) { picking = true }.testTag("reminder-due-date"),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(stringResource(R.string.reminder_due_date), color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                    Text(reminderDateText(ReminderDays.text(due)), color = c.accentText, style = MaterialTheme.typography.bodyLarge)
                }
                Text(
                    stringResource(R.string.reminder_remind_me), color = c.secondaryText, style = MaterialTheme.typography.labelLarge,
                    modifier = Modifier.padding(top = 8.dp).semantics { heading() },
                )
                for (choice in Reminders.leadChoices) {
                    val label = leadText(choice)
                    Row(
                        Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.RadioButton) { lead = choice }
                            .testTag("reminder-lead-$choice"),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(lead == choice, onClick = null)
                        Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(start = 12.dp))
                    }
                }
                Text(
                    stringResource(R.string.reminder_editor_footer), color = c.secondaryText, style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 8.dp),
                )
                if (failed) {
                    Text(failText ?: stringResource(R.string.reminder_save_failed), color = c.danger, style = MaterialTheme.typography.bodyMedium)
                }
            }
        },
        confirmButton = {
            TextButton({
                if (reminders.set(item.id, ReminderDays.text(due), lead) == null) {
                    onSaved()
                    onClose()
                } else {
                    failed = true
                }
            }, Modifier.testTag("reminder-save")) { Text(stringResource(R.string.common_save), color = c.accentText) }
        },
        dismissButton = { TextButton(onClose, Modifier.testTag("reminder-cancel")) { Text(stringResource(R.string.common_cancel), color = c.accentText) } },
    )
    if (picking) {
        val state = rememberDatePickerState(initialSelectedDateMillis = due.atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli())
        DatePickerDialog(
            onDismissRequest = { picking = false },
            confirmButton = {
                TextButton({
                    state.selectedDateMillis?.let { due = Instant.ofEpochMilli(it).atZone(ZoneOffset.UTC).toLocalDate() }
                    picking = false
                }) { Text(stringResource(R.string.common_ok)) }
            },
            dismissButton = { TextButton({ picking = false }) { Text(stringResource(R.string.common_cancel)) } },
        ) { DatePicker(state) }
    }
}

/**
 * The Security tab's Upcoming section: overdue and the next 30 days, with Done and Snooze (one day) on each row. When
 * notifications are off for the app the section says so; the reminders still show here.
 */
@Composable
fun UpcomingRemindersSection(reminders: Reminders, modifier: Modifier = Modifier) {
    val c = LgkTheme.colors
    val context = LocalContext.current
    val version by reminders.version.collectAsState()
    val rows = remember(version, reminders.items) { reminders.rows(days = 30) }
    var notificationsAllowed by remember { mutableStateOf(true) }
    LaunchedEffect(version) { notificationsAllowed = ReminderSystem.notificationsAllowed(context) }
    val footer = if (!notificationsAllowed) stringResource(R.string.reminder_notifications_off) else null
    Column(modifier) {
        Group(stringResource(R.string.reminder_upcoming), footer, "upcoming-reminders") {
            if (rows.isEmpty()) {
                Text(
                    stringResource(R.string.reminder_nothing_upcoming), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(vertical = 12.dp),
                )
            }
            rows.forEachIndexed { i, row ->
                if (i > 0) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
                val dueText = if (row.overdue) stringResource(R.string.reminder_overdue_due, reminderDateText(row.due))
                else stringResource(R.string.reminder_due_on, reminderDateText(row.due))
                Row(Modifier.fillMaxWidth().heightIn(min = 56.dp).testTag("reminder-row-${row.id}"), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f).padding(vertical = 8.dp).semantics(mergeDescendants = true) { contentDescription = "${row.title}, $dueText" }) {
                        Text(row.title, color = c.text, style = MaterialTheme.typography.bodyLarge)
                        Text(dueText, color = if (row.overdue) c.danger else c.secondaryText, style = MaterialTheme.typography.bodyMedium)
                    }
                    TextButton({ reminders.snooze(row.id) }, Modifier.testTag("reminder-snooze-${row.id}")) {
                        Text(stringResource(R.string.reminder_snooze), color = c.accentText)
                    }
                    TextButton({ reminders.complete(row.id) }, Modifier.testTag("reminder-done-${row.id}")) {
                        Text(stringResource(R.string.common_done), color = c.success)
                    }
                }
            }
        }
    }
}

/**
 * Settings › Reminders: whether notifications name the item (off by default, so nothing about the item shows on the
 * lock screen). Changing it re-plans the notifications.
 */
@Composable
fun ReminderSettingsSection(prefs: ReminderPrefs, reminders: Reminders?, modifier: Modifier = Modifier) {
    val c = LgkTheme.colors
    var names by remember { mutableStateOf(prefs.showItemNames) }
    val change: (Boolean) -> Unit = {
        names = it
        prefs.showItemNames = it
        reminders?.reschedule()
    }
    Column(modifier) {
        Group(stringResource(R.string.reminder_settings_title), stringResource(R.string.reminder_settings_footer), "reminder-settings") {
            Row(
                Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Switch) { change(!names) }.testTag("reminder-show-names"),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(stringResource(R.string.reminder_show_names), color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                Switch(names, onCheckedChange = change, colors = lgkSwitchColors())
            }
        }
    }
}
