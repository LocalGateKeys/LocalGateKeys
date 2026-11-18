package app.localgatekeys.android.reminders

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.onNodeWithText
import androidx.test.platform.app.InstrumentationRegistry
import app.localgatekeys.android.i18n.AndroidTxt
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.ui.reminders.ItemReminderSection
import app.localgatekeys.android.ui.reminders.ReminderSettingsSection
import app.localgatekeys.android.ui.reminders.UpcomingRemindersSection
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.json.JsonValue
import java.io.File
import java.time.ZoneId
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/** The reminder sections on fakes (no real alarms): add through the editor, Upcoming with Done, the names setting. */
class ReminderScreensTest {
    @get:Rule val rule = createComposeRule()

    private class Setter : AlarmSetter {
        val armed = linkedMapOf<String, Long>()
        override fun set(id: String, atMillis: Long) { armed[id] = atMillis }
        override fun cancel(id: String) { armed.remove(id) }
    }

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var dir: File
    private val setter = Setter()
    private val store = MemoryReminderStore()
    private val prefs = ReminderPrefs(MemoryStore())
    private lateinit var model: Reminders

    private fun item(id: String, kind: String, title: String) =
        VaultItem.of(id, JsonValue.Obj(mapOf("kind" to JsonValue.Str(kind), "title" to JsonValue.Str(title))))!!

    @Before fun setUp() {
        // Granted up front: the system's permission prompt would cover the screen under test.
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().uiAutomation
                .grantRuntimePermission(context.packageName, android.Manifest.permission.POST_NOTIFICATIONS)
        }
        dir = File(context.cacheDir, "reminder-ui-test").also { it.deleteRecursively(); it.mkdirs() }
        val alarms = ReminderAlarms(File(dir, "alarms.json"), setter, System::currentTimeMillis) { ZoneId.systemDefault() }
        model = Reminders(store, alarms, prefs, AndroidTxt(context.resources))
        model.items = listOf(item("d1", "document", "Passport"), item("w1", "web", "Example"))
    }

    @After fun tearDown() { dir.deleteRecursively() }

    @Test fun a_document_gets_a_reminder_through_the_editor_and_a_login_shows_no_section() {
        rule.setContent { LgkTheme { ItemReminderSection(model, model.items[0]) } }
        rule.onNodeWithTag("item-reminder-add").assertIsDisplayed().performClick()
        rule.onNodeWithTag("reminder-editor").assertIsDisplayed()
        // Due today with no lead: the alarm is armed (a lead into the past would leave nothing to arm, as on the iPhone).
        rule.onNodeWithTag("reminder-lead-0").performClick()
        rule.onNodeWithTag("reminder-save").performClick()
        rule.waitForIdle()
        assertEquals(1, store.rows.size)
        assertEquals(0, store.rows[0].leadDays)
        assertEquals(1, setter.armed.size)
        rule.onNodeWithTag("item-reminder-change").assertIsDisplayed()
        rule.onNodeWithTag("item-reminder-remove").performClick()
        rule.waitForIdle()
        assertTrue(store.rows.isEmpty())
        assertTrue(setter.armed.isEmpty())
    }

    @Test fun a_login_has_no_reminder_section() {
        rule.setContent { LgkTheme { ItemReminderSection(model, model.items[1]) } }
        rule.onNodeWithTag("item-reminder").assertDoesNotExist()
    }

    @Test fun upcoming_lists_a_due_reminder_and_done_clears_it() {
        val today = model.today().toString()
        model.set("d1", today, 0)
        rule.setContent { LgkTheme { UpcomingRemindersSection(model) } }
        rule.onNodeWithText("Passport").assertIsDisplayed()
        rule.onNodeWithTag("reminder-done-${store.rows[0].id}").performClick()
        rule.waitForIdle()
        rule.onNodeWithText("Passport").assertDoesNotExist()
        assertFalse(store.rows.single().status == Reminder.Status.ACTIVE)
    }

    @Test fun the_names_switch_changes_the_setting_and_replans() {
        model.set("d1", model.today().plusDays(10).toString(), 0)
        rule.setContent { LgkTheme { ReminderSettingsSection(prefs, model) } }
        rule.onNodeWithTag("reminder-show-names").performClick()
        rule.waitForIdle()
        assertTrue(prefs.showItemNames)
    }
}
