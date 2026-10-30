package app.localgatekeys.android.ui.sync

import app.localgatekeys.android.i18n.appTxt
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextInput
import androidx.test.platform.app.InstrumentationRegistry
import app.localgatekeys.android.sync.FolderOpening
import app.localgatekeys.android.sync.LanTransporting
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncDependencies
import app.localgatekeys.android.sync.SyncWording
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.FolderAccess
import app.localgatekeys.core.sync.FolderAccessException
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import java.io.File
import java.util.Collections
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/** The Sync tab's cloud-folder card and password sheet over the real coordinator (scripted picker; no folder opens). */
class FolderJoinSheetTest {
    @get:Rule val rule = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private val dir = File(context.cacheDir, "folder-sheet-test").apply { deleteRecursively(); mkdirs() }

    private class FakeStore(@Volatile var snapshot: StoreSnapshot) : ItemStore {
        override fun load() = snapshot
        @Synchronized override fun commit(change: StoreChange) {
            snapshot = StoreSnapshot(change.records, change.meta, change.sync, snapshot.revision + 1)
        }
    }

    /** Opens nothing (every folder is missing); records the opens and what keeps its permission. */
    private class NoFolders : FolderOpening {
        val opened: MutableList<String> = Collections.synchronizedList(ArrayList())
        val kept: MutableList<String?> = Collections.synchronizedList(ArrayList())
        override fun open(uri: String): FolderAccess {
            opened.add(uri)
            throw FolderAccessException(FolderAccessException.Kind.IO, "the chosen folder is no longer available")
        }
        override fun keepOnly(uri: String?) { kept.add(uri) }
    }

    /** Answers every pick with [next] through a buffered result channel, like the real picker. */
    private class ScriptedPicker(var next: FolderPick) : FolderPicking {
        var picks = 0
        private val sink = Channel<FolderPick>(Channel.BUFFERED)
        override val results: Flow<FolderPick> = sink.receiveAsFlow()
        override fun pick() {
            picks++
            sink.trySend(next)
        }
        fun deliver(result: FolderPick) { sink.trySend(result) }
    }

    private val folders = NoFolders()

    @After fun tearDown() {
        scope.cancel()
        dir.deleteRecursively()
    }

    private fun coordinator(store: ItemStore): SyncCoordinator {
        val slots = SecretSlots(File(dir, "secrets.bin"), ByteArray(32) { 5 }, SystemRandomSource())
        val deps = SyncDependencies(
            slots = slots, folders = folders, lan = LanTransporting.UNAVAILABLE,
            random = SystemRandomSource(), clock = SystemClock(), licenseKeys = emptyMap(),
        )
        return SyncCoordinator(store, deps, scope, appTxt())
    }

    private fun show(c: SyncCoordinator, picker: FolderPicking) {
        rule.setContent { LgkTheme { SyncScreen(c, picker) } }
    }

    private fun scrollTo(text: String) {
        rule.onNodeWithTag("sync-list").performScrollToNode(hasText(text))
    }

    @Test fun the_card_says_google_drive_cannot_be_chosen_and_offers_join() {
        show(coordinator(FakeStore(StoreSnapshot())), ScriptedPicker(FolderPick.Cancelled))
        scrollTo(appTxt().s(FolderJoinText.GOOGLE_DRIVE_NOTICE))
        rule.onNodeWithText(appTxt().s(SyncScreenText.FOLDER_NOT_JOINED)).assertIsDisplayed()
        rule.onNodeWithText(appTxt().s(FolderJoinText.GOOGLE_DRIVE_NOTICE)).assertIsDisplayed()
        scrollTo("Join a folder…")
        rule.onNodeWithText("Join a folder…").assertIsDisplayed()
    }

    @Test fun picked_folder_asks_for_the_password_and_cancel_releases_it() {
        val picker = ScriptedPicker(FolderPick.Picked("content://test.provider/tree/f"))
        show(coordinator(FakeStore(StoreSnapshot())), picker)
        scrollTo("Join a folder…")
        rule.onNodeWithText("Join a folder…").performClick()
        rule.waitForIdle()
        assertEquals(1, picker.picks)
        rule.onNodeWithTag("folder-password").assertIsDisplayed()
        rule.onNodeWithText(appTxt().s(FolderJoinText.FOOTER)).assertIsDisplayed()
        rule.onNodeWithTag("folder-join").assertIsNotEnabled() // no password yet
        // A masked password field (the keyboard gets the password type and no suggestions).
        rule.onNodeWithTag("folder-password-field").assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Password))
        rule.onNodeWithTag("folder-password-field").performTextInput("typed then cancelled")
        rule.onNodeWithTag("folder-join").assertIsEnabled()
        rule.onNodeWithText("Cancel").performClick()
        rule.onNodeWithTag("folder-password").assertDoesNotExist()
        rule.waitUntil(5_000) { folders.kept.isNotEmpty() }
        assertEquals(listOf<String?>(null), folders.kept) // nothing is stored, so the picked folder's permission goes
        assertEquals(emptyList<String>(), folders.opened)
    }

    @Test fun join_reports_a_missing_folder_in_the_desktop_wording() {
        val c = coordinator(FakeStore(StoreSnapshot()))
        show(c, ScriptedPicker(FolderPick.Picked("content://test.provider/tree/f")))
        scrollTo("Join a folder…")
        rule.onNodeWithText("Join a folder…").performClick()
        rule.onNodeWithTag("folder-password-field").performTextInput("a sync password")
        rule.onNodeWithTag("folder-join").performClick()
        rule.onNodeWithTag("folder-password").assertDoesNotExist()
        rule.waitUntil(5_000) { c.actionError.value != null }
        assertEquals(listOf("content://test.provider/tree/f"), folders.opened)
        rule.onNodeWithText(SyncWording(appTxt()).errorText("folder-missing")).assertIsDisplayed()
        assertEquals("That folder does not exist or is not available.", c.actionError.value)
    }

    @Test fun a_failed_pick_says_the_folder_could_not_be_used() {
        show(coordinator(FakeStore(StoreSnapshot())), ScriptedPicker(FolderPick.Failed))
        scrollTo("Join a folder…")
        rule.onNodeWithText("Join a folder…").performClick()
        rule.waitForIdle()
        rule.onNodeWithTag("folder-password").assertDoesNotExist()
        rule.onNodeWithText(SyncWording(appTxt()).errorText("folder-error")).assertIsDisplayed()
    }

    @Test fun choosing_the_folder_again_asks_no_password() {
        val me = DeviceIdentity.generate(random = SystemRandomSource())
        val state = SyncGroupState("5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64", 1, ByteArray(32) { 1 }, me, "install-1", hasFolder = true)
        val c = coordinator(FakeStore(StoreSnapshot(sync = state)))
        show(c, ScriptedPicker(FolderPick.Picked("content://test.provider/tree/again")))
        rule.waitUntil(5_000) { c.membership.value.hasFolder }
        scrollTo("Choose the folder again…")
        rule.onNodeWithText(appTxt().s(SyncScreenText.FOLDER_PICK_AGAIN)).assertIsDisplayed() // no folder URI on this phone yet
        rule.onNodeWithText("Choose the folder again…").performClick()
        rule.waitUntil(5_000) { folders.opened.isNotEmpty() }
        rule.onNodeWithTag("folder-password").assertDoesNotExist()
        assertEquals(listOf("content://test.provider/tree/again"), folders.opened)
    }

    /** A pick redelivered to a new screen (activity recreated while the picker was open) still opens the sheet. */
    @Test fun a_pick_delivered_before_the_screen_collects_still_arrives() {
        val picker = ScriptedPicker(FolderPick.Cancelled)
        picker.deliver(FolderPick.Picked("content://test.provider/tree/late")) // buffered before any collector
        show(coordinator(FakeStore(StoreSnapshot())), picker)
        rule.waitUntil(5_000) { rule.onAllNodesWithTag("folder-password").fetchSemanticsNodes().isNotEmpty() }
        rule.onNodeWithTag("folder-password").assertIsDisplayed()
    }
}
