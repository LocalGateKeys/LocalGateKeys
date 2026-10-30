package app.localgatekeys.android.ui.sync

import app.localgatekeys.android.i18n.appTxt
import android.content.Intent
import android.provider.Settings
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.performTextInput
import androidx.test.platform.app.InstrumentationRegistry
import app.localgatekeys.android.sync.FolderOpening
import app.localgatekeys.android.sync.LanSocketException
import app.localgatekeys.android.sync.LanTransporting
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncDependencies
import app.localgatekeys.android.sync.SyncWording
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.PinnedPeer
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Rule
import org.junit.Test

/**
 * The Sync tab's Wi-Fi card, scanner, paste sheet and Leave/Reset over the real coordinator (fake store; no socket
 * leaves the phone: the LAN seam here never dials). The camera permission is a fake, so the denied path runs without a
 * system dialog (spec section 7).
 */
class SyncScreenTest {
    @get:Rule val rule = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private val dir = File(context.cacheDir, "sync-screen-wifi-test").apply { deleteRecursively(); mkdirs() }

    private class FakeStore(@Volatile var snapshot: StoreSnapshot) : ItemStore {
        override fun load() = snapshot
        @Synchronized override fun commit(change: StoreChange) {
            snapshot = StoreSnapshot(change.records, change.meta, change.sync, snapshot.revision + 1)
        }
    }

    private class FakePermission(var granted: Boolean, private val answer: Boolean = false, private val camera: Boolean = true) : CameraPermission {
        val requests = AtomicInteger()
        val settingsOpened = AtomicInteger()
        override fun isGranted() = granted
        override fun request(onResult: (Boolean) -> Unit) {
            requests.incrementAndGet()
            granted = answer
            onResult(answer)
        }
        override fun openSettings() { settingsOpened.incrementAndGet() }
        override fun hasCamera() = camera
    }

    /** Never dials: every enrollment and exchange is refused at once. */
    private val noLan = object : LanTransporting {
        override fun exchangeViews(
            peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: List<ItemState>, ownCounter: Long,
        ): List<ItemState> = throw LanSocketException("no network in this test")

        override fun enroll(endpoint: LanEndpoint, request: ByteArray, onConnected: () -> Unit): ByteArray =
            throw LanSocketException("no network in this test")
    }

    @After fun tearDown() {
        scope.cancel()
        dir.deleteRecursively()
    }

    private fun coordinator(store: ItemStore): SyncCoordinator {
        val slots = SecretSlots(File(dir, "secrets.bin"), ByteArray(32) { 5 }, SystemRandomSource())
        val deps = SyncDependencies(
            slots = slots, folders = FolderOpening.UNAVAILABLE, lan = noLan,
            random = SystemRandomSource(), clock = SystemClock(), licenseKeys = emptyMap(),
        )
        return SyncCoordinator(store, deps, scope, appTxt())
    }

    private fun show(c: SyncCoordinator, permission: CameraPermission) {
        rule.setContent {
            LgkTheme { CompositionLocalProvider(LocalCameraPermission provides permission) { SyncScreen(c) } }
        }
    }

    @Test fun not_joined_offers_scan_and_paste() {
        val c = coordinator(FakeStore(StoreSnapshot()))
        show(c, FakePermission(granted = false))
        rule.onNodeWithText(appTxt().s(SyncScreenText.WIFI_NOT_JOINED)).assertIsDisplayed()
        rule.onNodeWithText("Scan QR code").assertIsDisplayed()
        rule.onNodeWithText("Paste code text").assertIsDisplayed()
        rule.onNodeWithTag("sync-list").performScrollToNode(hasText(appTxt().s(SyncScreenText.FOLDER_NOT_JOINED)))
        rule.onNodeWithText(appTxt().s(SyncScreenText.FOLDER_NOT_JOINED)).assertIsDisplayed()
        rule.onNodeWithText("Leave sync…").assertDoesNotExist()
    }

    @Test fun camera_denied_explains_and_opens_the_app_settings() {
        val c = coordinator(FakeStore(StoreSnapshot()))
        val permission = FakePermission(granted = false, answer = false)
        show(c, permission)
        // Asked only when the person taps scan.
        assertEquals(0, permission.requests.get())
        rule.onNodeWithText("Scan QR code").performClick()
        rule.waitForIdle()
        assertEquals(1, permission.requests.get())
        rule.onNodeWithTag("camera-denied").assertIsDisplayed()
        rule.onNodeWithText(appTxt().s(QrScanner.SYNC_DENIED_TEXT)).assertIsDisplayed()
        rule.onNodeWithText("Open Settings").performClick()
        assertEquals(1, permission.settingsOpened.get())
        // Cancel closes the scanner; nothing was joined.
        rule.onNodeWithText("Cancel").performClick()
        rule.onNodeWithTag("qr-scanner").assertDoesNotExist()
        rule.onNodeWithText("Sync is not set up on this phone.").assertIsDisplayed()
    }

    @Test fun settings_intent_opens_this_apps_page() {
        val intent = QrScanner.appSettingsIntent(context.packageName)
        assertEquals(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, intent.action)
        assertEquals("package:${context.packageName}", intent.data.toString())
        assertEquals(Intent.FLAG_ACTIVITY_NEW_TASK, intent.flags and Intent.FLAG_ACTIVITY_NEW_TASK)
        assertNotNull(intent.resolveActivity(context.packageManager))
    }

    @Test fun no_camera_says_so_and_points_to_paste() {
        val c = coordinator(FakeStore(StoreSnapshot()))
        show(c, FakePermission(granted = true, camera = false))
        rule.onNodeWithText("Scan QR code").performClick()
        rule.waitForIdle()
        rule.onNodeWithTag("qr-scanner").assertDoesNotExist()
        rule.onNodeWithText(appTxt().s(SyncScreenText.CAMERA_UNAVAILABLE)).assertIsDisplayed()
    }

    @Test fun granted_camera_shows_the_preview_until_cancel() {
        val c = coordinator(FakeStore(StoreSnapshot()))
        val permission = FakePermission(granted = true)
        show(c, permission)
        rule.onNodeWithText("Scan QR code").performClick()
        rule.waitForIdle()
        assertEquals(0, permission.requests.get()) // already allowed: no dialog
        rule.onNodeWithTag("camera-preview").assertIsDisplayed()
        rule.onNodeWithText("Cancel").performClick()
        rule.onNodeWithTag("qr-scanner").assertDoesNotExist()
    }

    @Test fun pasted_code_joins_with_desktop_wording_on_refusal() {
        val c = coordinator(FakeStore(StoreSnapshot()))
        show(c, FakePermission(granted = false))
        rule.onNodeWithText("Paste code text").performClick()
        rule.onNodeWithText(appTxt().s(SyncScreenText.PASTE_FOOTER)).assertIsDisplayed()
        rule.onNodeWithTag("paste-field").performTextInput("not a code")
        rule.onNodeWithText("Join").performClick()
        rule.onNodeWithTag("paste-code").assertDoesNotExist()
        rule.waitUntil(5_000) { c.actionError.value != null }
        rule.onNodeWithText(SyncWording(appTxt()).errorText("bad-offer")).assertIsDisplayed()
    }

    @Test fun leave_takes_two_confirmations_and_keeps_the_items() {
        val me = DeviceIdentity.generate(random = SystemRandomSource())
        val state = SyncGroupState("5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64", 1, ByteArray(32) { 1 }, me, "install-1", hasFolder = false)
        val store = FakeStore(StoreSnapshot(sync = state))
        val c = coordinator(store)
        show(c, FakePermission(granted = false))
        rule.waitUntil(5_000) { c.membership.value.joined }
        rule.onNodeWithText(appTxt().s(SyncScreenText.WIFI_FOLDER_ONLY)).assertIsDisplayed()
        rule.onNodeWithTag("sync-list").performScrollToNode(hasText("Leave sync…"))
        rule.onNodeWithText("Leave sync…").performClick()
        rule.onNodeWithText(appTxt().s(SyncWording.LEAVE_WIFI_TEXT)).assertIsDisplayed()
        rule.onNodeWithText("Continue").performClick()
        rule.onNodeWithText(appTxt().s(SyncWording.LEAVE_TEXT_2)).assertIsDisplayed()
        rule.onNode(hasText("Leave sync") and hasClickAction()).performClick()
        rule.waitUntil(5_000) { !c.membership.value.joined }
        rule.onNodeWithText(SyncWording(appTxt()).leftText).assertIsDisplayed()
        assertEquals(null, store.snapshot.sync)
    }

    @Test fun reset_cancel_changes_nothing() {
        val me = DeviceIdentity.generate(random = SystemRandomSource())
        val state = SyncGroupState("5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64", 1, ByteArray(32) { 1 }, me, "install-1", hasFolder = false)
        val store = FakeStore(StoreSnapshot(sync = state))
        val c = coordinator(store)
        show(c, FakePermission(granted = false))
        rule.waitUntil(5_000) { c.membership.value.joined }
        rule.onNodeWithTag("sync-list").performScrollToNode(hasText(appTxt().s(SyncScreenText.RESET_BUTTON)))
        rule.onNodeWithText(appTxt().s(SyncScreenText.RESET_BUTTON)).performClick()
        rule.onNodeWithText(appTxt().s(SyncWording.RESET_TEXT_1)).assertIsDisplayed()
        rule.onNodeWithText("Continue").performClick()
        rule.onNodeWithText(appTxt().s(SyncWording.RESET_TEXT_2)).assertIsDisplayed()
        rule.onNodeWithText("Cancel").performClick()
        rule.waitForIdle()
        assertNotNull(store.snapshot.sync)
    }
}
