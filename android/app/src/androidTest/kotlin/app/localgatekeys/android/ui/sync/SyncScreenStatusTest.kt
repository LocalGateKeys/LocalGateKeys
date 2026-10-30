package app.localgatekeys.android.ui.sync

import app.localgatekeys.android.i18n.appTxt
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.platform.app.InstrumentationRegistry
import app.localgatekeys.android.sync.FolderOpening
import app.localgatekeys.android.sync.LanTransporting
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncDependencies
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import app.localgatekeys.android.sync.LanFailure
import app.localgatekeys.android.sync.LanSocketException
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.PinnedPeer
import app.localgatekeys.core.primitives.UnixClock
import androidx.compose.ui.test.assertContentDescriptionEquals
import androidx.compose.ui.test.assertTextEquals
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.launch
import org.junit.After
import org.junit.Rule
import org.junit.Test

/** The Sync tab's status and messages over the real coordinator (fake store, no transports). */
class SyncScreenStatusTest {
    @get:Rule val rule = createComposeRule()

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private val dir = File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir, "sync-screen-test").apply {
        deleteRecursively(); mkdirs()
    }

    private class FakeStore(@Volatile var snapshot: StoreSnapshot) : ItemStore {
        override fun load() = snapshot
        override fun commit(change: StoreChange) {
            snapshot = StoreSnapshot(change.records, change.meta, change.sync, snapshot.revision + 1)
        }
    }

    @After fun tearDown() {
        scope.cancel()
        dir.deleteRecursively()
    }

    private fun coordinator(
        store: ItemStore,
        lan: LanTransporting = LanTransporting.UNAVAILABLE,
        clock: UnixClock = SystemClock(),
    ): SyncCoordinator {
        val slots = SecretSlots(File(dir, "secrets.bin"), ByteArray(32) { 5 }, SystemRandomSource())
        val deps = SyncDependencies(
            slots = slots, folders = FolderOpening.UNAVAILABLE, lan = lan,
            random = SystemRandomSource(), clock = clock, licenseKeys = emptyMap(),
        )
        return SyncCoordinator(store, deps, scope, appTxt())
    }

    @Test fun not_joined_says_so_and_offers_no_sync_now() {
        val c = coordinator(FakeStore(StoreSnapshot()))
        rule.setContent { LgkTheme { SyncScreen(c) } }
        rule.onNodeWithText("Sync is not set up on this phone.").assertIsDisplayed()
        rule.onNodeWithText("Sync now").assertDoesNotExist()
    }

    /** Sync v2: connected to the PC, the phone shows the verification code until the PC's user chooses Accept. */
    @Test fun a_qr_join_shows_the_verification_code_while_waiting_for_accept() {
        val vectors = InstrumentationRegistry.getInstrumentation().context.assets
        val qr = vectors.open("vectors/sync/lan/qr_payload.txt").use { it.readBytes().toString(Charsets.UTF_8) }
        val accept = CountDownLatch(1)
        val lan = object : LanTransporting {
            override fun exchangeViews(
                peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: List<ItemState>, ownCounter: Long,
            ): List<ItemState> = emptyList()

            override fun enroll(endpoint: LanEndpoint, request: ByteArray, onConnected: () -> Unit): ByteArray {
                onConnected()
                accept.await(30, TimeUnit.SECONDS) // the PC has not chosen Accept yet
                throw LanSocketException("closed", LanFailure.CLOSED_BY_PEER)
            }
        }
        val c = coordinator(FakeStore(StoreSnapshot()), lan, clock = object : UnixClock { override val now: Long = 1_790_000_000 })
        rule.setContent { LgkTheme { SyncScreen(c) } }
        scope.launch { c.joinByQr(qr) }
        rule.waitUntil(10_000) { c.verificationCode.value != null && c.connecting.value == null }
        val code = c.verificationCode.value!!
        rule.onNodeWithTag("sync-verification-code").assertIsDisplayed()
            .assertTextEquals("${code.take(3)} ${code.drop(3)}")
            .assertContentDescriptionEquals("Verification code ${code.toList().joinToString(" ")}")
        rule.onNodeWithText("Check that the other device shows this code, then choose Accept there.").assertIsDisplayed()
        rule.onNodeWithText("Waiting for Accept on the other device…").assertIsDisplayed()
        accept.countDown()
        rule.waitUntil(10_000) { c.verificationCode.value == null }
        rule.onNodeWithTag("sync-verification-code").assertDoesNotExist()
    }

    @Test fun joined_syncs_now_and_shows_messages_in_desktop_wording() {
        val me = DeviceIdentity.generate(random = SystemRandomSource())
        // A folder group whose folder URI is gone: the run reports folder-missing.
        val state = SyncGroupState("5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64", 1, ByteArray(32) { 1 }, me, "install-1", hasFolder = true)
        val c = coordinator(FakeStore(StoreSnapshot(sync = state)))
        rule.setContent { LgkTheme { SyncScreen(c) } }
        rule.waitUntil(5_000) { c.membership.value.joined }
        rule.onNodeWithText("Not synced since you unlocked.").assertIsDisplayed()
        rule.onNodeWithText("Sync now").performClick()
        rule.waitUntil(10_000) { c.completedRuns.value > 0 }
        rule.onNodeWithTag("sync-messages").assertIsDisplayed()
        rule.onNodeWithText("The sync folder is not available. Check that the cloud app is running and the folder exists.")
            .assertIsDisplayed()
        rule.onNodeWithText("Last synced", substring = true).assertIsDisplayed()
    }
}
