package app.localgatekeys.android.sync

import app.localgatekeys.android.sync.SyncCoordinator.Trigger
import app.localgatekeys.android.ui.sync.FolderJoinFlow
import app.localgatekeys.android.ui.sync.FolderPasswordForm
import app.localgatekeys.android.ui.sync.FolderJoinText
import app.localgatekeys.android.ui.sync.FolderPick
import app.localgatekeys.android.ui.sync.FolderPickResults
import app.localgatekeys.android.ui.sync.SyncScreenText
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.android.vault.Slot
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.PinnedPeer
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import app.localgatekeys.core.sync.SyncIssue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The cloud-folder join sheet's flow (picker -> password -> join or attach; re-pick without a password) over the real
 * coordinator and an in-memory folder, plus the persisted-permission bookkeeping: the folder permission that stays is
 * always the one in the folder slot (or none).
 */
class FolderJoinFlowTest {
    @get:Rule val tmp = TemporaryFolder()

    private lateinit var slots: SecretSlots
    private lateinit var folder: MemoryFolder
    private lateinit var folders: FakeFolders
    private lateinit var lan: FakeLan
    private lateinit var clock: TestClock
    private val scopes = ArrayList<CoroutineScope>()
    private val created = ArrayList<SyncCoordinator>()

    @Before fun setUp() {
        slots = SecretSlots(tmp.newFile("secrets.bin").also { it.delete() }, ByteArray(32) { 5 }, SystemRandomSource())
        folder = MemoryFolder(); folders = FakeFolders(folder); lan = FakeLan()
        clock = TestClock(1_790_000_000 + 1000)
    }

    @After fun tearDown() {
        created.forEach { it.shutdown() }
        scopes.forEach { it.cancel() }
    }

    private fun test(body: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60_000) { body() } }

    private fun CoroutineScope.coordinator(store: ItemStore): SyncCoordinator {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        scopes.add(scope)
        val deps = SyncDependencies(
            slots = slots, folders = folders, lan = lan, random = SystemRandomSource(), clock = clock,
            licenseKeys = emptyMap(), sleep = NoSleep().fn,
        )
        return SyncCoordinator(store, deps, scope).also { created.add(it) }
    }

    private fun seedEpoch1Folder() {
        folder.put("LocalGateKeys Sync/keyring.lgkkeys", SyncVectors.data("keyring_epoch1.json"))
        for (who in listOf("A", "B", "C")) {
            val id = SyncVectors.identity(who).deviceId
            folder.put("LocalGateKeys Sync/devices/$id.lgksync", SyncVectors.data("devices/$who.lgksync"))
        }
    }

    private fun folderUri(): String? = slots.read(Slot.FOLDER_URI)?.toString(Charsets.UTF_8)

    /** A vault that joined the epoch-1 folder group through [uri]. */
    private suspend fun CoroutineScope.joined(store: LockedStore, uri: String = "content://tree/one"): Pair<SyncCoordinator, FolderJoinFlow> {
        seedEpoch1Folder()
        val c = coordinator(store)
        val flow = FolderJoinFlow(c)
        flow.picked(FolderPick.Picked(uri))
        flow.form.value!!.update(SyncVectors.PASSWORD)
        assertTrue(c.actionError.value ?: "", flow.join())
        return c to flow
    }

    @Test fun picking_a_folder_asks_for_the_password_then_joins() = test {
        seedEpoch1Folder()
        val store = LockedStore()
        val c = coordinator(store)
        val flow = FolderJoinFlow(c)
        flow.picked(FolderPick.Picked("content://tree/one"))
        val form = flow.form.value!!
        assertEquals("content://tree/one", form.uri)
        assertTrue(folders.opened.isEmpty()) // nothing is read before the password
        assertFalse(form.canJoin)
        assertFalse(flow.join()) // Join is disabled without a password
        assertTrue(folders.opened.isEmpty())

        form.update(SyncVectors.PASSWORD)
        assertTrue(form.canJoin)
        assertTrue(c.actionError.value ?: "", flow.join())
        assertNull(flow.form.value) // the sheet closes
        assertEquals("", form.password.value) // the password is cleared after use
        assertTrue(store.snapshot.sync!!.hasFolder)
        assertEquals("content://tree/one", folderUri())
        assertEquals("content://tree/one", folders.kept.last()) // only the joined folder's permission stays
        assertTrue(c.membership.value.hasFolderUri)
        assertEquals("This phone now syncs through the cloud folder.", c.actionInfo.value)
    }

    @Test fun picking_after_a_qr_join_attaches_with_the_password() = test {
        val x = SyncVectors.json("expected.json")
        val existing = SyncVectors.obj(x["existing_group"])
        val gid = SyncVectors.str(existing["group_id"])
        val key = SyncVectors.hex(SyncVectors.str(SyncVectors.obj(SyncVectors.obj(existing["epochs"])["1"])["group_key_hex"]))
        val me = DeviceIdentity.generate(random = SystemRandomSource())
        val store = LockedStore(StoreSnapshot(sync = SyncGroupState(gid, 1, key, me, slots.installId(), hasFolder = false)))
        val a = SyncVectors.identity("A")
        val peer = PinnedPeer(a.deviceId, gid, a.signingPublicKey, a.exchangePublicKey, LanEndpoint("192.168.1.20", 47821))
        slots.setPairedPeer(peer)
        folder.put("LocalGateKeys Sync/keyring.lgkkeys", SyncVectors.data("keyring_existing_epoch1.json"))

        val c = coordinator(store)
        c.refreshMembership()
        val flow = FolderJoinFlow(c)
        flow.picked(FolderPick.Picked("content://tree/attach"))
        val form = flow.form.value!! // joined by QR but no folder yet: the password is needed (attach)
        form.update(SyncVectors.str(SyncVectors.obj(existing["attach"])["password"]))
        assertTrue(c.actionError.value ?: "", flow.join())
        val state = store.snapshot.sync!!
        assertTrue(state.hasFolder)
        assertEquals(me, state.identity) // attached, not joined again
        assertEquals(peer, slots.pairedPeer()) // the Wi-Fi pairing stays
        assertEquals("content://tree/attach", folderUri())
        assertEquals("content://tree/attach", folders.kept.last())
    }

    @Test fun picking_the_folder_again_needs_no_password_and_releases_the_old_one() = test {
        val store = LockedStore()
        val (c, flow) = joined(store, "content://tree/one")
        val identity = store.snapshot.sync!!.identity
        flow.picked(FolderPick.Picked("content://tree/two"))
        assertNull(flow.form.value) // no password sheet
        assertNull(c.actionError.value)
        assertEquals("content://tree/two", folderUri())
        assertEquals(identity, store.snapshot.sync!!.identity) // no new join
        assertEquals("content://tree/two", folders.kept.last()) // the first folder's permission is released
    }

    @Test fun a_wrong_password_releases_the_picked_folder() = test {
        seedEpoch1Folder()
        val store = LockedStore()
        val c = coordinator(store)
        val flow = FolderJoinFlow(c)
        flow.picked(FolderPick.Picked("content://tree/one"))
        flow.form.value!!.update("not the sync password")
        assertFalse(flow.join())
        assertEquals("That sync password is not right for this folder.", c.actionError.value)
        assertNull(flow.form.value)
        assertEquals(0, store.commits)
        assertNull(folderUri())
        assertEquals(listOf<String?>(null), folders.kept) // nothing is stored, so no permission stays
    }

    @Test fun the_password_backoff_also_releases_the_picked_folder() = test {
        seedEpoch1Folder()
        val c = coordinator(LockedStore())
        val flow = FolderJoinFlow(c)
        repeat(5) {
            flow.picked(FolderPick.Picked("content://tree/one"))
            flow.form.value!!.update("nope nope nope")
            flow.join()
        }
        folders.kept.clear()
        flow.picked(FolderPick.Picked("content://tree/one"))
        flow.form.value!!.update(SyncVectors.PASSWORD)
        assertFalse(flow.join())
        assertEquals(SyncWording.PASSWORD_BACKOFF_TEXT, c.actionError.value)
        assertEquals(listOf<String?>(null), folders.kept)
    }

    @Test fun cancelling_the_password_sheet_releases_the_picked_folder() = test {
        seedEpoch1Folder()
        val store = LockedStore()
        val c = coordinator(store)
        val flow = FolderJoinFlow(c)
        flow.picked(FolderPick.Picked("content://tree/one"))
        val form = flow.form.value!!
        form.update("typed then cancelled")
        flow.cancel()
        assertNull(flow.form.value)
        assertEquals("", form.password.value)
        assertTrue(folders.opened.isEmpty())
        assertEquals(listOf<String?>(null), folders.kept)
        assertEquals(0, store.commits)
    }

    @Test fun cancelling_the_sheet_keeps_the_folder_in_use() = test {
        val (c, flow) = joined(LockedStore(), "content://tree/one")
        folders.kept.clear()
        // A sheet cancelled while a folder is in use keeps that folder's permission, and only that one.
        flow.cancel()
        assertEquals(listOf<String?>("content://tree/one"), folders.kept)
        // After leaving, the slot is empty: a cancelled pick keeps nothing.
        c.leave()
        folders.kept.clear()
        flow.picked(FolderPick.Picked("content://tree/two"))
        flow.cancel()
        assertEquals(listOf<String?>(null), folders.kept)
    }

    @Test fun a_cancelled_pick_changes_nothing_and_a_failed_pick_says_so() = test {
        val c = coordinator(LockedStore())
        val flow = FolderJoinFlow(c)
        flow.picked(FolderPick.Cancelled)
        assertNull(flow.form.value); assertNull(flow.error.value)
        flow.picked(FolderPick.Failed)
        assertNull(flow.form.value)
        assertEquals(SyncWording.errorText("folder-error"), flow.error.value)
        assertEquals("The folder could not be used. Check that it exists and is writable.", flow.error.value)
        flow.picked(FolderPick.Cancelled) // the next pick clears the message
        assertNull(flow.error.value)
        assertTrue(folders.opened.isEmpty())
    }

    @Test fun revoked_folder_permission_is_folder_missing() = test {
        val store = LockedStore()
        val (c, _) = joined(store, "content://tree/one")
        c.sync(Trigger.MANUAL)
        assertTrue(c.issues.value.none { it.kind == "folder-missing" })
        val commits = store.commits
        val before = store.snapshot

        // The person removes the app's access to the folder in system settings (or the provider forgets it).
        folders.revoked.add("content://tree/one")
        c.refreshMembership()
        assertTrue(c.membership.value.hasFolder)
        assertFalse(c.membership.value.hasFolderUri) // the card asks to choose the folder again
        c.sync(Trigger.MANUAL)
        assertEquals(listOf("folder-missing"), c.issues.value.map { it.kind })
        assertEquals(
            "The sync folder is not available. Check that the cloud app is running and the folder exists.",
            c.issues.value.first().text,
        )
        assertEquals(SyncWording.text(SyncIssue("folder-missing")), c.issues.value.first().text)
        assertEquals(SyncWording.Severity.ERROR, c.issues.value.first().severity)
        assertEquals(commits, store.commits) // nothing written
        assertEquals(before, store.snapshot)
    }

    @Test fun leave_and_reset_release_the_folder_permission() = test {
        val store = LockedStore()
        val (c, _) = joined(store)
        folders.kept.clear()
        c.leave()
        assertNull(folderUri())
        assertEquals(listOf<String?>(null), folders.kept)

        val (c2, _) = joined(LockedStore(), "content://tree/two")
        folders.kept.clear()
        c2.reset()
        assertEquals(listOf<String?>(null), folders.kept)
        assertNull(folderUri())
    }

    @Test fun the_password_form_never_shows_the_password() {
        val form = FolderPasswordForm("content://com.example.provider/tree/secret%2Fpath")
        form.update("correct horse battery staple 42")
        val text = form.toString()
        assertFalse(text, text.contains("correct horse"))
        assertFalse(text, text.contains("secret"))
        assertEquals("correct horse battery staple 42", form.take())
        assertEquals("", form.password.value)
        val picked = FolderPick.Picked("content://com.example.provider/tree/secret%2Fpath").toString()
        assertFalse(picked, picked.contains("secret"))
    }

    @Test fun a_pick_returning_after_the_lock_is_dropped_without_persisting() {
        var persisted = 0
        val persist: (String) -> String = { persisted++; "content://tree/$it" }
        assertNull(FolderPickResults.decide("x", stillUnlocked = false, persist = persist))
        assertNull(FolderPickResults.decide(null, stillUnlocked = false, persist = persist))
        assertEquals(0, persisted)
        assertEquals(FolderPick.Cancelled, FolderPickResults.decide(null, stillUnlocked = true, persist = persist))
        val picked = FolderPickResults.decide("x", stillUnlocked = true, persist = persist)
        assertEquals("content://tree/x", (picked as FolderPick.Picked).uri)
        assertEquals(1, persisted)
        assertEquals(FolderPick.Failed, FolderPickResults.decide("y", stillUnlocked = true) { throw SecurityException("no grant") })
    }

    @Test fun cloud_folder_examples_follow_ruling_20_amended() {
        assertEquals(
            "Choose the folder your cloud app syncs (OneDrive, Dropbox, Nextcloud), the one that holds LocalGateKeys Sync, " +
                "and enter the sync password.",
            SyncScreenText.FOLDER_NOT_JOINED,
        )
        assertEquals(
            "Google Drive's Android app does not let other apps choose a folder in it. To sync with Google Drive, use Wi-Fi " +
                "sync, or a folder-sync app that keeps a folder on this phone in step with Google Drive.",
            FolderJoinText.GOOGLE_DRIVE_NOTICE,
        )
    }
}
