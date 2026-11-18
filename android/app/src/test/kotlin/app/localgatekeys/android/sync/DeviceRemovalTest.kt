package app.localgatekeys.android.sync

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.android.vault.Slot
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.FolderLayout
import app.localgatekeys.core.sync.FolderSync
import app.localgatekeys.core.sync.KeptIdentity
import app.localgatekeys.core.sync.Removal
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Removing a device from the cloud-folder group on the phone (desktop `app/sync.remove_device`, `device_removal`):
 * the coordinator's Remove (one rotation, a signed notice), the removed phone's run reporting the notice, the watch
 * file, and the erase guard with its setting. Real Argon2id (production cost) runs for the rotation's two derivations.
 */
class DeviceRemovalTest {
    @get:Rule val tmp = TemporaryFolder()

    private val uri = "content://tree/OneDrive"
    private val pw2 = "violet tram sundial 1987 pebble"
    private val ids = listOf("A", "B", "C").map { SyncVectors.identity(it).deviceId }
    private lateinit var folder: MemoryFolder
    private lateinit var folders: FakeFolders
    private val scopes = ArrayList<CoroutineScope>()
    private val created = ArrayList<SyncCoordinator>()

    private class Phone(val who: String, val slots: SecretSlots, val store: LockedStore, val watch: RemovalWatchFile) {
        var notices = 0
    }

    @Before fun setUp() {
        folder = MemoryFolder()
        folder.put(FolderLayout.KEYRING_PATH, SyncVectors.data("keyring_epoch1.json"))
        folders = FakeFolders(folder)
    }

    @After fun tearDown() {
        created.forEach { it.shutdown() }
        scopes.forEach { it.cancel() }
    }

    private fun test(body: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(120_000) { body() } }

    /** A phone that already belongs to the epoch-1 group as [who] (A, B or C of the vectors), folder chosen. */
    private fun phone(who: String): Phone {
        val dir = tmp.newFolder(who)
        val slots = SecretSlots(File(dir, "secrets.bin"), ByteArray(32) { 3 }, SystemRandomSource())
        slots.write(Slot.FOLDER_URI, uri.toByteArray(Charsets.UTF_8))
        val identity: DeviceIdentity = SyncVectors.identity(who)
        val gk = SyncVectors.hex(SyncVectors.str(SyncVectors.obj(SyncVectors.obj(SyncVectors.json("expected.json")["epochs"])["1"])["group_key_hex"]))
        val state = SyncGroupState(
            groupId = SyncVectors.str(SyncVectors.json("expected.json")["group_id"]), epoch = 1, key = gk, identity = identity,
            installId = slots.installId(), membersEpoch = 1, members = ids.sorted(), keyring = SyncVectors.data("keyring_epoch1.json"),
        )
        return Phone(who, slots, LockedStore(StoreSnapshot(sync = state)), RemovalWatchFile(File(dir, "Vault.sync-watch.json")))
    }

    private fun CoroutineScope.coordinator(p: Phone): SyncCoordinator {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        scopes.add(scope)
        val deps = SyncDependencies(
            slots = p.slots, folders = folders, lan = FakeLan(), random = SystemRandomSource(), clock = TestClock(1_790_000_000),
            licenseKeys = emptyMap(), sleep = NoSleep().fn, removalWatch = p.watch, onRemovalNotice = { p.notices++ },
            strongSyncPassword = { it.length >= 12 },
        )
        return SyncCoordinator(p.store, deps, scope, EnglishTxt()).also { created.add(it) }
    }

    private fun ringMembers(): Set<String> =
        (SyncVectors.obj(Keyring.parse(folder.get(FolderLayout.KEYRING_PATH)!!))["members"] as JsonValue.Arr).items
            .map { SyncVectors.str(SyncVectors.obj(it)["device_id"]) }.toSet()

    private fun notice(id: String) = folder.get("LocalGateKeys Sync/removed/$id.lgkremoved")

    @Test fun remove_rotates_and_writes_a_signed_notice() = test {
        val a = phone("A")
        val c = coordinator(a)
        c.sync()
        assertNotNull("every run keeps the watch file", a.watch.load())
        c.refreshMembership()
        assertEquals(ids.filter { it != ids[0] }.sorted(), c.membership.value.members)
        assertTrue(c.membership.value.names.isNotEmpty())
        val ok = c.removeDevices(listOf(ids[2]), pw2)
        assertTrue(c.actionError.value ?: "", ok)
        assertTrue(c.actionInfo.value!!, c.actionInfo.value!!.endsWith("was removed from sync."))
        assertFalse(ids[2] in ringMembers())
        val (n, _, _) = Removal.parseNotice(notice(ids[2])!!)
        assertEquals(ids[0], n.signer)
        assertEquals(2L, n.epoch)
        assertNull("kept members get no notice", notice(ids[1]))
        assertEquals(2L, a.store.snapshot.sync!!.epoch)
        assertEquals(listOf(ids[1]), c.membership.value.members)
    }

    @Test fun remove_refusals_change_nothing() = test {
        val a = phone("A")
        val c = coordinator(a)
        c.sync()
        val before = folder.snapshot()
        val epoch = a.store.snapshot.sync!!.epoch
        assertFalse(c.removeDevices(listOf(ids[2]), "short"))
        assertEquals("The sync password needs at least 12 characters and a Strong rating.", c.actionError.value)
        assertFalse(c.removeDevices(listOf(ids[0]), pw2))
        assertEquals("This phone cannot remove itself. Use Leave sync instead.", c.actionError.value)
        assertEquals(before, folder.snapshot())
        assertEquals(epoch, a.store.snapshot.sync!!.epoch)
    }

    @Test fun removed_phone_reports_the_notice_and_the_guard_erases() = test {
        val a = phone("A")
        val cPhone = phone("C")
        val ca = coordinator(a)
        val cc = coordinator(cPhone)
        ca.sync()
        cc.sync()
        assertEquals(0, cPhone.notices)
        assertTrue(ca.removeDevices(listOf(ids[2]), pw2))
        cc.sync()
        assertEquals("the run reported the verified notice", 1, cPhone.notices)
        assertEquals(SyncWording.REMOVAL_NOTICE_KIND, cc.issues.value.first().kind)
        assertEquals(SyncWording.Severity.ERROR, cc.issues.value.first().severity)

        val settings = AppSettings(app.localgatekeys.android.settings.MemoryStore())
        var erased = 0
        val clock = TestClock(1_790_000_000)
        val guard = RemovalGuard(settings, cPhone.watch, folders, erase = { erased++; true }, clock = clock)
        assertNotNull(guard.verified(null))
        assertNull("another installation's id never matches", guard.verified("another-install"))
        settings.eraseOnSyncRemoval = false
        assertEquals(RemovalGuard.Outcome.KEPT, guard.check())
        assertEquals(0, erased)
        settings.eraseOnSyncRemoval = true
        assertEquals("checked at most every 5 minutes", RemovalGuard.Outcome.NONE, guard.check())
        assertEquals(RemovalGuard.Outcome.ERASED, guard.check(force = true))
        assertEquals(1, erased)
        assertTrue(settings.deviceErasedNotice)
        assertEquals(1, guard.erasures.value)
        clock.now += RemovalGuard.INTERVAL_SECONDS
        assertEquals(RemovalGuard.Outcome.ERASED, guard.check())
    }

    // Design 2026-11-17 keep-device-id-on-rejoin, rule 2: a removed device never gets back in through its kept identity.

    @Test fun a_phone_removed_after_it_left_rejoins_under_a_new_id_and_drops_the_kept_one() = test {
        val a = phone("A")
        val cPhone = phone("C")
        val ca = coordinator(a)
        val cc = coordinator(cPhone)
        ca.sync(); cc.sync()
        cc.leave() // C left before it was removed: it keeps its identity
        assertEquals(ids[2], cPhone.slots.keptIdentity()?.deviceId)
        assertTrue(ca.removeDevices(listOf(ids[2]), pw2))
        assertNotNull(notice(ids[2]))
        // Joining with the new password: the folder holds a removal notice for the kept id, so a new identity joins.
        assertTrue(cc.actionError.value ?: "", cc.joinFolder(uri, pw2))
        val joined = cPhone.store.snapshot.sync!!
        assertNotEquals(ids[2], joined.deviceId)
        assertFalse(ids[2] in ringMembers())
        assertTrue(joined.deviceId in ringMembers())
        assertNull(cPhone.slots.keptIdentity())
    }

    @Test fun a_verified_removal_notice_drops_the_kept_identity_and_a_leave_after_it_keeps_none() = test {
        val a = phone("A")
        val cPhone = phone("C")
        val ca = coordinator(a)
        val cc = coordinator(cPhone)
        ca.sync(); cc.sync()
        assertTrue(ca.removeDevices(listOf(ids[2]), pw2))
        // An identity of this id still kept (a drop that failed earlier): the run that verifies the notice drops it.
        cPhone.slots.setKeptIdentity(KeptIdentity.of(cPhone.store.snapshot.sync!!))
        cc.sync()
        assertEquals(1, cPhone.notices)
        assertNull(cPhone.slots.keptIdentity())
        // The phone stays in its removed state (erase setting off); leaving it now keeps nothing.
        cc.leave()
        assertNull(cPhone.store.snapshot.sync)
        assertNull(cPhone.slots.keptIdentity())
    }

    @Test fun kept_phone_and_unrelated_issues_never_erase() = test {
        val a = phone("A")
        val b = phone("B")
        val cPhone = phone("C")
        val ca = coordinator(a)
        val cb = coordinator(b)
        val cc = coordinator(cPhone)
        ca.sync(); cb.sync(); cc.sync()
        assertTrue(ca.removeDevices(listOf(ids[2]), pw2))
        // The notice is gone (the folder holds only the rotation): C sees rejoin-required, which never erases.
        folder.remove("LocalGateKeys Sync/removed/${ids[2]}.lgkremoved")
        cc.sync()
        cb.sync()
        assertEquals(0, cPhone.notices)
        assertEquals(0, b.notices)
        var erased = 0
        val settings = AppSettings(app.localgatekeys.android.settings.MemoryStore())
        assertEquals(RemovalGuard.Outcome.NONE, RemovalGuard(settings, cPhone.watch, folders, { erased++; true }, TestClock(0)).check())
        assertEquals(RemovalGuard.Outcome.NONE, RemovalGuard(settings, b.watch, folders, { erased++; true }, TestClock(0)).check())
        assertEquals(0, erased)
        assertFalse(settings.deviceErasedNotice)
    }

    @Test fun failed_erase_shows_no_notice_and_is_retried_at_once() = test {
        val a = phone("A")
        val b = phone("B")
        val cPhone = phone("C")
        val ca = coordinator(a)
        val cb = coordinator(b)
        val cc = coordinator(cPhone)
        ca.sync(); cb.sync(); cc.sync()
        assertTrue(ca.removeDevices(listOf(ids[2]), pw2))
        cc.sync()
        val settings = AppSettings(app.localgatekeys.android.settings.MemoryStore())
        var attempts = 0
        var succeed = false
        val guard = RemovalGuard(settings, cPhone.watch, folders, { attempts++; succeed }, TestClock(1_790_000_000))
        assertEquals(RemovalGuard.Outcome.FAILED, guard.check())
        assertFalse("nothing was erased: no notice", settings.deviceErasedNotice)
        succeed = true
        assertEquals("no 5-minute wait after a failure", RemovalGuard.Outcome.ERASED, guard.check())
        assertEquals(2, attempts)
        assertTrue(settings.deviceErasedNotice)
    }

    @Test fun leave_deletes_the_watch_file() = test {
        val cPhone = phone("C")
        val cc = coordinator(cPhone)
        cc.sync()
        assertTrue(cPhone.watch.file.isFile)
        cc.leave()
        assertFalse(cPhone.watch.file.exists())
        // A notice written after leaving never erases this phone.
        val ca = coordinator(phone("A"))
        ca.sync()
        assertTrue(ca.removeDevices(listOf(ids[2]), pw2))
        assertNotNull(notice(ids[2]))
        var erased = 0
        val guard = RemovalGuard(AppSettings(app.localgatekeys.android.settings.MemoryStore()), cPhone.watch, folders, { erased++; true }, TestClock(0))
        assertEquals(RemovalGuard.Outcome.NONE, guard.check())
        assertEquals(0, erased)
    }

    @Test fun members_added_elsewhere_are_confirmed_on_request() = test {
        val a = phone("A")
        val c = coordinator(a)
        // D joins with the sync password (someone holding it).
        val d = DeviceIdentity.generate("d4444444-0000-4000-8000-00000000000d", SystemRandomSource())
        val ring = Keyring.parse(folder.get(FolderLayout.KEYRING_PATH)!!)
        val (ring2, _) = Keyring.join(
            ring, SyncVectors.str(SyncVectors.json("expected.json")["password_epoch1"]), d, "Tablet", SystemRandomSource(), TestClock(1_790_000_100),
        )
        folder.put(FolderLayout.KEYRING_PATH, app.localgatekeys.core.json.CanonicalJson.encode(ring2, app.localgatekeys.core.json.Dialect.UTF8))
        c.sync()
        c.refreshMembership()
        assertEquals(listOf(d.deviceId), c.membership.value.unconfirmed)
        assertFalse(d.deviceId in a.watch.load()!!.signers)
        assertTrue(c.confirmMembers(listOf(d.deviceId)))
        assertEquals(emptyList<String>(), c.membership.value.unconfirmed)
        assertEquals("Tablet", c.membership.value.names[d.deviceId])
    }
}
