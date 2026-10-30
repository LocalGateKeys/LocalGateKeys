package app.localgatekeys.android.sync

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.core.lan.DeviceIdentity
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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The Sync screen's rollback buttons (iPhone `acknowledgeRollback` / `dismissPeerRollback`): "This was me" asks the
 * owner first and writes only after a passed check; Dismiss forgets the peer's remembered generation.
 */
class RollbackActionsTest {
    @get:Rule val tmp = TemporaryFolder()

    private lateinit var slots: SecretSlots
    private val scopes = ArrayList<CoroutineScope>()
    private val created = ArrayList<SyncCoordinator>()

    @Before fun setUp() {
        slots = SecretSlots(tmp.newFile("secrets.bin").also { it.delete() }, ByteArray(32) { 7 }, SystemRandomSource())
    }

    @After fun tearDown() {
        created.forEach { it.shutdown() }
        scopes.forEach { it.cancel() }
    }

    private fun test(body: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60_000) { body() } }

    private fun CoroutineScope.coordinator(store: ItemStore): SyncCoordinator {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        scopes.add(scope)
        val folder = MemoryFolder()
        val deps = SyncDependencies(
            slots = slots, folders = FakeFolders(folder), lan = FakeLan(), random = SystemRandomSource(),
            clock = TestClock(1_790_000_000), licenseKeys = emptyMap(), sleep = NoSleep().fn,
        )
        return SyncCoordinator(store, deps, scope, EnglishTxt()).also { created.add(it) }
    }

    private fun state(suspected: Long = 0, peers: Map<String, Long> = emptyMap()): SyncGroupState {
        val me = DeviceIdentity.generate(random = SystemRandomSource())
        return SyncGroupState("g".repeat(32), 1, ByteArray(32) { 1 }, me, slots.installId(), hasFolder = false)
            .copy(rollbackSuspected = suspected, peerGenerations = peers)
    }

    @Test fun keep_this_copy_asks_the_owner_then_clears_the_warning() = test {
        val store = LockedStore(StoreSnapshot(sync = state(suspected = 9)))
        val c = coordinator(store)
        var asked = 0
        assertTrue(c.acknowledgeRollback { asked++; true })
        assertEquals(1, asked)
        assertEquals(0L, store.snapshot.sync?.rollbackSuspected)
        assertEquals(SyncWording(EnglishTxt()).text(SyncIssue("rollback-acknowledged")), c.actionInfo.value)
        assertEquals(SyncCoordinator.Phase.IDLE, c.phase.value)
    }

    @Test fun a_failed_owner_check_writes_nothing() = test {
        val store = LockedStore(StoreSnapshot(sync = state(suspected = 9)))
        val c = coordinator(store)
        assertFalse(c.acknowledgeRollback { false })
        assertFalse(c.acknowledgeRollback { throw IllegalStateException("prompt failed") })
        assertEquals(0, store.commits)
        assertEquals(9L, store.snapshot.sync?.rollbackSuspected)
        assertNull(c.actionInfo.value)
        assertEquals(SyncCoordinator.Phase.IDLE, c.phase.value)
    }

    @Test fun no_open_warning_never_asks() = test {
        val c = coordinator(LockedStore(StoreSnapshot(sync = state())))
        var asked = false
        assertFalse(c.acknowledgeRollback { asked = true; true })
        assertFalse(asked)
    }

    @Test fun dismiss_forgets_the_peer_generation() = test {
        val store = LockedStore(StoreSnapshot(sync = state(peers = mapOf("peer-a" to 40L, "peer-b" to 7L))))
        val c = coordinator(store)
        assertFalse(c.dismissPeerRollback(""))
        assertTrue(c.dismissPeerRollback("peer-a"))
        assertEquals(mapOf("peer-b" to 7L), store.snapshot.sync?.peerGenerations)
    }

    @Test fun peer_rollback_views_carry_the_peer_id() {
        val views = SyncWording(EnglishTxt()).views(listOf(SyncIssue("peer-vault-rollback", "peer-a"), SyncIssue("vault-rollback")))
        assertEquals("vault-rollback", views[0].kind)
        assertEquals("", views[0].detail)
        assertEquals("peer-a", views.single { it.kind == "peer-vault-rollback" }.detail)
    }
}
