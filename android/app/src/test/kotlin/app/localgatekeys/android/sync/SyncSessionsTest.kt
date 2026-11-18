package app.localgatekeys.android.sync

import app.localgatekeys.android.backup.INSTALL_ID
import app.localgatekeys.android.backup.TEST_KDF
import app.localgatekeys.android.backup.BackupExporter
import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.editor.numberedNotes
import app.localgatekeys.android.editor.pairedSnapshot
import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.trash.InMemoryLocalData
import app.localgatekeys.android.trash.PhoneTrash
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.core.backup.PhoneBackupFormat
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.android.unlock.MemoryItemStore
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.unlock.UnlockedVault
import app.localgatekeys.android.unlock.Unlocker
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.core.primitives.SystemRandomSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** One coordinator per unlock, shut down by the lock before the vault's own gates close. */
class SyncSessionsTest {
    @get:Rule val tmp = TemporaryFolder()

    private fun vault(): UnlockedVault {
        val key = ByteArray(32) { 9 }
        return UnlockedVault(MemoryItemStore(), SecretSlots(tmp.newFile().also { it.delete() }, key, SystemRandomSource()), key.copyOf())
    }

    private class RecordingUnlocker(val log: MutableList<String>, val syncOpen: () -> Boolean) : Unlocker {
        override suspend fun unlock(reason: String): UnlockedVault = error("not used")
        override fun lock() { log.add(if (syncOpen()) "vault closed while sync open" else "vault closed") }
        override fun discard(vault: UnlockedVault) { log.add("discard") }
    }

    @Test fun one_coordinator_per_unlock_and_the_lock_shuts_it_first() = runBlocking {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        val made = ArrayList<SyncCoordinator>()
        val sessions = SyncSessions { v ->
            SyncCoordinator(
                v.store,
                SyncDependencies(
                    slots = v.slots, folders = FakeFolders(MemoryFolder()), lan = FakeLan(), random = SystemRandomSource(),
                    clock = TestClock(0), licenseKeys = emptyMap(),
                ),
                scope,
                EnglishTxt(),
            ).also { made += it }
        }
        val first = vault()
        val a = sessions.forVault(first)
        assertSame(a, sessions.forVault(first)) // a recomposition or a new activity keeps the unlock's coordinator
        assertTrue(a.gate.isOpen)
        sessions.appOpen(first)
        sessions.appOpen(first) // a recreated activity: no second unlock sync
        assertEquals(1, a.completedRuns.value)
        // Back from the background while still unlocked: one more run, for the session that was open then only.
        sessions.foreground(a)
        assertEquals(2, a.completedRuns.value)
        sessions.foreground(null)
        assertEquals(2, a.completedRuns.value)

        val log = ArrayList<String>()
        val unlocker = sessions.wrap(RecordingUnlocker(log) { a.gate.isOpen })
        // The lock: the coordinator's gate closes before the vault's gates (nothing commits in between).
        log.clear()
        unlocker.lock()
        assertFalse(a.gate.isOpen)
        assertEquals(listOf("vault closed"), log)
        assertNull(sessions.current)

        val second = vault()
        val b = sessions.forVault(second)
        assertNotSame(a, b)
        sessions.foreground(a) // the session that was open when the app came back has locked since
        sessions.foreground(b) // before this unlock's own sync: that one covers it
        assertEquals(0, b.completedRuns.value)
        // Another vault replaces the old session (the old one shut down).
        val c = sessions.forVault(vault())
        assertFalse(b.gate.isOpen)
        assertTrue(c.gate.isOpen)
        unlocker.discard(second)
        assertEquals("discard goes to the real unlocker", "discard", log.last())
        assertEquals(3, made.size)
        sessions.end()
        assertFalse(c.gate.isOpen)
        scope.cancel()
    }
    /**
     * A lock between the unlock's IO hops and its `appOpen` (MainActivity's LaunchedEffect) must not build a coordinator
     * for the closed vault: after [SyncSessions.end] that vault only ever gets the shut-down one, and nothing syncs.
     */
    @Test fun an_ended_vault_never_gets_a_new_coordinator() = runBlocking {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        val made = ArrayList<SyncCoordinator>()
        val lan = FakeLan()
        val sessions = SyncSessions { v ->
            SyncCoordinator(
                v.store,
                SyncDependencies(
                    slots = v.slots, folders = FakeFolders(MemoryFolder()), lan = lan, random = SystemRandomSource(),
                    clock = TestClock(0), licenseKeys = emptyMap(),
                ),
                scope,
                EnglishTxt(),
            ).also { made += it }
        }
        val first = vault()
        val a = sessions.forVault(first)
        sessions.end() // the lock
        assertSame(a, sessions.forVault(first))
        assertFalse(sessions.forVault(first).gate.isOpen)
        sessions.appOpen(first) // the unlock's sync arriving late: nothing runs
        assertEquals(0, a.completedRuns.value)
        assertEquals(1, made.size)
        assertNull(sessions.current)
        sessions.endAndWait()
        assertSame("still refused after the erase wait", a, sessions.forVault(first))
        assertEquals(1, made.size)
        // The next unlock (a new vault) gets a new coordinator.
        val b = sessions.forVault(vault())
        assertNotSame(a, b)
        assertTrue(b.gate.isOpen)
        assertEquals(2, made.size)
        sessions.end()
        scope.cancel()
    }

    /** Erase: the lock ends the session first; endAndWait then waits for that coordinator's work in flight. */
    @Test fun end_and_wait_waits_for_the_ended_sessions_work() = runBlocking {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        val lan = FakeLan()
        val gate = AsyncGate()
        lan.enrollHold = { gate.await() }
        val sessions = SyncSessions { v ->
            SyncCoordinator(
                v.store,
                SyncDependencies(
                    slots = v.slots, folders = FakeFolders(MemoryFolder()), lan = lan, random = SystemRandomSource(),
                    clock = TestClock(SyncVectors.lanNow()), licenseKeys = emptyMap(),
                ),
                scope,
                EnglishTxt(),
            )
        }
        val c = sessions.forVault(vault())
        val join = async { c.joinByQr(SyncVectors.qrText()) }
        withTimeout(20_000) { while (gate.waiting != 1) delay(1) }
        sessions.wrap(RecordingUnlocker(ArrayList()) { c.gate.isOpen }).lock() // as eraseAndLock: lock first
        assertFalse(c.gate.isOpen)
        var done = false
        val waiting = async { sessions.endAndWait(); done = true }
        delay(200)
        assertFalse("endAndWait returned while the join was still in flight", done)
        gate.open()
        waiting.await()
        join.await()
        assertTrue(done)
        sessions.endAndWait() // nothing left: returns at once
        scope.cancel()
    }

    /**
     * Review 5a #1: a duress session starts no sync, yet deleting an item (Recently deleted) and exporting a backup
     * work there as in a normal vault: the features use the second vault's own store, not the shut coordinator's.
     */
    @Test fun a_duress_session_syncs_nothing_but_its_features_still_work() = runBlocking {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        val notes = numberedNotes(2)
        val store = CountingStore(pairedSnapshot(notes))
        val key = ByteArray(32) { 9 }
        val decoy = UnlockedVault(store, SecretSlots(tmp.newFile().also { it.delete() }, key, SystemRandomSource()), key.copyOf(), decoy = true)
        val sessions = SyncSessions { v ->
            SyncCoordinator(
                v.store,
                SyncDependencies(
                    slots = v.slots, folders = FakeFolders(MemoryFolder()), lan = FakeLan(), random = SystemRandomSource(),
                    clock = TestClock(0), licenseKeys = emptyMap(),
                ),
                scope,
                EnglishTxt(),
            )
        }
        val c = sessions.forVault(decoy)
        assertFalse(c.gate.isOpen)
        sessions.appOpen(decoy)
        assertEquals(0, c.completedRuns.value)
        // Leave sync does nothing there either: the duress vault never keeps an identity (design 2026-11-17, rule 2).
        val syncState = store.snapshot.sync
        c.leave()
        assertSame(syncState, store.snapshot.sync)
        assertNull(decoy.slots.keptIdentity())
        val features = sessions.featureStore(decoy)
        assertSame(store, features)
        val id = (notes[0].fields["id"] as JsonValue.Str).v
        val trash = PhoneTrash(InMemoryLocalData(), features, { false }, TestClock(1_800_000_000), EnglishTxt(), null, io = kotlinx.coroutines.Dispatchers.Unconfined)
        assertEquals(SaveResult.SAVED, trash.moveToTrash(id))
        assertNull(store.snapshot.records[id])
        val bytes = BackupExporter(features, TestClock(1_800_000_000), CountingRandom(), "1.0.0", installId = { INSTALL_ID }, kdf = TEST_KDF)
            .export("correct horse battery staple 42")
        assertEquals(2, PhoneBackupFormat.read(bytes, "correct horse battery staple 42").states.size)
        // A normal vault's features still go through the coordinator's gated store.
        val real = vault()
        assertSame(sessions.forVault(real).store, sessions.featureStore(real))
        sessions.end()
        scope.cancel()
    }
}
