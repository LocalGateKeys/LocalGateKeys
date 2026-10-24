package app.localgatekeys.android.backup

import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.PHONE_DEVICE
import app.localgatekeys.android.editor.syncState
import app.localgatekeys.android.pro.LicenseKeys
import app.localgatekeys.android.sync.GatedStore
import app.localgatekeys.android.sync.LockedStore
import app.localgatekeys.android.sync.SessionGate
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.android.vault.webLogin
import app.localgatekeys.core.backup.PhoneBackupFormat
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncRunner
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Desktop `sync/phone_restore.py` rules on the phone (Ruling B: two-factor keys are restored as they are). */
class PhoneRestoreTest {
    private val now = 1_800_000_000L

    private fun restorer(store: ItemStore, isPro: Boolean = false) =
        PhoneRestore(store, { isPro }, TestClock(now), installId = { INSTALL_ID })

    private fun joined(vararg states: Pair<JsonValue.Obj, Map<String, Long>>): CountingStore {
        val records = LinkedHashMap<String, JsonValue>()
        val meta = LinkedHashMap<String, SyncMeta>()
        for ((r, vv) in states) {
            val id = (r.fields["id"] as JsonValue.Str).v
            records[id] = wrap(r)
            meta[id] = SyncMeta.live(records.getValue(id), vv)
        }
        return CountingStore(StoreSnapshot(records, meta, syncState()))
    }

    private fun title(store: CountingStore, id: String): String? =
        (((store.snapshot.records[id] as? JsonValue.Obj)?.fields?.get("record") as? JsonValue.Obj)?.fields?.get("title") as? JsonValue.Str)?.v

    @Test fun restore_into_an_empty_store_brings_every_item_with_its_vectors() {
        val store = CountingStore()
        val states = (1..3).map { live(noteRecord(noteId(it), "Note $it", 1_799_000_000L + it), mapOf(OTHER_PHONE to it.toLong())) }
        val r = restorer(store, isPro = false)
        val plan = r.plan(backupOf(states))
        assertEquals(3, plan.new); assertEquals(0, plan.updated); assertEquals(0, plan.unchanged); assertEquals(0, plan.heldBack)
        assertEquals("the plan reads only", 0, store.commits)
        assertEquals("RestorePlan(new=3, updated=0, unchanged=0, heldBack=0, skipped=0, deleted=0)", plan.toString())
        val report = r.restore(plan)
        assertNull(report.failure)
        assertEquals(3, report.new); assertEquals(0, report.updated); assertEquals(0, report.heldBack)
        assertEquals(1, store.commits)
        assertEquals((1..3).map { noteId(it) }.toSet(), store.snapshot.records.keys)
        // Entered through the merge as remote state: the backup's vectors are what this phone now knows.
        assertEquals(mapOf(OTHER_PHONE to 2L), store.snapshot.meta.getValue(noteId(2)).vv)
        // A second restore changes nothing.
        val again = r.plan(backupOf(states))
        assertEquals(0, again.new); assertEquals(0, again.updated); assertEquals(3, again.unchanged)
        assertEquals(0, r.restore(again).new)
    }

    @Test fun a_backup_never_overwrites_a_newer_version() {
        val mine = noteRecord(noteId(1), "Newer here", 1_799_900_000)
        val store = joined(mine to mapOf("desk" to 5L))
        val older = live(noteRecord(noteId(1), "Older in the backup", 1_799_000_000), mapOf("desk" to 3L))
        val plan = restorer(store).plan(backupOf(listOf(older)))
        assertEquals(0, plan.updated); assertEquals(1, plan.unchanged); assertEquals(0, plan.new)
        restorer(store).restore(plan)
        assertEquals("Newer here", title(store, noteId(1)))

        // The other way round the backup's newer version is taken, and never counts against the free plan.
        val store2 = joined(noteRecord(noteId(1), "Old here", 1_799_000_000) to mapOf("desk" to 3L))
        val newer = live(noteRecord(noteId(1), "Newer in the backup", 1_799_900_000), mapOf("desk" to 5L))
        val plan2 = restorer(store2).plan(backupOf(listOf(newer)))
        assertEquals(1, plan2.updated); assertEquals(0, plan2.heldBack)
        val report = restorer(store2).restore(plan2)
        assertEquals(1, report.updated); assertEquals(0, report.new)
        assertEquals("Newer in the backup", title(store2, noteId(1)))
    }

    @Test fun free_plan_keeps_the_newest_new_items_and_holds_back_the_rest() {
        val store = CountingStore(StoreSnapshot(sync = syncState()))
        val states = (1..6).map { live(noteRecord(noteId(it), "Note $it", 1_799_000_000L + it), mapOf(OTHER_PHONE to 1L)) }
        val plan = restorer(store).plan(backupOf(states))
        assertEquals(4, plan.new); assertEquals(2, plan.heldBack)
        val report = restorer(store).restore(plan)
        assertEquals(4, report.new); assertEquals(2, report.heldBack)
        assertEquals((3..6).map { noteId(it) }.toSet(), store.snapshot.records.keys)
        // Pro: no cap.
        val pro = CountingStore()
        val all = restorer(pro, isPro = true).plan(backupOf(states))
        assertEquals(6, all.new); assertEquals(0, all.heldBack)
    }

    @Test fun ties_on_the_stamp_keep_the_lower_id() {
        val store = CountingStore(StoreSnapshot(records = (11..13).associate { noteId(it) to wrap(noteRecord(noteId(it), "Mine $it", 1)) }))
        val states = (1..3).map { live(noteRecord(noteId(it), "Same $it", 1_799_000_000), mapOf(OTHER_PHONE to 1L)) }
        val plan = restorer(store).plan(backupOf(states))
        assertEquals(1, plan.new); assertEquals(2, plan.heldBack)
        restorer(store).restore(plan)
        assertTrue(noteId(1) in store.snapshot.records)
        assertTrue(noteId(2) !in store.snapshot.records)
    }

    @Test fun conflict_copies_take_free_slots_after_plain_new_items() {
        fun setup(localNotes: Int): Pair<CountingStore, List<ItemState>> {
            val mine = noteRecord(noteId(1), "Edited here", 1_799_500_000)
            val pairs = mutableListOf(mine to mapOf(PHONE_DEVICE to 1L))
            for (k in 0 until localNotes - 1) pairs += noteRecord(noteId(20 + k), "Local $k", 1) to mapOf(PHONE_DEVICE to 1L)
            val store = joined(*pairs.toTypedArray())
            // Edited concurrently on the other phone (neither vector dominates): the merge keeps one, copies the other.
            val theirs = live(noteRecord(noteId(1), "Edited there", 1_799_400_000), mapOf(OTHER_PHONE to 1L))
            val fresh = (2..3).map { live(noteRecord(noteId(it), "New $it", 1_799_000_000L + it), mapOf(OTHER_PHONE to 1L)) }
            return store to (fresh + theirs)
        }
        // Two free slots: both new items fit, the copy does not, so the concurrent state is held back (ours stays).
        val (tight, states) = setup(localNotes = 2)
        val plan = restorer(tight).plan(backupOf(states))
        assertEquals(2, plan.new); assertEquals(1, plan.heldBack)
        restorer(tight).restore(plan)
        assertEquals(4, tight.snapshot.records.size)
        assertEquals("Edited here", title(tight, noteId(1)))
        // Three free slots: the copy fits too and counts as a new item.
        val (roomy, states2) = setup(localNotes = 1)
        val plan2 = restorer(roomy).plan(backupOf(states2))
        assertEquals(3, plan2.new); assertEquals(0, plan2.heldBack)
        val report = restorer(roomy).restore(plan2)
        assertEquals(3, report.new)
        assertEquals(4, roomy.snapshot.records.size)
        assertTrue(roomy.snapshot.records.values.any { it.toString().contains("(sync conflict)") })
    }

    @Test fun items_the_phone_deleted_are_deleted_here() {
        val store = joined(noteRecord(noteId(1), "Doomed", 1_799_000_000) to mapOf("desk" to 3L))
        val plan = restorer(store).plan(backupOf(listOf(tomb(noteId(1), mapOf("desk" to 3L, OTHER_PHONE to 1L), 1_799_100_000))))
        assertEquals(1, plan.deleted)
        val report = restorer(store).restore(plan)
        assertEquals(1, report.deleted)
        assertTrue(store.snapshot.records.isEmpty())
        assertTrue(store.snapshot.meta.getValue(noteId(1)).deleted)
    }

    @Test fun a_backup_made_by_this_phone_is_refused() {
        val store = joined()
        try {
            restorer(store).plan(backupOf(listOf(live(noteRecord(noteId(1), "x", 1), mapOf(PHONE_DEVICE to 1L))), device = PHONE_DEVICE))
            fail("same device")
        } catch (e: PhoneRestoreException) {
            assertEquals(PhoneRestoreException.SAME_DEVICE, e.reason)
            assertEquals("This backup was made on this phone, so there is nothing to restore.", e.message)
        }
        // Not in a group: this phone's own backup id is refused too.
        val alone = CountingStore()
        val own = BackupDevice.id(alone.snapshot) { INSTALL_ID }
        try {
            restorer(alone).plan(backupOf(emptyList(), device = own))
            fail("same device")
        } catch (e: PhoneRestoreException) {
            assertEquals(PhoneRestoreException.SAME_DEVICE, e.reason)
        }
        assertEquals(0, store.commits + alone.commits)
    }

    @Test fun two_factor_keys_are_restored_as_they_are_even_on_the_free_plan() {
        val store = CountingStore()
        val login = rec(*(webLogin.fields.entries.map { it.key to it.value } + ("id" to s("11111111-0000-4000-8000-000000000001"))).toTypedArray())
        val plan = restorer(store, isPro = false).plan(backupOf(listOf(live(login, mapOf(OTHER_PHONE to 1L)))))
        assertEquals(1, plan.new)
        restorer(store).restore(plan)
        val stored = store.snapshot.records.getValue("11111111-0000-4000-8000-000000000001")
        assertEquals(wrap(login), stored) // byte for byte, totp included
    }

    @Test fun unreadable_states_are_skipped_and_take_no_free_slot() {
        val store = CountingStore()
        // A wrapper of a newer schema: the bridge refuses it (update-needed).
        val newer = JsonValue.Obj((wrap(noteRecord(noteId(1), "Future", 1_799_900_000)) as JsonValue.Obj).fields + ("schema" to JsonValue.Int(99)))
        val states = listOf(ItemState(noteId(1), mapOf(OTHER_PHONE to 1L), false, null, newer)) +
            (2..5).map { live(noteRecord(noteId(it), "Note $it", 1_799_000_000L + it), mapOf(OTHER_PHONE to 1L)) }
        assertTrue(SyncRunner.check(states[0], LicenseKeys.production) != null)
        val plan = restorer(store).plan(backupOf(states))
        assertEquals(1, plan.skipped); assertEquals(4, plan.new); assertEquals(0, plan.heldBack)
        val report = restorer(store).restore(plan)
        assertEquals(1, report.skipped); assertEquals(4, report.new)
    }

    // Desktop test_phone_backup_with_poisoned_vectors_is_skipped (audit M-6)
    @Test fun states_with_an_implausible_version_vector_are_skipped_and_take_no_free_slot() {
        val store = CountingStore(StoreSnapshot(sync = syncState().copy(members = listOf(PHONE_DEVICE, "desk-member"))))
        val max = (1L shl 53) - 1
        val bad = live(noteRecord(noteId(1), "Poisoned", 1_799_900_000), mapOf(OTHER_PHONE to max, "desk-id" to max))
        // 2^30: past the bound of an unknown device (2^20), within that of a known one (2^40).
        val unknownBig = live(noteRecord(noteId(2), "Unknown big", 1_799_800_000), mapOf("stranger" to (1L shl 30)))
        val memberBig = live(noteRecord(noteId(3), "Member big", 1_799_000_003), mapOf("desk-member" to (1L shl 30)))
        val peerBig = live(noteRecord(noteId(4), "Paired big", 1_799_000_004), mapOf("wifi-pc" to (1L shl 30)))
        val states = listOf(bad, unknownBig, memberBig, peerBig) +
            (5..6).map { live(noteRecord(noteId(it), "Note $it", 1_799_000_000L + it), mapOf(OTHER_PHONE to 1L)) }
        val r = PhoneRestore(store, { false }, TestClock(now), installId = { INSTALL_ID }, pairedPeerId = { "wifi-pc" })
        val plan = r.plan(backupOf(states))
        assertEquals(2, plan.skipped); assertEquals(4, plan.new); assertEquals(0, plan.heldBack)
        // Without the pairing that device is unknown: its state is left out too.
        assertEquals(3, restorer(store).plan(backupOf(states)).skipped)
        val report = r.restore(plan)
        assertNull(report.failure)
        assertEquals(2, report.skipped); assertEquals(4, report.new); assertEquals(0, report.heldBack)
        assertEquals(setOf(noteId(3), noteId(4), noteId(5), noteId(6)), store.snapshot.records.keys)
    }

    @Test fun lock_during_restore_writes_nothing() {
        val states = (1..3).map { live(noteRecord(noteId(it), "Note $it", 1_799_000_000L + it), mapOf(OTHER_PHONE to 1L)) }
        // Locked while the restore reads: refused before anything is written.
        val gate = SessionGate()
        val base = LockedStore(StoreSnapshot(sync = syncState()))
        val r = restorer(GatedStore(base, gate), isPro = true)
        val plan = r.plan(backupOf(states))
        base.onLoad = { gate.close() }
        try {
            r.restore(plan)
            fail("a locked restore must not finish")
        } catch (e: PhoneRestoreException) {
            assertEquals(PhoneRestoreException.LOCKED, e.reason)
        }
        assertEquals(0, base.commits)
        // Locked between the plan and the restore: refused too.
        val gate2 = SessionGate()
        val base2 = LockedStore(StoreSnapshot(sync = syncState()))
        val r2 = restorer(GatedStore(base2, gate2), isPro = true)
        val plan2 = r2.plan(backupOf(states))
        gate2.close()
        try {
            r2.restore(plan2)
            fail("locked")
        } catch (e: PhoneRestoreException) {
            assertEquals(PhoneRestoreException.LOCKED, e.reason)
        }
        assertEquals(0, base2.commits)
        assertTrue(base2.snapshot.records.isEmpty())
    }

    @Test fun a_store_that_changed_since_the_merge_is_reported_and_left_alone() {
        val store = object : ItemStore {
            var snap = StoreSnapshot(sync = syncState())
            override fun load() = snap
            override fun commit(change: app.localgatekeys.core.sync.StoreChange) =
                throw app.localgatekeys.android.vault.LocalStoreException(app.localgatekeys.android.vault.LocalStoreException.Kind.STALE, "stale")
        }
        val r = restorer(store, isPro = true)
        val report = r.restore(r.plan(backupOf(listOf(live(noteRecord(noteId(1), "x", 1), mapOf(OTHER_PHONE to 1L))))))
        assertEquals("busy", report.failure)
        assertEquals(0, report.new)
    }

    @Test fun restoring_the_android_vector_into_an_empty_store_yields_its_live_items() {
        val repo = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot not set"))
        val bytes = File(repo, "tests/vectors/backup/from_android/backup.lgkm").readBytes()
        val backup = PhoneBackupFormat.read(bytes, "correct horse battery staple 42")
        val store = CountingStore()
        val r = restorer(store, isPro = true)
        val plan = r.plan(backup)
        val live = backup.states.filter {
            !it.deleted && SyncRunner.check(it, LicenseKeys.production) == null &&
                ((it.item as JsonValue.Obj).fields["ns"] as JsonValue.Str).v in setOf("entry", "item")
        }
        assertTrue(live.size >= 2)
        assertEquals(live.size, plan.new); assertEquals(0, plan.heldBack); assertEquals(0, plan.skipped)
        // tests/test_backup_from_android.py: the web login and the passkey created on Android are among them.
        assertTrue(setOf("f1050000-0000-4000-8000-000000000201", "f1050000-0000-4000-8000-000000000202").all { id -> live.any { it.itemId == id } })
        val report = r.restore(plan)
        assertNull(report.failure)
        assertEquals(live.size, report.new)
        assertEquals(live.map { it.itemId }.toSet(), store.snapshot.records.keys)
        for (s in live) assertEquals(s.item, store.snapshot.records[s.itemId])
        assertEquals(0, r.restore(r.plan(backup)).new)
    }
}
