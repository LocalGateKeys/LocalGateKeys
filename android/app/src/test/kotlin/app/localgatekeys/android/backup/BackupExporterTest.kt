package app.localgatekeys.android.backup

import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.PHONE_DEVICE
import app.localgatekeys.android.editor.syncState
import app.localgatekeys.android.sync.GatedStore
import app.localgatekeys.android.sync.LockedStore
import app.localgatekeys.android.sync.SessionGate
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.core.backup.PhoneBackupFormat
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.sync.StoreSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class BackupExporterTest {
    private val now = 1_800_000_000L
    private val password = "correct horse battery staple 42"

    private fun store(joined: Boolean): CountingStore {
        val a = noteRecord(noteId(1), "Alpha", 1_799_000_000)
        val b = noteRecord(noteId(2), "Beta", 1_799_000_100)
        val records = mapOf(noteId(1) to wrap(a), noteId(2) to wrap(b))
        // One item synced before, one tombstone of an item deleted on this phone.
        val meta = mapOf(
            noteId(1) to SyncMeta.live(records.getValue(noteId(1)), mapOf("desk" to 3L)),
            noteId(9) to SyncMeta.tomb(mapOf("desk" to 2L), 1_799_500_000),
        )
        return CountingStore(StoreSnapshot(records, meta, if (joined) syncState() else null))
    }

    private fun exporter(store: app.localgatekeys.core.sync.ItemStore, isPro: Boolean = false) =
        BackupExporter(store, TestClock(now), CountingRandom(), "1.0.0", installId = { INSTALL_ID }, isPro = { isPro }, kdf = TEST_KDF)

    @Test fun export_reads_back_through_the_format_with_the_local_view() {
        val s = store(joined = true)
        val before = s.snapshot
        val bytes = exporter(s, isPro = true).export(password)
        val backup = PhoneBackupFormat.read(bytes, password)
        assertEquals("android", backup.header.platform)
        assertEquals(now, backup.header.createdAt)
        assertEquals(PHONE_DEVICE, backup.deviceId)
        assertEquals("1.0.0", backup.appVersion)
        assertTrue(backup.proHint)
        val view = SyncMeta.localView(before.records, before.meta, PHONE_DEVICE, now)
        assertEquals(view.states.values.sortedBy { it.itemId }, backup.states)
        // Every item, its vector and the tombstone travel; the new item got this phone's first counter.
        assertEquals(listOf(noteId(1), noteId(2), noteId(9)), backup.states.map { it.itemId })
        assertEquals(mapOf("desk" to 3L), backup.states[0].vv)
        assertEquals(mapOf(PHONE_DEVICE to 1L), backup.states[1].vv)
        assertTrue(backup.states[2].deleted)
    }

    @Test fun export_uses_the_production_kdf_by_default() {
        val bytes = BackupExporter(store(true), TestClock(now), CountingRandom(), "1.0.0", installId = { INSTALL_ID }).export(password)
        val kdf = PhoneBackupFormat.inspect(bytes).kdf
        assertEquals(4L, kdf["time_cost"]); assertEquals(131072L, kdf["memory_cost_kib"]); assertEquals(4L, kdf["parallelism"])
        assertFalse(PhoneBackupFormat.read(bytes, password).proHint)
    }

    @Test fun the_vectors_a_backup_carries_are_stored_first_so_a_later_edit_is_always_newer() {
        val s = store(joined = true)
        exporter(s).export(password)
        assertEquals(1, s.commits)
        assertEquals(mapOf(PHONE_DEVICE to 1L), s.snapshot.meta.getValue(noteId(2)).vv)
        // Nothing changed since: the next export writes nothing and carries the same vectors.
        val again = PhoneBackupFormat.read(exporter(s).export(password), password)
        assertEquals(1, s.commits)
        assertEquals(mapOf(PHONE_DEVICE to 1L), again.states[1].vv)
    }

    @Test fun a_phone_not_in_a_group_exports_under_a_stable_id_of_its_own() {
        val a = PhoneBackupFormat.read(exporter(store(joined = false)).export(password), password)
        val b = PhoneBackupFormat.read(exporter(store(joined = false)).export(password), password)
        assertEquals(a.deviceId, b.deviceId)
        assertTrue(Identifier.isValid(a.deviceId))
        assertNotEquals(INSTALL_ID, a.deviceId)
        assertEquals(BackupDevice.id(StoreSnapshot()) { INSTALL_ID }, a.deviceId)
        assertNotEquals(a.deviceId, BackupDevice.id(StoreSnapshot()) { "fedcba9876543210fedcba9876543210" })
        // Joined: the group's device id.
        assertEquals(PHONE_DEVICE, BackupDevice.id(StoreSnapshot(sync = syncState())) { INSTALL_ID })
    }

    @Test fun lock_during_export_writes_nothing() {
        val gate = SessionGate()
        val base = LockedStore(store(joined = true).snapshot)
        base.onLoad = { gate.close() } // the vault locks while the export reads
        try {
            exporter(GatedStore(base, gate)).export(password)
            fail("a locked export must not finish")
        } catch (e: Exception) {
            // refused
        }
        assertEquals(0, base.commits)
    }
}
