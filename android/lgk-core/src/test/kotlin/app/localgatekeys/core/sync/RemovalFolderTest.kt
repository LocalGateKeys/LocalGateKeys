package app.localgatekeys.core.sync

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.keyring.KeyringRotate
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Ed25519
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MemoryFolder
import app.localgatekeys.core.support.MemoryStore
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.SyncFixtures.GROUP_ID
import app.localgatekeys.core.support.SyncFixtures.KEYRING_PATH
import app.localgatekeys.core.support.SyncFixtures.T0
import app.localgatekeys.core.support.Vectors
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Removing a device from a cloud-folder group, as the desktop tests it (`tests/test_sync_removal.py` and the removal
 * cases of `tests/test_sync_folder_transport.py`): rotation, the signed notice, the watch file, competing rotations.
 */
class RemovalFolderTest {
    private val pw2 = "violet tram sundial 1987 pebble"
    private val pw3 = "third long sync phrase 99#"

    /** A cheap stand-in for Argon2id (the rotation writes the production parameters, only the key differs). */
    private val cheap = KeyringRotate.KeyDerivation { pw, salt ->
        MessageDigest.getInstance("SHA-256").digest(pw.toByteArray(Charsets.UTF_8) + salt)
    }

    private class MemoryWatch(override val folder: String) : RemovalWatchStore {
        var data: ByteArray? = null
        override fun read(): ByteArray? = data
        override fun write(data: ByteArray) {
            this.data = data.copyOf()
        }
        override fun delete() {
            data = null
        }
        fun watch(): RemovalWatch? = Removal.parseWatch(data)
    }

    private inner class Dev(val name: String, val folder: MemoryFolder) {
        val identity: DeviceIdentity = SyncFixtures.identity(name)
        val id: String get() = identity.deviceId
        val install = "install-$name"
        val watch = MemoryWatch("content://tree/$name")
        val fs = FolderSync(folder, install, removalWatch = watch)
        val store = MemoryStore(
            StoreSnapshot(
                sync = SyncGroupState(
                    groupId = GROUP_ID, epoch = 1, key = SyncFixtures.epochKey("1").key, identity = identity, installId = install,
                    membersEpoch = 1, members = listOf(SyncFixtures.identity("A"), SyncFixtures.identity("B"), SyncFixtures.identity("C"))
                        .map { it.deviceId }.sorted(),
                    keyring = Vectors.sync("keyring_epoch1.json").readBytes(),
                ),
            ),
        )
        private var runs = 0
        val state: SyncGroupState get() = store.snapshot.sync!!
        fun sync(): RunReport = fs.runOnce(store, DetRand("run|$name|${runs++}"), FixedClock(T0 + 1000 + runs))
        fun rotate(newPassword: String, remove: List<String> = emptyList(), keep: List<String>? = null): RunReport =
            fs.rotate(store, newPassword, remove, keep, DetRand("rotate|$name|${runs++}"), FixedClock(T0 + 2000), { true }, cheap)
    }

    private fun kinds(r: RunReport) = r.issues.map { it.kind }

    private fun noticePath(id: String) = "LocalGateKeys Sync/removed/$id.lgkremoved"

    private fun ringMembers(folder: MemoryFolder): Set<String> =
        FolderSync.memberIds(Keyring.parse(folder.files[KEYRING_PATH]!!))

    private fun group(): Triple<Dev, Dev, Dev> {
        val folder = MemoryFolder()
        folder.files[KEYRING_PATH] = Vectors.sync("keyring_epoch1.json").readBytes()
        val devs = Triple(Dev("A", folder), Dev("B", folder), Dev("C", folder))
        for (d in devs.toList()) assertEquals(emptyList(), kinds(d.sync()), d.name)
        for (d in devs.toList()) assertEquals(emptyList(), kinds(d.sync()), d.name)
        return devs
    }

    @Test fun every_run_keeps_a_watch_of_the_trusted_signers() {
        val (a, b, c) = group()
        val w = c.watch.watch()!!
        assertEquals(c.id, w.deviceId)
        assertEquals(1, w.epoch)
        assertEquals(c.install, w.installId)
        assertEquals("content://tree/C", w.folder)
        assertEquals(setOf(a.id, b.id), w.signers.keys)
        assertEquals(Base64Std.encode(a.identity.signingPublicKey), w.signers[a.id])
    }

    @Test fun rotation_writes_a_notice_signed_by_the_remover() {
        val (a, b, c) = group()
        val report = a.rotate(pw2, remove = listOf(c.id))
        assertEquals(2, a.state.epoch)
        assertFalse(c.id in ringMembers(a.folder))
        assertFalse(SyncFixtures.devPath(c.id) in a.folder.files)
        val raw = a.folder.files[noticePath(c.id)]!!
        val (notice, message, sig) = Removal.parseNotice(raw)
        assertEquals(RemovalNotice(GROUP_ID, c.id, 2, a.id, T0 + 2000), notice)
        assertTrue(Ed25519.verify(sig, message, a.identity.signingPublicKey))
        assertTrue(message.toString(Charsets.UTF_8).startsWith("localgatekeys|sync|removal-notice|v1|"))
        assertFalse(noticePath(b.id) in a.folder.files) // kept members get no notice
        assertFalse("removal-notice" in kinds(report))
        // The keyring is written before the notice.
        val writes = a.folder.writes
        assertTrue(writes.lastIndexOf(KEYRING_PATH) < writes.indexOf(noticePath(c.id)))
    }

    @Test fun removed_device_reports_the_verified_notice() {
        val (a, b, c) = group()
        a.rotate(pw2, remove = listOf(c.id))
        val stored = c.store.snapshot
        val report = c.sync()
        assertEquals(listOf("rejoin-required", "removal-notice"), kinds(report))
        assertEquals(a.id, report.issues.last().detail)
        assertEquals(stored, c.store.snapshot) // nothing committed
        // The app's locked check reads the watch file and finds the same notice.
        val w = c.watch.watch()!!
        assertEquals(c.id, assertNotNull(Removal.check(w, c.install, c.folder)).deviceId)
        assertNull(Removal.check(w, "another-phone", c.folder))
    }

    @Test fun kept_member_never_sees_a_notice() {
        val (a, b, c) = group()
        a.rotate(pw2, remove = listOf(c.id))
        val report = b.sync()
        assertFalse("removal-notice" in kinds(report))
        assertEquals(2, b.state.epoch)
        assertNull(Removal.check(b.watch.watch()!!, b.install, b.folder))
        assertEquals(2, b.watch.watch()!!.epoch)
        assertEquals(setOf(a.id), b.watch.watch()!!.signers.keys)
    }

    @Test fun unconfirmed_members_lose_the_key_but_get_no_notice() {
        val (a, b, c) = group()
        a.rotate(pw2, keep = listOf(b.id))
        assertFalse(c.id in ringMembers(a.folder))
        assertFalse(noticePath(c.id) in a.folder.files)
        assertFalse("removal-notice" in kinds(c.sync()))
    }

    @Test fun existing_issue_kinds_alone_never_report_a_notice() {
        val (a, b, c) = group()
        a.rotate(pw2, remove = listOf(c.id))
        a.folder.files.remove(noticePath(c.id))
        assertEquals(listOf("rejoin-required"), kinds(c.sync()))
    }

    private fun forge(folder: MemoryFolder, c: Dev, seed: ByteArray, signer: String, epoch: Long = 2) {
        folder.files[noticePath(c.id)] = Removal.makeNotice(GROUP_ID, c.id, epoch, signer, T0) { Ed25519.sign(seed, it) }
    }

    @Test fun notice_signed_by_an_unknown_key_is_ignored() {
        val (a, b, c) = group()
        a.rotate(pw2, remove = listOf(c.id))
        forge(a.folder, c, ByteArray(32) { 7 }, a.id) // right signer id, wrong key
        assertEquals(listOf("rejoin-required"), kinds(c.sync()))
        forge(a.folder, c, ByteArray(32) { 7 }, "stranger")
        assertEquals(listOf("rejoin-required"), kinds(c.sync()))
    }

    @Test fun notice_without_a_keyring_that_drops_the_device_is_ignored() {
        val (a, b, c) = group()
        val seedA = Base64Std.decodeStrict(signingSeed("A"))
        forge(a.folder, c, seedA, a.id)
        assertFalse("removal-notice" in kinds(c.sync()))
        assertNull(Removal.check(c.watch.watch()!!, c.install, c.folder))
    }

    @Test fun leaving_forgets_the_watch_file() {
        val (a, b, c) = group()
        assertNotNull(c.watch.data)
        val snap = c.store.snapshot
        c.store.commit(StoreChange(snap.revision, snap.records, snap.meta, null))
        assertEquals(listOf("not-joined"), kinds(c.sync()))
        assertNull(c.watch.data)
    }

    @Test fun removed_device_cannot_read_after_rotation() {
        val (a, b, c) = group()
        val oldKey = SyncFixtures.epochKey("1")
        a.rotate(pw2, remove = listOf(c.id))
        a.sync()
        val raw = a.folder.files[SyncFixtures.devPath(a.id)]!!
        // The new view opens with the new key ...
        val newKey = app.localgatekeys.core.group.GroupKey(GROUP_ID, 2, a.state.key)
        app.localgatekeys.core.group.ViewFile.decode(raw, newKey, a.id)
        // ... and the removed device's old key, even claiming the new epoch, cannot decrypt it.
        val forged = app.localgatekeys.core.group.GroupKey(GROUP_ID, 2, oldKey.key)
        val e = runCatching { app.localgatekeys.core.group.ViewFile.decode(raw, forged, a.id) }.exceptionOrNull()
        assertEquals("auth-failed", (e as? app.localgatekeys.core.group.SyncFormatException)?.reason)
        // And under its own epoch the header check refuses it.
        val e1 = runCatching { app.localgatekeys.core.group.ViewFile.decode(raw, oldKey, a.id) }.exceptionOrNull()
        assertEquals("epoch-mismatch", (e1 as? app.localgatekeys.core.group.SyncFormatException)?.reason)
    }

    @Test fun missed_rotations_require_rejoin() {
        val (a, b, c) = group()
        a.rotate(pw2)
        a.rotate(pw3)
        assertEquals(3, a.state.epoch)
        val before = b.store.snapshot
        assertEquals(listOf("rejoin-required"), kinds(b.sync()))
        assertEquals(before, b.store.snapshot)
    }

    @Test fun password_change_writes_no_notice_and_keeps_everyone() {
        val (a, b, c) = group()
        a.rotate(pw2)
        assertEquals(setOf(a.id, b.id, c.id), ringMembers(a.folder))
        assertTrue(a.folder.files.keys.none { it.startsWith("LocalGateKeys Sync/removed/") })
        assertEquals(emptyList(), kinds(b.sync()).filter { it != "epoch-mismatch" })
        assertEquals(2, b.state.epoch)
    }

    @Test fun competing_rotations_stop_with_rotation_conflict() {
        val (a, b, c) = group()
        val epoch1 = a.folder.files[KEYRING_PATH]!!
        a.rotate(pw2)
        val ringA = a.folder.files[KEYRING_PATH]!!
        a.folder.files[KEYRING_PATH] = epoch1 // B works from a stale copy of epoch 1 and rotates too
        b.rotate(pw3)
        val ringB = a.folder.files[KEYRING_PATH]!!
        val report = a.sync()
        assertEquals(listOf("rotation-conflict"), kinds(report))
        assertFalse(report.wrote)
        assertContentEquals(ringB, a.folder.files[KEYRING_PATH])
        a.folder.files[KEYRING_PATH] = ringA
        assertEquals(listOf("rotation-conflict"), kinds(b.sync()))
        assertContentEquals(ringA, a.folder.files[KEYRING_PATH])
    }

    @Test fun device_removed_in_overlapping_rotation_does_not_restore_itself() {
        val (a, b, c) = group()
        val epoch1 = a.folder.files[KEYRING_PATH]!!
        a.rotate(pw2)
        c.sync()
        assertEquals(2, c.state.epoch) // C adopts A's keyring (C still a member)
        a.folder.files[KEYRING_PATH] = epoch1 // B works from a stale copy of epoch 1 and removes C
        b.rotate(pw3, remove = listOf(c.id))
        val ringB = a.folder.files[KEYRING_PATH]!!
        assertFalse(c.id in ringMembers(a.folder))
        val report = c.sync()
        // B's notice is at epoch 2, which C already trusts: not a proof (stale), so no removal-notice.
        assertEquals(listOf("removed-or-conflict"), kinds(report))
        assertFalse(report.wrote)
        assertContentEquals(ringB, a.folder.files[KEYRING_PATH])
        assertEquals(listOf("rotation-conflict"), kinds(a.sync()))
        assertContentEquals(ringB, a.folder.files[KEYRING_PATH])
    }

    @Test fun winner_rotating_again_after_conflict_does_not_ping_pong() {
        val (a, b, c) = group()
        val epoch1 = a.folder.files[KEYRING_PATH]!!
        a.rotate(pw2)
        a.folder.files[KEYRING_PATH] = epoch1
        b.rotate(pw3)
        assertEquals(listOf("rotation-conflict"), kinds(a.sync()))
        b.rotate(pw2)
        val ringB3 = a.folder.files[KEYRING_PATH]!!
        assertEquals(3L, (Keyring.obj(Keyring.parse(ringB3))["epoch"] as JsonValue.Int).v)
        repeat(3) {
            val r = a.sync()
            assertEquals(listOf("rotation-conflict"), kinds(r))
            assertFalse(r.wrote)
            assertContentEquals(ringB3, a.folder.files[KEYRING_PATH])
            assertFalse("keyring-restored" in kinds(b.sync()))
        }
        assertEquals(2, a.state.epoch)
    }

    @Test fun rotating_from_a_stale_epoch_is_refused_and_untouched() {
        val (a, b, c) = group()
        val epoch1 = a.folder.files[KEYRING_PATH]!!
        b.rotate(pw2) // B rotated after A last read: A's state is epoch 1, folder at 2
        val before = a.store.snapshot
        val r = runCatching { a.rotate(pw3, remove = listOf(c.id)) }.exceptionOrNull()
        assertEquals("stale-trust", (r as FolderSyncException).reason)
        assertEquals(before, a.store.snapshot)
        assertFalse(noticePath(c.id) in a.folder.files)
        assertFalse(epoch1.contentEquals(a.folder.files[KEYRING_PATH]))
    }

    @Test fun rotation_refusals_leave_store_and_folder_untouched() {
        val (a, b, c) = group()
        val image = a.folder.image()
        val before = a.store.snapshot
        fun reason(f: () -> Any?) = (runCatching { f() }.exceptionOrNull() as? FolderSyncException)?.reason
        assertEquals("cannot-remove-self", reason { a.rotate(pw2, remove = listOf(a.id)) })
        assertEquals("not-member", reason { a.rotate(pw2, remove = listOf("d4444444-0000-4000-8000-00000000000d")) })
        assertEquals("not-member", reason { a.rotate(pw2, remove = listOf("bad/id")) })
        assertEquals("weak-password", reason { a.fs.rotate(a.store, "short", emptyList(), null, DetRand("w"), FixedClock(T0), { false }) })
        assertEquals(image, a.folder.image())
        assertEquals(before, a.store.snapshot)
    }

    @Test fun members_added_elsewhere_stay_unconfirmed_until_acknowledged() {
        val (a, b, c) = group()
        // D joins with the sync password (someone holding it).
        val d = DeviceIdentity.generate(SyncFixtures.PHONE, DetRand("identity|D"))
        val ring = Keyring.parse(a.folder.files[KEYRING_PATH]!!)
        val (joined, _) = Keyring.join(ring, SyncFixtures.pwKey("1"), d, "Stranger", DetRand("join|D"), FixedClock(T0 + 1500))
        a.folder.files[KEYRING_PATH] = CanonicalJson.encode(joined, Dialect.UTF8)
        a.sync()
        assertEquals(listOf(d.deviceId), a.state.unackedMembers)
        assertFalse(d.deviceId in a.watch.watch()!!.signers) // an unconfirmed member cannot sign a notice
        // A rotation without a keep list drops D, with no notice.
        a.rotate(pw2)
        assertFalse(d.deviceId in ringMembers(a.folder))
        assertFalse(noticePath(d.deviceId) in a.folder.files)
        assertEquals(emptyList(), a.state.unackedMembers)
    }

    @Test fun acknowledged_members_keep_the_key() {
        val (a, b, c) = group()
        val d = DeviceIdentity.generate(SyncFixtures.PHONE, DetRand("identity|D"))
        val ring = Keyring.parse(a.folder.files[KEYRING_PATH]!!)
        val (joined, _) = Keyring.join(ring, SyncFixtures.pwKey("1"), d, "My tablet", DetRand("join|D"), FixedClock(T0 + 1500))
        a.folder.files[KEYRING_PATH] = CanonicalJson.encode(joined, Dialect.UTF8)
        a.sync()
        assertEquals(0, a.fs.acknowledgeMembers(a.store, listOf("someone-else")))
        assertEquals(1, a.fs.acknowledgeMembers(a.store, listOf(d.deviceId)))
        assertEquals(emptyList(), a.state.unackedMembers)
        a.sync()
        assertEquals(emptyList(), a.state.unackedMembers)
        assertTrue(d.deviceId in a.watch.watch()!!.signers)
        a.rotate(pw2)
        assertTrue(d.deviceId in ringMembers(a.folder))
    }

    @Test fun stored_signer_keys_stay_pinned() {
        val (a, b, c) = group()
        val stored = c.watch.watch()!!
        val other = Base64Std.encode(Ed25519.publicKey(ByteArray(32) { 9 }))
        val swapped = stored.copy(signers = stored.signers + (a.id to other))
        assertEquals(stored.signers[a.id], Removal.pinned(swapped, stored).signers[a.id])
        val dropped = stored.copy(signers = mapOf(b.id to stored.signers[b.id]!!))
        assertEquals(setOf(b.id), Removal.pinned(dropped, stored).signers.keys)
        // Through the store, as a folder run refreshes it: the swapped key never replaces the pinned one.
        Removal.refresh(c.watch, swapped)
        assertEquals(stored.signers[a.id], c.watch.watch()!!.signers[a.id])
        // A later normal run keeps it too.
        c.sync()
        assertEquals(stored.signers[a.id], c.watch.watch()!!.signers[a.id])
    }

    private fun signingSeed(who: String): String {
        val ids = Vectors.json(Vectors.sync("identities.json")).obj().fields["devices"] as JsonValue.Obj
        val p = ((ids.fields[who] as JsonValue.Obj).fields["private"] as JsonValue.Obj).fields
        return (p["signing_private"] as JsonValue.Str).v
    }
}
