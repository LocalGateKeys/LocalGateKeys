package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.group.ViewSignature
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.keyring.MemberNames
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MemoryFolder
import app.localgatekeys.core.support.MemoryStore
import app.localgatekeys.core.support.MergeVectors
import app.localgatekeys.core.support.MergeVectors.A
import app.localgatekeys.core.support.MergeVectors.B
import app.localgatekeys.core.support.MergeVectors.C
import app.localgatekeys.core.support.MergeVectors.NOTE
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.SyncFixtures.INSTALL
import app.localgatekeys.core.support.SyncFixtures.KEYRING_PATH
import app.localgatekeys.core.support.SyncFixtures.T0
import app.localgatekeys.core.support.SyncFixtures.devPath
import app.localgatekeys.core.support.SyncFixtures.epochKey
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Port of Swift `FolderSyncTests` (the `from_ios` writer test is Task 14's Android equivalent). */
class FolderSyncTest {
    private fun issues(r: RunReport) = r.issues.map { it.kind }

    private class Joined(val folder: MemoryFolder, val store: MemoryStore, val fs: FolderSync, val report: RunReport)

    /** Joins the seeded folder with the known password-wrap key (no Argon2id) at T0 + 1000. */
    private fun joined(label: String = "phone"): Joined {
        val folder = SyncFixtures.seededFolder()
        val store = MemoryStore()
        val fs = FolderSync(folder, INSTALL)
        val pw = SyncFixtures.pwKey("1")
        val report = fs.join(store, "Pixel", DetRand("t10|$label"), FixedClock(T0 + 1000)) { pw }
        return Joined(folder, store, fs, report)
    }

    private fun storedStates(store: MemoryStore, device: String, now: Long): List<ItemState> {
        val v = SyncMeta.localView(store.snapshot.records, store.snapshot.meta, device, now)
        return v.states.values.sortedBy { it.itemId }
    }

    private fun reason(f: () -> Any?): String? = try {
        f()
        null
    } catch (e: FolderSyncException) {
        e.reason
    }

    private fun decode(bytes: ByteArray, id: String) = ViewFile.decode(bytes, epochKey("1"), id)

    private fun encode(id: String, counter: Long, states: List<ItemState>, at: Long, rand: String) =
        ViewFile.encode(epochKey("1"), id, counter, states, FixedClock(at), DetRand(rand))

    // ---- join and merge ----

    @Test
    fun join_with_password_reads_ABC_and_matches_bridge_stored_states() {
        val folder = SyncFixtures.seededFolder()
        val store = MemoryStore()
        val fs = FolderSync(folder, INSTALL)
        val password = str(SyncFixtures.expected()["password_epoch1"])!!
        val report = fs.join(store, password, "Pixel", DetRand("t10|join"), FixedClock(T0 + 1000))
        assertEquals(emptyList(), report.issues)
        assertTrue(report.wrote)
        val state = assertNotNull(store.snapshot.sync)
        val want = SyncFixtures.bridgeStoredStates()
        assertEquals(want, storedStates(store, state.deviceId, T0 + 1000))
        assertEquals(want, report.ownStates)
        // The keyring now lists the phone and is accepted by A; the phone's file decodes with counter 1.
        val ring = Keyring.parse(folder.files[KEYRING_PATH]!!)
        assertEquals(epochKey("1"), Keyring.accept(ring, epochKey("1"), SyncFixtures.identity("A")))
        assertEquals("Pixel", Keyring.memberNames(ring, epochKey("1"))[state.deviceId])
        val own = decode(folder.files[devPath(state.deviceId)]!!, state.deviceId)
        assertEquals(1L, own.first.counter)
        assertEquals(want, own.second)
        assertEquals(1L, state.ownCounter)
        assertEquals(mapOf(A to 7L, B to 4L, C to 3L), state.lastSeen)
        assertEquals(listOf(A, B, C, state.deviceId).sorted(), state.members)
        // A second run without changes neither commits nor writes.
        val commits = store.commits
        val writes = folder.writes.size
        val again = fs.runOnce(store, DetRand("again"), FixedClock(T0 + 1100))
        assertEquals(emptyList(), again.issues)
        assertFalse(again.wrote)
        assertEquals(commits, store.commits)
        assertEquals(writes, folder.writes.size)
    }

    @Test
    fun join_refusals() {
        val j = joined()
        assertEquals(
            "already-joined",
            reason { j.fs.join(j.store, "x", DetRand("x"), FixedClock(T0)) { SyncFixtures.pwKey("1") } },
        )
        val empty = MemoryFolder()
        val fs2 = FolderSync(empty, INSTALL)
        assertEquals("no-group", reason { fs2.join(MemoryStore(), "x", DetRand("x"), FixedClock(T0)) { ByteArray(0) } })
        assertEquals("bad-install-id", reason { FolderSync(empty, "") })
    }

    // ---- peer files ----

    @Test
    fun rollback_and_suspicious_rewrite_are_skipped() {
        val j = joined()
        val a = decode(j.folder.files[devPath(A)]!!, A)
        // Lower counter: rollback.
        j.folder.files[devPath(A)] = encode(A, 6, a.second, T0 + 950, "rb")
        val commits = j.store.commits
        var r = j.fs.runOnce(j.store, DetRand("r1"), FixedClock(T0 + 1100))
        assertEquals(listOf("rollback"), issues(r))
        assertEquals(commits, j.store.commits)
        // Same counter, other bytes: suspicious-rewrite.
        j.folder.files[devPath(A)] = encode(A, 7, a.second, T0 + 900, "other-nonces")
        r = j.fs.runOnce(j.store, DetRand("r2"), FixedClock(T0 + 1100))
        assertEquals(listOf("suspicious-rewrite"), issues(r))
        assertEquals(commits, j.store.commits)
        // A higher counter is accepted again.
        j.folder.files[devPath(A)] = encode(A, 8, a.second, T0 + 1050, "ok")
        r = j.fs.runOnce(j.store, DetRand("r3"), FixedClock(T0 + 1100))
        assertEquals(emptyList(), r.issues)
        assertEquals(8L, j.store.snapshot.sync?.lastSeen?.get(A))
    }

    @Test
    fun provider_copies_and_unknown_files_are_ignored() {
        val j = joined()
        val aBytes = j.folder.files[devPath(A)]!!
        j.folder.files["LocalGateKeys Sync/devices/$A (1).lgksync"] = aBytes
        j.folder.files["LocalGateKeys Sync/devices/$B-DESKTOP-ABC.lgksync"] = aBytes
        j.folder.files["LocalGateKeys Sync/devices/.$C.lgksync.abc123.tmp"] = byteArrayOf(1, 2, 3)
        val r = j.fs.runOnce(j.store, DetRand("r"), FixedClock(T0 + 1100))
        assertEquals(listOf("ignored-file"), issues(r))
        assertEquals("2 files: $A (1).lgksync, $B-DESKTOP-ABC.lgksync", r.issues[0].detail)
        assertFalse(r.wrote)
    }

    @Test
    fun stale_device_is_skipped_entirely() {
        val j = joined()
        val late = T0 + 1000 + 366 * 86400
        // B writes an old file with a new item: the whole file is skipped.
        val b = decode(j.folder.files[devPath(B)]!!, B)
        j.folder.files[devPath(B)] = encode(B, 5, b.second, T0 + 950, "stale")
        val r = j.fs.runOnce(j.store, DetRand("r"), FixedClock(late))
        assertTrue(issues(r).contains("stale-device"))
        assertEquals(5L, j.store.snapshot.sync?.lastSeen?.get(B))
    }

    // ---- Review Focus #2 ----

    @Test
    fun failed_reads_leave_store_untouched() {
        // 1. Wrong sync password (real Argon2id): refused, no commit, folder unchanged.
        run {
            val folder = SyncFixtures.seededFolder()
            val before = folder.image()
            val store = MemoryStore()
            val fs = FolderSync(folder, INSTALL)
            assertEquals(
                "password",
                reason { fs.join(store, "not the password", "Pixel", DetRand("wrong"), FixedClock(T0 + 1000)) },
            )
            assertEquals(0, store.commits)
            assertEquals(StoreSnapshot(), store.snapshot)
            assertEquals(before, folder.image())
        }
        val j = joined()
        val synced = j.store.snapshot
        val baseline = j.store.commits // the join and its first run
        val goodRing = j.folder.files[KEYRING_PATH]!!
        fun assertUntouched(r: RunReport, kinds: List<String>, what: String) {
            assertEquals(kinds, issues(r), what)
            assertEquals(baseline, j.store.commits, "$what: no commit at all")
            assertEquals(synced, j.store.snapshot, what)
            assertFalse(r.wrote, what)
        }
        val clock = FixedClock(T0 + 1100)
        // 2a. Tampered keyring that no longer parses.
        val bad = goodRing.copyOf()
        bad[bad.size / 2] = (bad[bad.size / 2].toInt() xor 0x01).toByte()
        j.folder.files[KEYRING_PATH] = bad.copyOf(bad.size - 5)
        assertUntouched(j.fs.runOnce(j.store, DetRand("k1"), clock), listOf("keyring-corrupt"), "garbage keyring")
        // 2b. Tampered keyring that parses but fails its MAC: restored from the stored copy; store unchanged.
        val o = obj(Keyring.parse(goodRing)).toMutableMap()
        val ms = (o["members"] as JsonValue.Arr).items.toMutableList()
        ms[0] = JsonValue.Obj(obj(ms[0]) + ("added_at" to JsonValue.Int(1)))
        o["members"] = JsonValue.Arr(ms)
        j.folder.files[KEYRING_PATH] = CanonicalJson.encode(JsonValue.Obj(o), Dialect.UTF8)
        assertUntouched(j.fs.runOnce(j.store, DetRand("k2"), clock), listOf("keyring-restored"), "MAC tampered")
        assertContentEquals(goodRing, j.folder.files[KEYRING_PATH])
        // 2c. A keyring of another group: never overwritten, nothing written.
        val other = Vectors.sync("keyring_existing_epoch1.json").readBytes()
        j.folder.files[KEYRING_PATH] = other
        val writes = j.folder.writes.size
        assertUntouched(j.fs.runOnce(j.store, DetRand("k3"), clock), listOf("folder-has-other-group"), "other group")
        assertContentEquals(other, j.folder.files[KEYRING_PATH])
        assertEquals(writes, j.folder.writes.size)
        j.folder.files[KEYRING_PATH] = goodRing
        // 3. Corrupt device files (flipped byte, truncated, garbage): skipped, store unchanged.
        val a = j.folder.files[devPath(A)]!!
        val flipped = a.copyOf()
        flipped[flipped.size - 3] = (flipped[flipped.size - 3].toInt() xor 0x40).toByte()
        for ((name, data) in listOf(
            "flipped" to flipped, "truncated" to a.copyOf(a.size / 2), "garbage" to "hello".toByteArray(),
        )) {
            j.folder.files[devPath(A)] = data
            assertUntouched(j.fs.runOnce(j.store, DetRand(name), clock), listOf("corrupt"), name)
        }
        // A wrong-device file under A's name.
        j.folder.files[devPath(A)] = j.folder.files[devPath(B)]!!
        assertUntouched(j.fs.runOnce(j.store, DetRand("dm"), clock), listOf("device-mismatch"), "device mismatch")
    }

    // ---- own file counter ----

    @Test
    fun own_file_counter_is_max_of_reserved_and_file_plus_one() {
        val j = joined()
        val me = j.store.snapshot.sync!!.deviceId
        // A local edit: the file is rewritten with counter 2, reserved in the same commit.
        val snap = j.store.snapshot
        val rec = obj(obj(snap.records[NOTE])["record"]) +
            mapOf("title" to JsonValue.Str("Edited on the phone"), "updated_at" to JsonValue.Int(T0 + 1050))
        val w = Wrapper.make(Namespace.ITEM, Normalise.normalForm(Namespace.ITEM, JsonValue.Obj(rec)))
        j.store.snapshot = snap.copy(records = snap.records + (NOTE to w))
        var r = j.fs.runOnce(j.store, DetRand("c2"), FixedClock(T0 + 1100))
        assertEquals(emptyList(), r.issues)
        assertTrue(r.wrote)
        var own = decode(j.folder.files[devPath(me)]!!, me)
        assertEquals(2L, own.first.counter)
        assertEquals(2L, j.store.snapshot.sync?.ownCounter)
        // The store was restored from an older backup (reserved 2) while the file says 5: write 6.
        // That file was written (and signed) by this device itself.
        val five = ViewFile.encode(epochKey("1"), me, 5, own.second, FixedClock(T0 + 1150), DetRand("five"))
        j.folder.files[devPath(me)] = five
        j.folder.files[FolderLayout.signatureFile(me)!!] =
            ViewSignature.sign(five, ViewFile.decodeHeader(five), j.store.snapshot.sync!!.identity)
        r = j.fs.runOnce(j.store, DetRand("c6"), FixedClock(T0 + 1200))
        assertEquals(listOf("counter-resynced"), issues(r))
        assertTrue(r.wrote)
        own = decode(j.folder.files[devPath(me)]!!, me)
        assertEquals(6L, own.first.counter)
        assertEquals(6L, j.store.snapshot.sync?.ownCounter)
        // A missing own file is written again above the reserved counter.
        j.folder.files.remove(devPath(me))
        r = j.fs.runOnce(j.store, DetRand("c7"), FixedClock(T0 + 1300))
        assertTrue(r.wrote)
        own = decode(j.folder.files[devPath(me)]!!, me)
        assertEquals(7L, own.first.counter)
        // Leftover own temp files are swept.
        val tmp = "LocalGateKeys Sync/devices/.$me.lgksync.dead.tmp"
        j.folder.files[tmp] = byteArrayOf(0)
        j.fs.runOnce(j.store, DetRand("c8"), FixedClock(T0 + 1400))
        assertNull(j.folder.files[tmp])
    }

    @Test
    fun bad_member_name_is_reported_and_run_continues() {
        val j = joined()
        val o = obj(Keyring.parse(j.folder.files[KEYRING_PATH]!!)).toMutableMap()
        val members = (o["members"] as JsonValue.Arr).items.toMutableList()
        // Re-seal B's name with garbage under a valid MAC.
        val gk: GroupKey = epochKey("1")
        for (i in members.indices) {
            val m = obj(members[i])
            if (m["device_id"] != JsonValue.Str(B)) continue
            members[i] = JsonValue.Obj(m + ("name_ct" to JsonValue.Str(MemberNames.sealName(gk, A, "Wrong binding", DetRand("n")))))
        }
        o["members"] = JsonValue.Arr(members)
        val ring = Keyring.finish(o, gk)
        j.folder.files[KEYRING_PATH] = CanonicalJson.encode(ring, Dialect.UTF8)
        val r = j.fs.runOnce(j.store, DetRand("bn"), FixedClock(T0 + 1100))
        assertEquals(listOf(SyncIssue("bad-name", B)), r.issues)
    }

    // ---- attach ----

    private fun attachState(identity: DeviceIdentity, installId: String = INSTALL, hasFolder: Boolean = false): SyncGroupState {
        val gk = epochKey("1")
        return SyncGroupState(gk.groupId, gk.epoch, gk.key, identity, installId, hasFolder = hasFolder)
    }

    private fun attach(fs: FolderSync, store: MemoryStore) =
        fs.attach(store, "Pixel", DetRand("attach"), FixedClock(T0 + 1000)) { SyncFixtures.pwKey("1") }

    @Test
    fun attach_refusals() {
        val fresh = DeviceIdentity.generate(random = DetRand("fresh"))
        val fs = FolderSync(SyncFixtures.seededFolder(), INSTALL)
        assertEquals("not-joined", reason { attach(fs, MemoryStore()) })
        assertEquals(
            "rejoin-required",
            reason { attach(fs, MemoryStore(StoreSnapshot(sync = attachState(fresh, installId = "other-install")))) },
        )
        assertEquals(
            "already-has-folder",
            reason { attach(fs, MemoryStore(StoreSnapshot(sync = attachState(fresh, hasFolder = true)))) },
        )
        assertEquals(
            "no-group",
            reason { attach(FolderSync(MemoryFolder(), INSTALL), MemoryStore(StoreSnapshot(sync = attachState(fresh)))) },
        )
        val other = SyncFixtures.seededFolder()
        other.files[KEYRING_PATH] = Vectors.sync("keyring_existing_epoch1.json").readBytes()
        val before = other.image()
        assertEquals(
            "folder-has-other-group",
            reason { attach(FolderSync(other, INSTALL), MemoryStore(StoreSnapshot(sync = attachState(fresh)))) },
        )
        assertEquals(before, other.image())
    }

    @Test
    fun attach_adds_an_unlisted_identity_and_runs() {
        val fresh = DeviceIdentity.generate(random = DetRand("fresh"))
        val folder = SyncFixtures.seededFolder()
        val store = MemoryStore(StoreSnapshot(sync = attachState(fresh)))
        val report = attach(FolderSync(folder, INSTALL), store)
        assertEquals(emptyList(), report.issues)
        val state = store.snapshot.sync!!
        assertTrue(state.hasFolder)
        assertContentEquals(epochKey("1").key, state.key)
        assertEquals(1L, state.epoch)
        assertEquals(listOf(A, B, C, fresh.deviceId).sorted(), state.members)
        val ring = Keyring.parse(folder.files[KEYRING_PATH]!!)
        assertContentEquals(state.keyring, folder.files[KEYRING_PATH])
        assertEquals("Pixel", Keyring.memberNames(ring, epochKey("1"))[fresh.deviceId])
        assertEquals(epochKey("1"), Keyring.accept(ring, epochKey("1"), fresh))
        assertEquals(mapOf(A to 7L, B to 4L, C to 3L), state.lastSeen) // the first run read A/B/C
        assertTrue(report.wrote)
    }

    @Test
    fun attach_with_an_already_listed_identity_leaves_the_keyring_alone() {
        val folder = SyncFixtures.seededFolder()
        val ringBefore = folder.files[KEYRING_PATH]!!.copyOf()
        val store = MemoryStore(StoreSnapshot(sync = attachState(SyncFixtures.identity("A"))))
        attach(FolderSync(folder, INSTALL), store)
        assertContentEquals(ringBefore, folder.files[KEYRING_PATH])
        assertFalse(folder.writes.contains(KEYRING_PATH))
        assertTrue(store.snapshot.sync!!.hasFolder)
        assertContentEquals(ringBefore, store.snapshot.sync!!.keyring)
    }

    // ---- commit and write failures ----

    private fun editNote(j: Joined, title: String, at: Long) {
        val snap = j.store.snapshot
        val rec = obj(obj(snap.records[NOTE])["record"]) +
            mapOf("title" to JsonValue.Str(title), "updated_at" to JsonValue.Int(at))
        val w = Wrapper.make(Namespace.ITEM, Normalise.normalForm(Namespace.ITEM, JsonValue.Obj(rec)))
        j.store.snapshot = snap.copy(records = snap.records + (NOTE to w))
    }

    @Test
    fun commit_failure_is_busy_and_writes_nothing() {
        val j = joined()
        editNote(j, "Edited", T0 + 1050)
        val writes = j.folder.writes.size
        val before = j.store.snapshot
        j.store.failCommits = true
        val r = j.fs.runOnce(j.store, DetRand("busy"), FixedClock(T0 + 1100))
        assertEquals(listOf("busy"), issues(r))
        assertFalse(r.wrote)
        assertEquals(writes, j.folder.writes.size)
        assertEquals(before, j.store.snapshot)
    }

    @Test
    fun write_failure_keeps_the_reserved_counter() {
        val j = joined()
        val me = j.store.snapshot.sync!!.deviceId
        editNote(j, "Edited", T0 + 1050)
        j.folder.failWritesContaining = devPath(me)
        var r = j.fs.runOnce(j.store, DetRand("w1"), FixedClock(T0 + 1100))
        assertEquals(listOf("write-failed"), issues(r))
        assertFalse(r.wrote)
        assertEquals(2L, j.store.snapshot.sync?.ownCounter) // committed before the write
        assertEquals(1L, decode(j.folder.files[devPath(me)]!!, me).first.counter)
        j.folder.failWritesContaining = null
        r = j.fs.runOnce(j.store, DetRand("w2"), FixedClock(T0 + 1200))
        assertTrue(r.wrote)
        assertEquals(3L, decode(j.folder.files[devPath(me)]!!, me).first.counter) // 2 is never reused
        assertEquals(3L, j.store.snapshot.sync?.ownCounter)
    }

    /** A folder whose permission was revoked: `exists` throws, everything else delegates. */
    private class RevokedFolder(private val inner: MemoryFolder) : FolderAccess by inner {
        override fun exists(path: String): Boolean = throw SecurityException("Permission Denial: no persisted grant")
    }

    @Test
    fun throwing_exists_is_folder_missing_and_leaves_the_store_untouched() {
        val j = joined()
        editNote(j, "Edited while the grant was revoked", T0 + 1050)
        val before = j.store.snapshot
        val commits = j.store.commits
        val writes = j.folder.writes.size
        val image = j.folder.image()
        val r = FolderSync(RevokedFolder(j.folder), INSTALL).runOnce(j.store, DetRand("revoked"), FixedClock(T0 + 1100))
        assertEquals(listOf(SyncIssue("folder-missing", FolderLayout.SYNC_DIR)), r.issues)
        assertFalse(r.wrote)
        assertEquals(commits, j.store.commits)
        assertEquals(before, j.store.snapshot)
        assertEquals(writes, j.folder.writes.size)
        assertEquals(image, j.folder.image())
    }
}
