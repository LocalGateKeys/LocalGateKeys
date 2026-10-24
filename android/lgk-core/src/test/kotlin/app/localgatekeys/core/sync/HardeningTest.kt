package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.engine.VersionVector
import app.localgatekeys.core.group.SyncFormatException
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.group.ViewSignature
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MemoryFolder
import app.localgatekeys.core.support.MemoryStore
import app.localgatekeys.core.support.MergeVectors.A
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.SyncFixtures.INSTALL
import app.localgatekeys.core.support.SyncFixtures.PHONE
import app.localgatekeys.core.support.SyncFixtures.T0
import app.localgatekeys.core.support.SyncFixtures.devPath
import app.localgatekeys.core.support.SyncFixtures.epochKey
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Audit 2026-10-24 M-6 / M-7 (desktop `tests/test_secfix_sync_vv.py`, `tests/test_secfix_sync_views.py`). */
class HardeningTest {
    private val cases = Vectors.json(Vectors.sync("hardening_cases.json")).obj().fields

    private fun issues(r: RunReport) = r.issues.map { it.kind }

    private fun longMap(v: JsonValue?): Map<String, Long>? =
        if (v == null || v == JsonValue.Null) null else v.obj().fields.mapValues { it.value.long() }

    private fun strOrNull(v: JsonValue?): String? = if (v == null || v == JsonValue.Null) null else v.str()

    // ---- shared vectors ----

    @Test
    fun constants_match_the_desktop() {
        val c = cases.getValue("constants").obj().fields
        assertEquals(Plausibility.MAX_VV_COUNTER, c.getValue("MAX_VV_COUNTER").long())
        assertEquals(Plausibility.MAX_UNKNOWN_VV_COUNTER, c.getValue("MAX_UNKNOWN_VV_COUNTER").long())
        assertEquals(Plausibility.MAX_VV_STEP, c.getValue("MAX_VV_STEP").long())
        assertEquals(Plausibility.MAX_VV_KEYS.toLong(), c.getValue("MAX_VV_KEYS").long())
        assertEquals(FolderSync.MAX_FILE_COUNTER, c.getValue("MAX_FILE_COUNTER").long())
        assertEquals(FolderSync.MAX_COUNTER_JUMP, c.getValue("MAX_COUNTER_JUMP").long())
    }

    @Test
    fun vv_cases_match_the_desktop() {
        val vv = (cases.getValue("vv") as JsonValue.Arr).items
        assertTrue(vv.isNotEmpty())
        for (case in vv) {
            val o = case.obj().fields
            val known = (o.getValue("known") as JsonValue.Arr).items.map { it.str() }.toSet()
            val got = Plausibility.implausibleVv(longMap(o["remote"])!!, longMap(o["local"]), known)
            assertEquals(strOrNull(o["expected"]), got, "case $o")
        }
    }

    @Test
    fun counter_cases_match_the_desktop() {
        for (case in (cases.getValue("counters") as JsonValue.Arr).items) {
            val o = case.obj().fields
            val last = o["last"].let { if (it == null || it == JsonValue.Null) null else it.long() }
            assertEquals(strOrNull(o["expected"]), FolderSync.counterVerdict(o.getValue("counter").long(), last), "case $o")
        }
    }

    @Test
    fun signature_vector_and_cases_match_the_desktop() {
        val raw = SyncFixtures.deviceBytes("A")
        val header = ViewFile.decodeHeader(raw)
        val sig = Vectors.sync("signatures/A.lgksig").readBytes()
        val a = SyncFixtures.identity("A")
        assertContentEquals(a.signingPublicKey, ViewSignature.verify(sig, raw, header))
        assertContentEquals(sig, ViewSignature.sign(raw, header, a)) // Ed25519 is deterministic
        val list = (cases.getValue("signatures") as JsonValue.Arr).items
        assertTrue(list.size > 10)
        for (case in list) {
            val o = case.obj().fields
            val got = try {
                ViewSignature.verify(o.getValue("signature").str().toByteArray(Charsets.UTF_8), raw, header)
                "valid"
            } catch (e: SyncFormatException) {
                e.reason
            }
            assertEquals(o.getValue("expected").str(), got, o.getValue("name").str())
        }
    }

    // ---- runner ----

    @Test
    fun poisoned_vector_is_quarantined_and_the_rest_merges() {
        val views = SyncFixtures.views()
        val first = views[0]
        val bad = first.states[0]
        val poisoned = ItemState(bad.itemId, bad.vv.mapValues { VersionVector.MAX_COUNTER }, bad.deleted, bad.deletedAt, bad.item)
        val forged = listOf(PeerView(first.deviceId, listOf(poisoned) + first.states.drop(1))) + views.drop(1)
        val r = SyncRunner.run(StoreSnapshot(), forged, PHONE, T0 + 1000)
        assertTrue(SyncIssue("implausible-vv", "${first.deviceId}:${bad.itemId}") in r.issues)
        assertTrue(r.records!!.isNotEmpty())
        for (s in r.ownStates!!) assertTrue(s.vv.values.all { it < 100 }, s.itemId)
    }

    // ---- folder ----

    private class Joined(val folder: MemoryFolder, val store: MemoryStore, val fs: FolderSync)

    private fun joined(): Joined {
        val folder = SyncFixtures.seededFolder()
        val store = MemoryStore()
        val fs = FolderSync(folder, INSTALL)
        val pw = SyncFixtures.pwKey("1")
        fs.join(store, "Pixel", DetRand("hardening|join"), FixedClock(T0 + 1000)) { pw }
        return Joined(folder, store, fs)
    }

    private fun aStates(): List<ItemState> = ViewFile.decode(SyncFixtures.deviceBytes("A"), epochKey("1"), A).second

    private fun writeA(j: Joined, counter: Long, label: String): ByteArray {
        val raw = ViewFile.encode(epochKey("1"), A, counter, aStates(), FixedClock(T0 + 1500), DetRand(label))
        j.folder.files[devPath(A)] = raw
        return raw
    }

    private fun pin(j: Joined, device: String, key: ByteArray) {
        val snap = j.store.snapshot
        val st = snap.sync!!
        j.store.snapshot = snap.copy(sync = st.copy(viewSigners = st.viewSigners + (device to Base64Std.encode(key))))
    }

    @Test
    fun own_view_is_signed_and_pinned() {
        val j = joined()
        val st = j.store.snapshot.sync!!
        val raw = j.folder.files[devPath(st.deviceId)]!!
        val sig = j.folder.files[FolderLayout.signatureFile(st.deviceId)!!]!!
        assertContentEquals(st.identity.signingPublicKey, ViewSignature.verify(sig, raw, ViewFile.decodeHeader(raw)))
        assertEquals(Base64Std.encode(st.identity.signingPublicKey), st.viewSigners[st.deviceId])
    }

    @Test
    fun unsigned_views_of_older_peers_are_accepted_until_pinned() {
        val j = joined()
        writeA(j, 8, "a8")
        assertEquals(emptyList(), issues(j.fs.runOnce(j.store, DetRand("r1"), FixedClock(T0 + 1600))))
        assertEquals(8L, j.store.snapshot.sync!!.lastSeen[A])
        pin(j, A, SyncFixtures.identity("A").signingPublicKey)
        writeA(j, 9, "a9")
        assertEquals(listOf("view-unsigned"), issues(j.fs.runOnce(j.store, DetRand("r2"), FixedClock(T0 + 1700))))
        assertEquals(8L, j.store.snapshot.sync!!.lastSeen[A])
        // A signs it: accepted
        val raw = j.folder.files[devPath(A)]!!
        j.folder.files[FolderLayout.signatureFile(A)!!] = ViewSignature.sign(raw, ViewFile.decodeHeader(raw), SyncFixtures.identity("A"))
        assertEquals(emptyList(), issues(j.fs.runOnce(j.store, DetRand("r3"), FixedClock(T0 + 1800))))
        assertEquals(9L, j.store.snapshot.sync!!.lastSeen[A])
        // someone else signs A's next file
        val next = writeA(j, 10, "a10")
        j.folder.files[FolderLayout.signatureFile(A)!!] = ViewSignature.sign(next, ViewFile.decodeHeader(next), SyncFixtures.identity("B"))
        assertEquals(listOf("view-forged"), issues(j.fs.runOnce(j.store, DetRand("r4"), FixedClock(T0 + 1900))))
    }

    @Test
    fun a_valid_signature_pins_the_peer() {
        val j = joined()
        val raw = writeA(j, 8, "a8")
        j.folder.files[FolderLayout.signatureFile(A)!!] = ViewSignature.sign(raw, ViewFile.decodeHeader(raw), SyncFixtures.identity("A"))
        assertEquals(emptyList(), issues(j.fs.runOnce(j.store, DetRand("r1"), FixedClock(T0 + 1600))))
        assertEquals(Base64Std.encode(SyncFixtures.identity("A").signingPublicKey), j.store.snapshot.sync!!.viewSigners[A])
        writeA(j, 9, "a9") // forged by a group-key holder, no signature
        assertEquals(listOf("view-unsigned"), issues(j.fs.runOnce(j.store, DetRand("r2"), FixedClock(T0 + 1700))))
    }

    @Test
    fun huge_counter_of_an_unpinned_peer_is_refused() {
        val j = joined()
        writeA(j, VersionVector.MAX_COUNTER, "amax")
        assertEquals(listOf("implausible-counter"), issues(j.fs.runOnce(j.store, DetRand("r1"), FixedClock(T0 + 1600))))
        assertEquals(7L, j.store.snapshot.sync!!.lastSeen[A])
    }

    @Test
    fun own_file_written_by_someone_else_is_reported_and_taken_back() {
        val j = joined()
        val st = j.store.snapshot.sync!!
        val me = st.deviceId
        val own = ViewFile.decode(j.folder.files[devPath(me)]!!, epochKey("1"), me).second
        val forged = st.ownCounter + 3
        j.folder.files[devPath(me)] = ViewFile.encode(epochKey("1"), me, forged, own, FixedClock(T0 + 1100), DetRand("f"))
        val r = j.fs.runOnce(j.store, DetRand("r1"), FixedClock(T0 + 1200))
        assertEquals(listOf("own-file-rewritten"), issues(r))
        assertTrue(r.wrote)
        assertEquals(forged + 1, j.store.snapshot.sync!!.ownCounter)
        // a huge forged counter is not followed (peers refused it)
        val reserved = j.store.snapshot.sync!!.ownCounter
        j.folder.files[devPath(me)] = ViewFile.encode(epochKey("1"), me, VersionVector.MAX_COUNTER, own, FixedClock(T0 + 1300), DetRand("g"))
        val r2 = j.fs.runOnce(j.store, DetRand("r2"), FixedClock(T0 + 1400))
        assertEquals(listOf("own-file-rewritten"), issues(r2))
        assertEquals(reserved + 1, j.store.snapshot.sync!!.ownCounter)
    }

    @Test
    fun own_counter_overflow_is_an_issue_not_a_crash() {
        val j = joined()
        val snap = j.store.snapshot
        j.store.snapshot = snap.copy(sync = snap.sync!!.copy(ownCounter = VersionVector.MAX_COUNTER))
        j.folder.files.remove(devPath(snap.sync!!.deviceId))
        val r = j.fs.runOnce(j.store, DetRand("r1"), FixedClock(T0 + 1200))
        assertTrue("counter-exhausted" in issues(r))
        assertFalse(r.wrote)
    }

    @Test
    fun new_epoch_clears_peer_counters_and_keys() {
        val st = joinedState()
        val reset = FolderSync.epochReset(st.copy(viewSigners = st.viewSigners + (A to "x")), 2, ByteArray(32) { 9 })
        assertEquals(emptyMap(), reset.lastSeen)
        assertEquals(emptyMap(), reset.peerDigests)
        assertEquals(setOf(st.deviceId), reset.viewSigners.keys)
        assertEquals(2L, reset.epoch)
    }

    private fun joinedState(): SyncGroupState = joined().store.snapshot.sync!!
}
