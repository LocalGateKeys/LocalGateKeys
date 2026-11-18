package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.HelloCounterSource
import app.localgatekeys.core.lan.LanClient
import app.localgatekeys.core.lan.LanConnection
import app.localgatekeys.core.lan.LanConnector
import app.localgatekeys.core.lan.LanFeatures
import app.localgatekeys.core.lan.LanMessage
import app.localgatekeys.core.lan.LanMessages
import app.localgatekeys.core.lan.LanTransport
import app.localgatekeys.core.lan.PinnedPeer
import app.localgatekeys.core.lan.SealedHello
import app.localgatekeys.core.lan.SecureChannel
import app.localgatekeys.core.lan.SessionHello
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.records.ConflictSuffix
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MemoryCounterStore
import app.localgatekeys.core.support.MemoryFolder
import app.localgatekeys.core.support.MemoryStore
import app.localgatekeys.core.support.MergeVectors.arr
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.QueueRandom
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.SyncFixtures.T0
import app.localgatekeys.core.support.SyncFixtures.devPath
import app.localgatekeys.core.support.Vectors
import app.localgatekeys.core.sync.CollectionCatalogTest.Companion.CAT
import app.localgatekeys.core.sync.CollectionCatalogTest.Companion.LNK
import app.localgatekeys.core.sync.CollectionCatalogTest.Companion.MEM
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Personal collection sync (sub-plan 07 Task 5j), the Kotlin port of LGKCore `CollectionSyncTests` (themselves ports of
 * the desktop's `tests/test_vault_bridge_collections.py` and `tests/test_collections_sync_e2e.py`): catalog rows,
 * memberships and share links travel as `col:`/`cm:`/`csl:` states only between devices that read them (a folder
 * member's signed `.lgkcol`, a Wi-Fi peer's `features` answer); item records keep their v1 shape, so an older peer gets
 * exactly today's view and never loses anything. Byte checks against `tests/vectors/share/collections/states.json`.
 */
class CollectionSyncTest {
    companion object {
        const val NOW = 1_800_000_000L
        const val FAMILY = "3f2a6c1e-8b4d-4e7a-9c05-d1e2f3a4b5c6"
        const val WORK = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
        const val OTHER = "0000000b-0000-4000-8000-000000000000"
        const val LOW = "0000000a-0000-4000-8000-000000000000"
        const val N1 = "11111111-1111-4111-8111-111111111111"
        const val N2 = "55555555-5555-4555-8555-555555555555"
        const val PERSONAL = "77777777-7777-4777-8777-777777777777"
    }

    /** One of a person's devices, in memory: its store, its personal-group device id and its share records. */
    private class Dev(val id: String) {
        var snap = StoreSnapshot()
        var shares = CollectionShares.NONE
    }

    // ---- helpers ----

    private fun create(snap: StoreSnapshot, id: String, name: String, description: String = ""): StoreSnapshot =
        snap.copy(records = CollectionCatalog.create(name, description, snap, NOW) { id }.first.records)

    private fun note(snap: StoreSnapshot, id: String, title: String, collections: List<String> = emptyList(), at: Long = 1): StoreSnapshot {
        val s = snap.copy(records = snap.records + (id to CollectionCatalogTest.item(id, title = title, extra = mapOf("updated_at" to JsonValue.Int(at)))))
        return if (collections.isEmpty()) s else member(s, id, collections)
    }

    private fun member(snap: StoreSnapshot, item: String, ids: List<String>): StoreSnapshot {
        val change = CollectionCatalog.setMemberships(item, "note", ids, snap) ?: return snap
        return snap.copy(records = change.records)
    }

    private fun edit(snap: StoreSnapshot, item: String, title: String, at: Long): StoreSnapshot =
        snap.copy(records = snap.records + (item to CollectionCatalogTest.item(item, title = title, extra = mapOf("updated_at" to JsonValue.Int(at)))))

    private fun title(snap: StoreSnapshot, item: String): String? = str(obj(obj(snap.records[item])["record"])["title"])

    private fun names(snap: StoreSnapshot): Map<String, String> = CollectionCatalog.collections(snap).associate { it.id to it.name }

    private fun membership(snap: StoreSnapshot, item: String): List<String> = CollectionCatalog.memberships(item, snap)

    /** Conflict copies stored as items (a collection state is never one). */
    private fun copies(snap: StoreSnapshot): List<String> =
        snap.itemRecords.keys.filter { (title(snap, it) ?: "").endsWith(ConflictSuffix.SUFFIX) }.sorted()

    private fun stateIds(ids: Iterable<String>): Set<String> = ids.filter { CollectionStates.isStateId(it) }.toSet()

    private fun canonical(v: JsonValue?): ByteArray = CanonicalJson.encode(assertNotNull(v), Dialect.UTF8)

    /** [dev]'s published view; its meta is kept, as a run's commit keeps it. */
    private fun view(dev: Dev, collections: Boolean = true): Map<String, ItemState> {
        val v = SyncMeta.localView(dev.snap.records, dev.snap.meta, dev.id, NOW, collections, dev.shares)
        dev.snap = dev.snap.copy(meta = v.meta)
        return v.states
    }

    private fun run(dst: Dev, peer: PeerView, collections: Boolean = true): RunReport {
        val report = SyncRunner.run(dst.snap, listOf(peer), dst.id, NOW, collections = collections, shares = dst.shares)
        report.records?.let { dst.snap = dst.snap.copy(records = it) }
        report.meta?.let { dst.snap = dst.snap.copy(meta = it) }
        return report
    }

    /** [dst] merges [src]'s personal view (one transport run with one peer). */
    private fun pull(dst: Dev, src: Dev, collections: Boolean = true, srcCollections: Boolean? = null): RunReport {
        val theirs = view(src, srcCollections ?: collections)
        return run(dst, PeerView(src.id, theirs.values.sortedBy { it.itemId }), collections)
    }

    private fun sync(a: Dev, b: Dev, rounds: Int = 2, collections: Boolean = true) {
        repeat(rounds) {
            pull(b, a, collections)
            pull(a, b, collections)
        }
    }

    // ---- between two devices of this version ----

    @Test fun collections_and_membership_sync_between_new_devices_and_settle() {
        val a = Dev("dev-a")
        val b = Dev("dev-b")
        a.snap = create(a.snap, FAMILY, "Family", "the house")
        a.snap = note(a.snap, N1, "Wi-Fi", listOf(FAMILY))
        a.snap = note(a.snap, N2, "Plain")
        assertEquals(emptyList(), pull(b, a).issues)
        assertEquals(mapOf(FAMILY to "Family"), names(b.snap))
        assertEquals("the house", CollectionCatalog.collections(b.snap).first().description)
        assertEquals(listOf(FAMILY), membership(b.snap, N1))
        assertEquals(emptyList(), membership(b.snap, N2))

        // B moves it from Family into a new Work collection; A follows.
        b.snap = create(b.snap, WORK, "Work")
        b.snap = member(b.snap, N1, listOf(WORK))
        assertEquals(emptyList(), pull(a, b).issues)
        assertEquals(mapOf(FAMILY to "Family", WORK to "Work"), names(a.snap))
        assertEquals(listOf(WORK), membership(a.snap, N1))
        // Settled: another round changes nothing on either side.
        sync(a, b)
        val before = view(a) to view(b)
        sync(a, b)
        assertEquals(before.first, view(a))
        assertEquals(before.second, view(b))
        assertEquals(setOf(CAT + FAMILY, CAT + WORK, MEM + N1), stateIds(before.first.keys))
    }

    @Test fun items_without_collections_sync_exactly_as_before() {
        val a = Dev("dev-a")
        a.snap = create(a.snap, FAMILY, "Family")
        a.snap = note(a.snap, N1, "Tagged", listOf(FAMILY))
        a.snap = note(a.snap, N2, "Plain")
        val old = SyncMeta.localView(a.snap.records, a.snap.meta, a.id, NOW).states
        val new = SyncMeta.localView(a.snap.records, a.snap.meta, a.id, NOW, collections = true).states
        assertEquals(emptySet(), stateIds(old.keys), "no collection state leaves for a peer that does not read them")
        assertEquals(old, new.filterKeys { !CollectionStates.isStateId(it) })
        for (id in listOf(N1, N2)) {
            assertContentEquals(canonical(old[id]?.item), canonical(new[id]?.item), "byte for byte")
            assertEquals(setOf("ns", "schema", "updated_at", "record"), obj(old[id]?.item).keys)
            assertNull(obj(obj(old[id]?.item)["record"])["collection_ids"], "item records keep the v1 shape")
        }
        assertEquals(setOf(CAT + FAMILY, MEM + N1), stateIds(new.keys))
        assertTrue(new.values.filter { CollectionStates.isStateId(it.itemId) }.all { obj(it.item)["ns"] == JsonValue.Str(CollectionStates.NAMESPACE) })
    }

    @Test fun two_devices_change_one_membership_at_once_and_both_stay() {
        val a = Dev("dev-a")
        val b = Dev("dev-b")
        a.snap = create(a.snap, FAMILY, "X")
        a.snap = create(a.snap, WORK, "Y")
        a.snap = note(a.snap, N1, "Shared note")
        sync(a, b)
        a.snap = member(a.snap, N1, listOf(FAMILY))
        b.snap = member(b.snap, N1, listOf(WORK))
        b.snap = edit(b.snap, N1, "Renamed on B", 5)
        val report = pull(b, a)
        assertEquals(emptyList(), report.issues)
        assertEquals(0, report.conflicts, "a membership change is never a conflict the person sees")
        sync(a, b, rounds = 3)
        for (dev in listOf(a, b)) {
            assertEquals(listOf(FAMILY, WORK).sorted(), membership(dev.snap, N1))
            assertEquals("Renamed on B", title(dev.snap, N1))
            assertEquals(emptyList(), copies(dev.snap), "a membership change never makes a conflict copy")
            assertEquals(setOf(N1, CAT + FAMILY, CAT + WORK, MEM + N1), dev.snap.records.keys, "the engine's copy of a membership is never stored")
        }
    }

    @Test fun same_name_collections_made_on_two_devices_converge() {
        val a = Dev("dev-a")
        val b = Dev("dev-b")
        a.snap = create(a.snap, LOW, "Family")
        b.snap = create(b.snap, OTHER, "family")
        sync(a, b, rounds = 3)
        assertEquals(names(a.snap), names(b.snap))
        assertEquals(mapOf(LOW to "Family", OTHER to "family (2)"), names(a.snap), "the larger id gets the number")
        // updated_at is untouched by the rename.
        assertEquals(listOf(NOW, NOW), CollectionCatalog.collections(a.snap).map { it.updatedAt })
        val before = view(a) to view(b)
        sync(a, b)
        assertEquals(before.first, view(a))
        assertEquals(before.second, view(b))
    }

    @Test fun deleting_a_collection_syncs_and_its_items_stay() {
        val a = Dev("dev-a")
        val b = Dev("dev-b")
        a.snap = create(a.snap, FAMILY, "Family")
        a.snap = note(a.snap, N1, "Kept", listOf(FAMILY))
        sync(a, b)
        b.snap = b.snap.copy(records = CollectionCatalog.delete(FAMILY, b.snap, emptyList(), emptySet()).change.records)
        sync(a, b)
        for (dev in listOf(a, b)) {
            assertEquals(emptyMap(), names(dev.snap))
            assertEquals(emptyList(), membership(dev.snap, N1))
            assertNotNull(dev.snap.records[N1])
            assertEquals(true, dev.snap.meta[CAT + FAMILY]?.deleted)
        }
    }

    @Test fun a_removed_item_takes_its_membership_record_with_it() {
        val a = Dev("dev-a")
        val b = Dev("dev-b")
        a.snap = create(a.snap, FAMILY, "Family")
        a.snap = note(a.snap, N1, "Gone soon", listOf(FAMILY))
        sync(a, b)
        a.snap = a.snap.copy(records = a.snap.records - N1 - (MEM + N1)) // the person deleted it (the trash row keeps its collections)
        sync(a, b)
        for (dev in listOf(a, b)) {
            assertNull(dev.snap.records[N1])
            assertNull(dev.snap.records[MEM + N1])
            assertEquals(true, dev.snap.meta[MEM + N1]?.deleted)
            assertEquals(mapOf(FAMILY to "Family"), names(dev.snap))
        }
    }

    // ---- with an older peer (a v1 view: no collection states, records without collection_ids) ----

    @Test fun an_older_peer_edits_an_item_and_the_new_devices_keep_its_collections() {
        val a = Dev("dev-a")
        val b = Dev("dev-b")
        val old = Dev("dev-old")
        a.snap = create(a.snap, FAMILY, "Family")
        a.snap = note(a.snap, N1, "Door code", listOf(FAMILY))
        sync(a, b)
        sync(a, old, collections = false) // the older peer only ever runs without collections
        assertEquals(emptyList(), membership(old.snap, N1), "the older peer gets the item, not the membership")
        assertEquals(emptySet(), stateIds(old.snap.records.keys))
        old.snap = edit(old.snap, N1, "Door code (new)", 5)
        val report = pull(a, old, collections = true, srcCollections = false) // a v1 view in a collections run
        assertEquals(emptyList(), report.issues)
        assertEquals(0, report.conflicts)
        assertEquals("Door code (new)", title(a.snap, N1))
        assertEquals(listOf(FAMILY), membership(a.snap, N1), "the older peer's edit keeps the newer device's collections")
        pull(b, a)
        assertEquals("Door code (new)", title(b.snap, N1))
        assertEquals(listOf(FAMILY), membership(b.snap, N1))
        pull(old, a, collections = false)
        assertEquals("Door code (new)", title(old.snap, N1))
        assertEquals(emptyList(), copies(a.snap))
        assertEquals(emptyList(), copies(old.snap))
    }

    @Test fun collection_states_reaching_a_run_without_collections_are_dropped() {
        val a = Dev("dev-a")
        val old = Dev("dev-old")
        a.snap = create(a.snap, FAMILY, "Family")
        a.snap = note(a.snap, N1, "Tagged", listOf(FAMILY))
        val report = pull(old, a, collections = false, srcCollections = true)
        assertEquals(emptyList(), report.issues)
        assertNotNull(old.snap.records[N1])
        assertEquals(emptySet(), stateIds(old.snap.records.keys))
        assertEquals(emptySet(), stateIds(view(old, collections = false).keys))
        assertEquals(emptySet(), stateIds(old.snap.meta.keys))
    }

    @Test fun a_run_without_collections_never_tombstones_them() {
        val a = Dev("dev-a")
        val b = Dev("dev-b")
        a.snap = create(a.snap, FAMILY, "Family")
        a.snap = note(a.snap, N1, "Tagged", listOf(FAMILY))
        sync(a, b)
        val meta = a.snap.meta
        assertEquals(emptySet(), stateIds(view(a, collections = false).keys))
        assertEquals(meta, a.snap.meta, "their meta is left alone")
        pull(b, a, collections = true, srcCollections = false)
        assertEquals(mapOf(FAMILY to "Family"), names(b.snap))
        assertEquals(listOf(FAMILY), membership(b.snap, N1))
        assertTrue(view(a).values.filter { CollectionStates.isStateId(it.itemId) }.all { !it.deleted })
    }

    // ---- waiting and refusing ----

    @Test fun a_membership_waits_for_its_item_and_collection() {
        val a = Dev("dev-a")
        val b = Dev("dev-b")
        a.snap = create(a.snap, FAMILY, "Family")
        a.snap = note(a.snap, N1, "Tagged", listOf(FAMILY))
        val theirs = view(a)
        val report = run(b, PeerView(a.id, listOf(theirs.getValue(MEM + N1))))
        assertEquals(emptyList(), report.issues)
        assertNull(b.snap.meta[MEM + N1], "it waits: no meta, so it comes again")
        assertNull(b.snap.records[MEM + N1])
        // The item without its collection: still waiting.
        run(b, PeerView(a.id, listOf(theirs.getValue(N1), theirs.getValue(MEM + N1))))
        assertNull(b.snap.meta[MEM + N1])
        pull(b, a)
        assertEquals(listOf(FAMILY), membership(b.snap, N1))
    }

    @Test fun a_malformed_membership_is_quarantined_alone() {
        val a = Dev("dev-a")
        val b = Dev("dev-b")
        a.snap = create(a.snap, FAMILY, "Family")
        a.snap = note(a.snap, N1, "Tagged", listOf(FAMILY))
        val theirs = LinkedHashMap(view(a))
        val good = theirs.getValue(MEM + N1)
        val record = LinkedHashMap(obj(obj(good.item)["record"]))
        record["collection_ids"] = JsonValue.Arr(listOf(JsonValue.Str(FAMILY), JsonValue.Str("not-a-uuid")))
        val wrapper = LinkedHashMap(obj(good.item)).also { it["record"] = JsonValue.Obj(record) }
        theirs[good.itemId] = ItemState(good.itemId, good.vv, false, null, JsonValue.Obj(wrapper))
        val report = run(b, PeerView(a.id, theirs.values.sortedBy { it.itemId }))
        assertEquals(listOf("bad-peer-record"), report.issues.map { it.kind })
        assertNotNull(b.snap.records[N1])
        assertEquals(mapOf(FAMILY to "Family"), names(b.snap))
        assertEquals(emptyList(), membership(b.snap, N1))
    }

    /** [w] with a record no collection reader accepts (a damaged copy: same id, same namespace). */
    private fun damaged(w: JsonValue?): JsonValue {
        val f = LinkedHashMap(obj(assertNotNull(w)))
        f["record"] = JsonValue.Obj(mapOf("name" to JsonValue.Int(7)))
        return JsonValue.Obj(f)
    }

    @Test fun an_unreadable_stored_collection_state_is_neither_published_nor_tombstoned_nor_overwritten() {
        val a = Dev("dev-a")
        val b = Dev("dev-b")
        a.snap = create(a.snap, FAMILY, "Family")
        a.snap = note(a.snap, N1, "Tagged", listOf(FAMILY))
        sync(a, b)
        assertEquals(listOf(FAMILY), membership(b.snap, N1))
        // B's copies of the row and the membership become unreadable.
        val badRow = damaged(b.snap.records[CAT + FAMILY])
        val badMember = damaged(b.snap.records[MEM + N1])
        b.snap = b.snap.copy(records = b.snap.records + (CAT + FAMILY to badRow) + (MEM + N1 to badMember))
        val metaBefore = b.snap.meta
        assertNotNull(metaBefore[CAT + FAMILY])
        assertNotNull(metaBefore[MEM + N1])
        // (a) B's view neither publishes nor tombstones them, and leaves their meta alone.
        val published = view(b)
        assertNull(published[CAT + FAMILY])
        assertNull(published[MEM + N1])
        assertEquals(metaBefore[CAT + FAMILY], b.snap.meta[CAT + FAMILY])
        assertEquals(metaBefore[MEM + N1], b.snap.meta[MEM + N1])
        // A's next run therefore keeps Family and the membership.
        assertEquals(emptyList(), pull(a, b).issues)
        assertEquals(mapOf(FAMILY to "Family"), names(a.snap))
        assertEquals(listOf(FAMILY), membership(a.snap, N1))
        // (b) Incoming changes of both are skipped on B: the stored bytes stay, nothing is reported.
        a.snap = a.snap.copy(records = assertNotNull(CollectionCatalog.rename(FAMILY, "Home", snapshot = a.snap, now = NOW + 5)).records)
        a.snap = member(a.snap, N1, emptyList())
        val report = pull(b, a)
        assertEquals(emptyList(), report.issues)
        assertContentEquals(canonical(badRow), canonical(b.snap.records[CAT + FAMILY]))
        assertContentEquals(canonical(badMember), canonical(b.snap.records[MEM + N1]))
        assertEquals(metaBefore[CAT + FAMILY], b.snap.meta[CAT + FAMILY])
        assertEquals(metaBefore[MEM + N1], b.snap.meta[MEM + N1])
    }

    @Test fun published_states_match_the_desktop_vectors_and_the_run_check_reads_them() {
        val doc = Vectors.json(Vectors.shareCollections("states.json")).obj().fields
        val valid = arr(doc["valid"]).map { obj(it) }
        val wrappers = valid.associate { str(it["id"])!! to (it["wrapper"] ?: JsonValue.Null) }
        // The store the vectors describe: Family, a note in Family and Work, and Family shared on this device (read, member).
        val dev = Dev("dev-a")
        dev.snap = dev.snap.copy(records = mapOf(CAT + FAMILY to wrappers.getValue(CAT + FAMILY)))
        dev.snap = note(dev.snap, N1, "Cabin")
        dev.snap = dev.snap.copy(records = dev.snap.records + (MEM + N1 to wrappers.getValue(MEM + N1)))
        dev.shares = CollectionShares(mapOf(FAMILY to CollectionShares.Link("read", "member")), setOf(FAMILY))
        val states = view(dev)
        assertEquals(wrappers.keys, stateIds(states.keys))
        for (v in valid) {
            val id = str(v["id"])!!
            val state = assertNotNull(states[id])
            assertContentEquals(canonical(v["wrapper"]), canonical(state.item), id)
            assertEquals(str(v["digest"]), SyncMeta.digest(state.item!!), id)
            assertNull(SyncRunner.check(state, emptyMap(), collections = true), id)
            // A stray top-level `id` under a reserved id is refused in the fold (quarantined alone), never taken for a copy.
            val stray = JsonValue.Obj(obj(v["wrapper"]) + ("id" to JsonValue.Str(id)))
            assertEquals("bad-remote", SyncRunner.check(ItemState(id, mapOf("dev-b" to 1L), false, null, stray), emptyMap(), collections = true), id)
        }
        // The share link says only the mode and this device's role: nothing else about the share leaves the device.
        assertEquals(setOf("kind", "collection_id", "mode", "role"), obj(obj(states[LNK + FAMILY]?.item)["record"]).keys)
        for (m in arr(doc["malformed"]).map { obj(it) }) {
            val state = ItemState(str(m["id"])!!, mapOf("dev-b" to 1L), false, null, m["wrapper"])
            assertEquals(str(m["verdict"]), SyncRunner.check(state, emptyMap(), collections = true), str(m["name"]))
        }
    }

    @Test fun without_readable_share_records_links_and_catalog_tombstones_wait() {
        val a = Dev("dev-a")
        val b = Dev("dev-b")
        a.shares = CollectionShares(mapOf(FAMILY to CollectionShares.Link("edit", "owner")))
        a.snap = create(a.snap, FAMILY, "Family")
        sync(a, b)
        assertEquals(CollectionStates.wrapper(CollectionStates.link(FAMILY, "edit", "owner")), b.snap.records[LNK + FAMILY])
        // B's catalog refuses: the collection is shared from another of this person's devices.
        val refused = assertFailsWith<CollectionCatalogException> { CollectionCatalog.delete(FAMILY, b.snap, emptyList(), emptySet()) }
        assertEquals(CollectionCatalog.Failure.SHARED, refused.failure)
        b.snap = b.snap.copy(records = b.snap.records - (CAT + FAMILY)) // an older or tampered app deletes it anyway
        a.shares = a.shares.copy(links = null) // A cannot read its share records right now
        val published = view(a)
        assertNull(published[LNK + FAMILY], "no link is published while unknown")
        assertEquals(false, a.snap.meta[LNK + FAMILY]?.deleted, "nor tombstoned")
        pull(a, b)
        assertEquals(mapOf(FAMILY to "Family"), names(a.snap), "the tombstone waits")
        assertEquals(false, a.snap.meta[CAT + FAMILY]?.deleted)
        // Readable again: shared here, so the row is republished above the tombstone and comes back on B.
        a.shares = a.shares.copy(links = mapOf(FAMILY to CollectionShares.Link("edit", "owner")))
        pull(a, b)
        assertEquals(mapOf(FAMILY to "Family"), names(a.snap))
        pull(b, a)
        assertEquals(mapOf(FAMILY to "Family"), names(b.snap))
    }

    // ---- shares across one person's own devices ----

    /**
     * M1 is a member of an owner's [mode] share of Family (it holds the alarm code from the share); M2 is M1's second
     * device, which is not in the share.
     */
    private fun memberDevices(mode: String): Pair<Dev, Dev> {
        val m1 = Dev("dev-m1")
        val m2 = Dev("dev-m2")
        m1.shares = CollectionShares(mapOf(FAMILY to CollectionShares.Link(mode, "member")), if (mode == "read") setOf(FAMILY) else emptySet())
        m1.snap = create(m1.snap, FAMILY, "Family")
        m1.snap = note(m1.snap, N1, "Alarm code", listOf(FAMILY))
        pull(m2, m1)
        assertEquals(listOf(FAMILY), membership(m2.snap, N1))
        assertEquals(CollectionStates.wrapper(CollectionStates.link(FAMILY, mode, "member")), m2.snap.records[LNK + FAMILY])
        return m1 to m2
    }

    @Test fun read_only_share_stays_read_only_on_a_members_second_device() {
        val (m1, m2) = memberDevices("read")
        assertEquals(setOf(FAMILY), CollectionCatalog.linkedReadOnlyIds(m2.snap))
        // M2's own catalog refuses a move into it, a rename and a delete, like the member's device does.
        m2.snap = note(m2.snap, PERSONAL, "Personal")
        assertFailsWith<ReadOnlyCollectionException> { CollectionCatalog.setMemberships(PERSONAL, "note", listOf(FAMILY), m2.snap) }
        assertFailsWith<ReadOnlyCollectionException> { CollectionCatalog.setMemberships(N1, "note", emptyList(), m2.snap) }
        assertEquals(
            CollectionCatalog.Failure.SHARED,
            assertFailsWith<CollectionCatalogException> { CollectionCatalog.rename(FAMILY, "Ours", snapshot = m2.snap, now = NOW) }.failure,
        )
        assertEquals(
            CollectionCatalog.Failure.SHARED,
            assertFailsWith<CollectionCatalogException> { CollectionCatalog.delete(FAMILY, m2.snap, emptyList(), emptySet()) }.failure,
        )

        // Even a forced change on M2 (an older app, a tampered vault) never changes it on M1: an edit, a move of a
        // personal item into the share and a rename of the shared collection.
        m2.snap = edit(m2.snap, N1, "Forced on M2", 5)
        m2.snap = m2.snap.copy(
            records = m2.snap.records +
                (MEM + PERSONAL to CollectionStates.wrapper(CollectionStates.membership(PERSONAL, listOf(FAMILY)))) +
                (CAT + FAMILY to CollectionCatalog.catalogWrapper(FAMILY, "Renamed on M2", "", NOW, NOW + 100)),
        )
        assertEquals(emptyList(), pull(m1, m2).issues)
        assertEquals("Alarm code", title(m1.snap, N1))
        assertEquals(emptyList(), membership(m1.snap, PERSONAL), "a personal item is never added to a read-only share")
        assertNotNull(m1.snap.records[PERSONAL], "the personal item itself syncs")
        assertEquals(mapOf(FAMILY to "Family"), names(m1.snap), "the shared collection keeps its name")
        // M1's copy wins back on M2.
        pull(m2, m1)
        assertEquals("Alarm code", title(m2.snap, N1))
        assertEquals(emptyList(), membership(m2.snap, PERSONAL))
        assertEquals(mapOf(FAMILY to "Family"), names(m2.snap))

        // A delete of the item, its membership and the collection from M2 is undone the same way.
        m2.snap = m2.snap.copy(records = m2.snap.records - N1 - (MEM + N1) - (CAT + FAMILY))
        sync(m1, m2)
        assertNotNull(m1.snap.records[N1])
        assertEquals(listOf(FAMILY), membership(m1.snap, N1))
        assertEquals(mapOf(FAMILY to "Family"), names(m1.snap))
        assertNotNull(m2.snap.records[N1])
        assertEquals(listOf(FAMILY), membership(m2.snap, N1))
        assertEquals(mapOf(FAMILY to "Family"), names(m2.snap))
        assertEquals(emptyList(), copies(m1.snap))

        // Settled without loops: another round changes nothing.
        val before = view(m1) to view(m2)
        sync(m1, m2)
        assertEquals(before.first, view(m1))
        assertEquals(before.second, view(m2))

        // The owner's next edit (applied on M1 by the share run) reaches M2 through M1.
        m1.snap = edit(m1.snap, N1, "Alarm code v2", 10)
        pull(m2, m1)
        assertEquals("Alarm code v2", title(m2.snap, N1))
    }

    // ---- final fix wave B: finding 4 (a share link whose holder device is gone stays for ever) ----

    /** [dev] forgets its link of [collectionId] through [ShareGroups.forgetLink] (on a store holding its snapshot). */
    private fun forget(dev: Dev, collectionId: String) {
        val store = MemoryStore(dev.snap)
        ShareGroups.forgetLink(store, collectionId)
        dev.snap = store.load()
    }

    @Test fun forgetting_the_link_of_a_lost_member_device_frees_the_collection_on_every_other_device() {
        val (_, m2) = memberDevices("read")
        val m3 = Dev("dev-m3")
        pull(m3, m2)
        assertEquals(setOf(FAMILY), CollectionCatalog.linkedReadOnlyIds(m3.snap))
        assertEquals(CollectionShares.Link("read", "member"), ShareGroups.receivedLink(m2.snap, FAMILY))
        // M1 (the device in the share) is lost.
        forget(m2, FAMILY)
        assertNull(m2.snap.records[LNK + FAMILY])
        assertNull(ShareGroups.receivedLink(m2.snap, FAMILY))
        assertEquals(emptySet(), CollectionCatalog.linkedReadOnlyIds(m2.snap))
        assertTrue(assertNotNull(view(m2)[LNK + FAMILY], "M2 publishes the link's tombstone").deleted)
        pull(m3, m2)
        assertNull(m3.snap.records[LNK + FAMILY])
        assertEquals(emptySet(), CollectionCatalog.linkedReadOnlyIds(m3.snap))
        CollectionCatalog.delete(FAMILY, m3.snap, emptyList(), emptySet()) // no longer refused
    }

    @Test fun a_device_that_still_holds_the_share_publishes_its_link_again() {
        val (m1, m2) = memberDevices("read")
        forget(m2, FAMILY)
        pull(m1, m2)
        pull(m2, m1)
        assertEquals(CollectionStates.wrapper(CollectionStates.link(FAMILY, "read", "member")), m2.snap.records[LNK + FAMILY])
        assertEquals(setOf(FAMILY), CollectionCatalog.linkedReadOnlyIds(m2.snap))
    }

    @Test fun forget_link_refusals() {
        val (_, m2) = memberDevices("read")
        assertEquals("no-link", assertFailsWith<ShareGroupException> { ShareGroups.forgetLink(MemoryStore(m2.snap), WORK) }.reason)
        // A damaged share store counts as shared here (fails closed).
        val damaged = MemoryStore(m2.snap.copy(shares = JsonValue.Str("not a share store")))
        assertEquals("shared-here", assertFailsWith<ShareGroupException> { ShareGroups.forgetLink(damaged, FAMILY) }.reason)
        assertNull(ShareGroups.receivedLink(damaged.load(), FAMILY))
    }

    // ---- re-review wave B: B1 (one collection shared from two of this person's devices) ----

    @Test fun a_collection_shared_from_two_devices_settles_on_one_link() {
        val o1 = Dev("dev-o1")
        val o2 = Dev("dev-o2")
        o1.shares = CollectionShares(mapOf(FAMILY to CollectionShares.Link("read", "owner")))
        o1.snap = create(o1.snap, FAMILY, "Family")
        pull(o2, o1)
        // O2 forgot the link and shared Family again, in edit mode.
        o2.snap = o2.snap.copy(records = o2.snap.records - (LNK + FAMILY))
        o2.shares = CollectionShares(mapOf(FAMILY to CollectionShares.Link("edit", "owner")))
        val o3 = Dev("dev-o3")
        val rounds = ArrayList<List<Map<String, Long>>>()
        repeat(5) {
            pull(o1, o2)
            pull(o2, o1)
            pull(o3, o2)
            rounds.add(listOf(o1, o2, o3).map { assertNotNull(view(it)[LNK + FAMILY]).vv })
        }
        assertEquals(rounds[4], rounds[3], rounds.toString())
        assertEquals(rounds[3], rounds[2], rounds.toString())
        val read = CollectionStates.link(FAMILY, "read", "owner")
        val edit = CollectionStates.link(FAMILY, "edit", "owner")
        val winner = if (CollectionSync.linkBeats(read, edit)) read else edit
        for (d in listOf(o1, o2, o3)) assertEquals(CollectionStates.wrapper(winner), view(d)[LNK + FAMILY]?.item, d.id)
        // Both sharing devices keep the other's link (their share sheets warn); the third device holds the winner's.
        assertNotNull(o1.snap.records[LNK + FAMILY])
        assertNotNull(o2.snap.records[LNK + FAMILY])
        assertEquals(CollectionStates.wrapper(winner), o3.snap.records[LNK + FAMILY])
        // O2 stops sharing (its stored link goes with it, as `ShareGroups.leave` does): it settles on O1's link.
        o2.shares = CollectionShares.NONE
        o2.snap = o2.snap.copy(records = o2.snap.records - (LNK + FAMILY))
        repeat(3) {
            pull(o1, o2)
            pull(o2, o1)
        }
        assertNull(o1.snap.records[LNK + FAMILY])
        assertEquals(CollectionStates.wrapper(read), o2.snap.records[LNK + FAMILY])
        val settled = listOf(o1, o2).map { assertNotNull(view(it)[LNK + FAMILY]).vv }
        pull(o1, o2)
        pull(o2, o1)
        assertEquals(settled, listOf(o1, o2).map { assertNotNull(view(it)[LNK + FAMILY]).vv })
    }

    @Test fun an_owner_link_beats_a_member_link() {
        val owner = CollectionStates.link(FAMILY, "read", "owner")
        val member = CollectionStates.link(FAMILY, "read", "member")
        val editMember = CollectionStates.link(FAMILY, "edit", "member")
        assertTrue(CollectionSync.linkBeats(owner, member) && !CollectionSync.linkBeats(member, owner))
        assertTrue(CollectionSync.linkBeats(owner, editMember) && !CollectionSync.linkBeats(editMember, owner))
        assertTrue(CollectionSync.linkBeats(member, editMember) != CollectionSync.linkBeats(editMember, member))
    }

    @Test fun edit_share_second_device_edits_reach_the_member_device() {
        val (m1, m2) = memberDevices("edit")
        assertEquals(emptySet(), CollectionCatalog.linkedReadOnlyIds(m2.snap))
        m2.snap = edit(m2.snap, N1, "Changed on M2", 5)
        pull(m1, m2)
        assertEquals("Changed on M2", title(m1.snap, N1))
    }

    // ---- Wi-Fi ----

    private val gk: GroupKey = SyncFixtures.epochKey("1")
    private val idA: DeviceIdentity = SyncFixtures.identity("A")
    private val idB: DeviceIdentity = SyncFixtures.identity("B")

    private fun pinned(i: DeviceIdentity) = PinnedPeer(i.deviceId, gk.groupId, i.signingPublicKey, i.exchangePublicKey, null)

    private fun lanStore(identity: DeviceIdentity, install: String) = MemoryStore(
        StoreSnapshot(sync = SyncGroupState(gk.groupId, gk.epoch, gk.key, identity, install, hasFolder = false)),
    )

    @Test fun lan_features_list_and_store() {
        assertEquals(listOf("dev-b"), LanFeatures.peers(emptyList(), "dev-b", true))
        assertNull(LanFeatures.peers(listOf("dev-b"), "dev-b", true))
        assertNull(LanFeatures.peers(emptyList(), "dev-b", false))
        assertEquals(listOf("dev-b"), LanFeatures.peers(listOf("dev-a", "dev-b"), "dev-a", false))
        val full = (0 until LanFeatures.MAX_PEERS).map { "dev-$it" }
        assertNull(LanFeatures.peers(full, "dev-x", true), "bounded like the desktop")
        // setPeer: true saved, false nothing to change, null not saved (past the bound, or the store refused).
        val store = PeerSavingStore(lanStore(idA, "lan-install-a"))
        assertEquals(true, LanFeatures.setPeer("dev-b", true, store))
        assertEquals(false, LanFeatures.setPeer("dev-b", true, store))
        store.setPeers(full)
        assertNull(LanFeatures.setPeer("dev-x", true, store))
        assertEquals(false, LanFeatures.setPeer("dev-0", true, store), "a listed peer stays")
        store.setPeers(emptyList())
        store.refusePeers = true
        assertNull(LanFeatures.setPeer("dev-b", true, store))
        assertEquals(emptyList(), store.load().sync?.collectionPeers)
        assertTrue(LanFeatures.readsCollections(listOf("later", "collections")))
        assertFalse(LanFeatures.readsCollections(listOf("later")))
        // The live parser now reads a features message (and writes the desktop's bytes).
        assertEquals(LanMessage.Features(LanFeatures.OURS), LanMessages.parse(LanFeatures.encode(LanFeatures.OURS)))
        assertContentEquals(LanFeatures.encode(LanFeatures.OURS), LanMessages.encode(LanMessage.Features(LanFeatures.OURS)))
    }

    /** A store that can refuse to save a change of `collectionPeers`; every other commit goes through. */
    private class PeerSavingStore(val inner: MemoryStore) : ItemStore {
        var refusePeers = false

        fun setPeers(peers: List<String>) {
            val s = inner.snapshot
            inner.snapshot = s.copy(sync = s.sync!!.copy(collectionPeers = peers))
        }

        override fun load(): StoreSnapshot = inner.load()

        override fun commit(change: StoreChange) {
            if (refusePeers && change.sync?.collectionPeers != inner.snapshot.sync?.collectionPeers) {
                throw FolderSyncException("busy", "refused by the test")
            }
            inner.commit(change)
        }
    }

    /**
     * B's side of a Wi-Fi sync behind a fake connection (the phone has no responder: this plays the desktop's or the
     * Apple app's): it merges A's view (collection states only when it listed A), answers with its own view, and answers
     * `features` like a current app ([collections]) or an older one (`bad-message`).
     */
    private inner class Responder(val store: PeerSavingStore, val collections: Boolean) {
        val views = ArrayList<List<ItemState>>()
        var features = 0
        var lastIssues: List<SyncIssue> = emptyList()

        /** When set, the `features` answer (an older or other app); this responder then records nothing itself. */
        var answerFeatures: List<String>? = null

        fun answer(request: ByteArray): ByteArray = LanMessages.encode(
            when (val m = LanMessages.parse(request)) {
                is LanMessage.Features -> {
                    features++
                    val fixed = answerFeatures
                    if (fixed != null) {
                        LanMessage.Features(fixed)
                    } else if (!collections) {
                        LanMessage.Error("bad-message")
                    } else if (LanFeatures.setPeer(idA.deviceId, LanFeatures.readsCollections(m.features), store) == null) {
                        lastIssues = listOf(SyncIssue("local-data", "collection peers could not be saved"))
                        LanMessage.Error("local-data")
                    } else {
                        LanMessage.Features(LanFeatures.OURS)
                    }
                }
                is LanMessage.View -> serveView(m)
                else -> LanMessage.Error("bad-message")
            },
        )

        private fun serveView(m: LanMessage.View): LanMessage {
            val states = ViewFile.decode(Base64Std.decodeStrict(m.view), gk, idA.deviceId).second
            views.add(states)
            val snap = store.load()
            val state = snap.sync!!
            val withCollections = collections && idA.deviceId in state.collectionPeers
            val run = SyncRunner.run(snap, listOf(PeerView(idA.deviceId, states)), state.deviceId, NOW, collections = withCollections)
            lastIssues = run.issues
            val own = run.ownStates ?: return LanMessage.Error("local-data")
            store.commit(StoreChange(snap.revision, run.records ?: snap.records, run.meta ?: snap.meta, snap.sync))
            val raw = ViewFile.encode(gk, idB.deviceId, 1, own, FixedClock(NOW), SystemRandomSource())
            return LanMessage.View(gk.groupId, gk.epoch, "0".repeat(32), 0, 1, raw.size.toLong(), Base64Std.encode(raw))
        }
    }

    /** B's half of each connection: opens A's sealed hello, answers with its own (counter [counter]), then the sealed answer. */
    private inner class Connection(val counter: Long, val answer: (ByteArray) -> ByteArray) : LanConnection {
        private var channel: SecureChannel? = null

        override fun exchange(frame: ByteArray): ByteArray {
            val ch = channel
            if (ch == null) {
                val (h, seal) = SealedHello.openInitiator(LanTransport.decodeFrame(frame), idB)
                SessionHello.verify(h, pinned(idA), gk.groupId)
                val rnd = SystemRandomSource()
                val mine = SessionHello.make(
                    idB, gk.groupId, h.sessionId, counter, QueueRandom(listOf(rnd.bytes(32), rnd.bytes(32))), LanTransport.VERSION,
                )
                channel = SecureChannel(idB, pinned(idA), gk.groupId, h.sessionId, SecureChannel.Role.RESPONDER, mine, h)
                return LanTransport.encodeFrame(SealedHello.sealResponder(mine, seal))
            }
            return ch.seal(answer(ch.open(frame)))
        }
    }

    private inner class Connector(val responder: Responder) : LanConnector {
        var opened = 0L

        override fun connect(peer: PinnedPeer): LanConnection {
            opened++
            return Connection(opened) { responder.answer(it) }
        }
    }

    private fun lanClient() = LanClient(idA, gk, HelloCounterSource(MemoryCounterStore(), FixedClock(NOW)), SystemRandomSource(), FixedClock(NOW))

    /**
     * One Wi-Fi sync as the app's initiator runs it with collections: the view exchange (collection states only for a
     * listed peer), `features` for a peer not yet listed (before any witness exchange), one merge, then the answer kept.
     */
    private fun lanSync(store: MemoryStore, client: LanClient, connector: Connector): RunReport {
        val snap = store.load()
        val state = snap.sync!!
        val peer = pinned(idB)
        val withCollections = peer.deviceId in state.collectionPeers
        val local = SyncMeta.localView(snap.records, snap.meta, state.deviceId, NOW, withCollections)
        val found = client.exchange(peer, local.states.values.sortedBy { it.itemId }, 1, connector, null, askFeatures = !withCollections)
        val report = SyncRunner.run(snap, listOf(PeerView(peer.deviceId, found.states)), state.deviceId, NOW, collections = withCollections)
        store.commit(StoreChange(snap.revision, report.records ?: snap.records, report.meta ?: snap.meta, snap.sync))
        found.collections?.let { LanFeatures.setPeer(peer.deviceId, it, store) }
        return report
    }

    private fun lanA(): MemoryStore {
        val a = lanStore(idA, "lan-install-a")
        var snap = create(a.snapshot, FAMILY, "Family")
        snap = note(snap, N1, "Wi-Fi", listOf(FAMILY))
        a.snapshot = snap
        return a
    }

    @Test fun lan_learns_features_after_the_first_exchange_then_syncs_collections() {
        val aStore = lanA()
        val bStore = PeerSavingStore(lanStore(idB, "lan-install-b"))
        val responder = Responder(bStore, collections = true)
        val connector = Connector(responder)
        val client = lanClient()

        assertEquals(emptyList(), lanSync(aStore, client, connector).issues)
        // First exchange: features learnt both ways, nothing of the collections sent yet.
        assertEquals(listOf(idB.deviceId), aStore.snapshot.sync?.collectionPeers)
        assertEquals(listOf(idA.deviceId), bStore.load().sync?.collectionPeers)
        assertEquals(1, responder.views.size)
        assertEquals(emptySet(), stateIds(responder.views[0].map { it.itemId }))
        assertNotNull(bStore.load().records[N1])
        assertEquals(emptyMap(), names(bStore.load()))

        assertEquals(emptyList(), lanSync(aStore, client, connector).issues)
        assertEquals(1, responder.features, "a listed peer is not asked again")
        assertEquals(mapOf(FAMILY to "Family"), names(bStore.load()))
        assertEquals(listOf(FAMILY), membership(bStore.load(), N1))

        // B takes it out of Family; A follows on the next exchange.
        bStore.inner.snapshot = member(bStore.inner.snapshot, N1, emptyList())
        assertEquals(emptyList(), lanSync(aStore, client, connector).issues)
        assertEquals(emptyList(), membership(aStore.snapshot, N1))
        assertEquals(emptyList(), responder.lastIssues)

        // The peer is updated to an app whose `features` list does not name collections: the phone asks again (it no
        // longer lists the peer), records it as not capable and sends it no collection state from then on (5j review
        // minor 3: the phone's side, not the test responder's).
        aStore.snapshot = aStore.snapshot.copy(sync = aStore.snapshot.sync!!.copy(collectionPeers = emptyList()))
        responder.answerFeatures = listOf("later")
        val asked = responder.features
        assertEquals(emptyList(), lanSync(aStore, client, connector).issues)
        assertEquals(asked + 1, responder.features)
        assertEquals(emptyList(), aStore.snapshot.sync?.collectionPeers)
        assertEquals(emptyList(), lanSync(aStore, client, connector).issues)
        assertEquals(asked + 2, responder.features, "a peer that is not capable is asked again")
        assertEquals(emptySet(), stateIds(responder.views.last().map { it.itemId }))
        assertNotNull(responder.views.last().firstOrNull { it.itemId == N1 }, "items still sync")
    }

    @Test fun lan_responder_that_cannot_save_the_peer_answers_local_data_and_is_asked_again() {
        val aStore = lanA()
        val bStore = PeerSavingStore(lanStore(idB, "lan-install-b"))
        val responder = Responder(bStore, collections = true)
        val connector = Connector(responder)
        val client = lanClient()
        bStore.refusePeers = true
        assertEquals(emptyList(), lanSync(aStore, client, connector).issues)
        assertEquals(listOf("local-data"), responder.lastIssues.map { it.kind })
        assertEquals(emptyList(), bStore.load().sync?.collectionPeers)
        assertEquals(emptyList(), aStore.snapshot.sync?.collectionPeers, "not recorded: one-sided sync never starts")
        // The responder can save again: the initiator asks again and both sides learn it.
        bStore.refusePeers = false
        assertEquals(emptyList(), lanSync(aStore, client, connector).issues)
        assertEquals(2, responder.features)
        assertEquals(listOf(idB.deviceId), aStore.snapshot.sync?.collectionPeers)
        assertEquals(listOf(idA.deviceId), bStore.load().sync?.collectionPeers)
        assertEquals(emptyList(), lanSync(aStore, client, connector).issues)
        assertEquals(mapOf(FAMILY to "Family"), names(bStore.load()))
        assertEquals(listOf(FAMILY), membership(bStore.load(), N1))
    }

    @Test fun lan_features_goes_after_the_view_and_before_the_witness_exchange() {
        val aStore = lanA()
        val bStore = PeerSavingStore(lanStore(idB, "lan-install-b"))
        val responder = Responder(bStore, collections = true)
        // Every message B receives, in order, by type.
        val order = ArrayList<String>()
        val connector = object : LanConnector {
            var opened = 0L

            override fun connect(peer: PinnedPeer): LanConnection {
                opened++
                return Connection(opened) { request ->
                    order.add(
                        when (LanMessages.parse(request)) {
                            is LanMessage.View -> "view"
                            is LanMessage.Features -> "features"
                            is LanMessage.Witness -> "witness"
                            else -> "other"
                        },
                    )
                    responder.answer(request)
                }
            }
        }
        val snap = aStore.load()
        val local = SyncMeta.localView(snap.records, snap.meta, idA.deviceId, NOW).states.values.sortedBy { it.itemId }
        // A format-1 exchange that publishes a witness afterwards (not inline), with features asked.
        val publish = app.localgatekeys.core.lan.LanPublish(false, 3, emptyMap())
        val found = lanClient().exchange(pinned(idB), local, 1, connector, publish, askFeatures = true)
        assertEquals(listOf("view", "features", "witness"), order)
        assertEquals(true, found.collections)
        // Not asked: no features message, the witness still goes.
        order.clear()
        lanClient().exchange(pinned(idB), local, 2, connector, publish, askFeatures = false)
        assertEquals(listOf("view", "witness"), order)
    }

    @Test fun lan_older_responder_never_gets_collection_states() {
        val aStore = lanA()
        val bStore = PeerSavingStore(lanStore(idB, "lan-install-b"))
        val responder = Responder(bStore, collections = false)
        val connector = Connector(responder)
        val client = lanClient()
        repeat(3) { assertEquals(emptyList(), lanSync(aStore, client, connector).issues) }
        assertEquals(3, responder.features, "asked each time, answered as an older app")
        assertEquals(emptyList(), aStore.snapshot.sync?.collectionPeers)
        assertEquals(3, responder.views.size)
        assertTrue(responder.views.all { stateIds(it.map { s -> s.itemId }).isEmpty() }, "no view with collection states")
        assertEquals(emptySet(), stateIds(bStore.load().records.keys))
        assertNotNull(bStore.load().records[N1])
        // A lost connection or another answer says nothing: the peer is neither added nor removed.
        val silent = LanClient(idA, gk, HelloCounterSource(MemoryCounterStore(), FixedClock(NOW)), SystemRandomSource(), FixedClock(NOW))
        val failing = object : LanConnector {
            override fun connect(peer: PinnedPeer): LanConnection = throw app.localgatekeys.core.lan.LanPeerNotAnswering("gone")
        }
        assertNull(silent.exchangeFeatures(pinned(idB), failing))
    }

    // ---- folder ----

    private val gk1: GroupKey = SyncFixtures.epochKey("1")
    private var clock = T0 + 2000

    private fun capPaths(id: String, feature: FeatureCapability.Feature) =
        FolderLayout.capabilityFile(id, feature)!! to FolderLayout.capabilitySignatureFile(id, feature)!!

    /** The seeded epoch-1 folder (members A, B and C, which also read collections). */
    private fun folderWithReaders(): MemoryFolder {
        val folder = SyncFixtures.seededFolder(signed = true)
        for (who in listOf("A", "B", "C")) {
            val identity = SyncFixtures.identity(who)
            val (raw, sig) = FeatureCapability.encode(gk1, identity, FeatureCapability.Feature.COLLECTIONS, FixedClock(T0), DetRand("col|$who"))
            val (p, s) = capPaths(identity.deviceId, FeatureCapability.Feature.COLLECTIONS)
            folder.files[p] = raw
            folder.files[s] = sig
        }
        return folder
    }

    private class Phone(val store: MemoryStore, val label: String) {
        val id: String get() = store.snapshot.sync!!.deviceId
    }

    private fun phone(folder: MemoryFolder, label: String, collections: Boolean): Phone {
        val store = MemoryStore()
        FolderSync(folder, "android-$label", collections = collections)
            .join(store, label, DetRand("5j|$label"), FixedClock(T0 + 1000)) { SyncFixtures.pwKey("1") }
        assertNotNull(store.snapshot.sync)
        return Phone(store, label)
    }

    private fun runPhone(folder: MemoryFolder, p: Phone, collections: Boolean = true): RunReport {
        clock += 10
        val report = FolderSync(folder, "android-${p.label}", collections = collections)
            .runOnce(p.store, DetRand("run|${p.label}|$clock"), FixedClock(clock))
        val bad = setOf("bad-peer-record", "apply-failed", "local-data", "write-failed", "busy", "bad-peer-data")
        assertEquals(emptyList(), report.issues.filter { it.kind in bad })
        return report
    }

    private fun published(folder: MemoryFolder, id: String): List<String> =
        ViewFile.decode(folder.files.getValue(devPath(id)), gk1, id).second.map { it.itemId }

    private fun capable(folder: MemoryFolder, p: Phone, feature: FeatureCapability.Feature): Boolean {
        val signer = Base64Std.encode(p.store.snapshot.sync!!.identity.signingPublicKey)
        return FolderSync(folder, "android-check").folderCapable(gk1, p.id, signer, feature)
    }

    @Test fun folder_collections_sync_between_new_members_and_settle() {
        val folder = folderWithReaders()
        val p1 = phone(folder, "p1", collections = true)
        val p2 = phone(folder, "p2", collections = true)
        runPhone(folder, p1)
        runPhone(folder, p2)
        for (p in listOf(p1, p2)) assertTrue(capable(folder, p, FeatureCapability.Feature.COLLECTIONS), "each phone wrote its signed .lgkcol")
        p1.store.snapshot = note(create(p1.store.snapshot, FAMILY, "Family"), N1, "Wi-Fi", listOf(FAMILY))
        repeat(2) {
            runPhone(folder, p1)
            runPhone(folder, p2)
        }
        assertTrue(CAT + FAMILY in stateIds(published(folder, p1.id)))
        assertEquals(mapOf(FAMILY to "Family"), names(p2.store.snapshot))
        assertEquals(listOf(FAMILY), membership(p2.store.snapshot, N1))
        p2.store.snapshot = member(create(p2.store.snapshot, WORK, "Work"), N1, listOf(WORK))
        repeat(2) {
            runPhone(folder, p2)
            runPhone(folder, p1)
        }
        assertEquals(listOf(WORK), membership(p1.store.snapshot, N1))
        // Settled: no view is written again.
        val files = folder.files[devPath(p1.id)]!!.toList() to folder.files[devPath(p2.id)]!!.toList()
        assertFalse(runPhone(folder, p1).wrote)
        assertFalse(runPhone(folder, p2).wrote)
        assertEquals(files.first, folder.files[devPath(p1.id)]!!.toList())
        assertEquals(files.second, folder.files[devPath(p2.id)]!!.toList())
    }

    @Test fun folder_older_member_gets_v1_views_until_it_updates() {
        val folder = folderWithReaders()
        val p1 = phone(folder, "p1", collections = true)
        val p2 = phone(folder, "p2", collections = false)
        p1.store.snapshot = note(create(p1.store.snapshot, FAMILY, "Family"), N1, "Wi-Fi", listOf(FAMILY))
        runPhone(folder, p1)
        runPhone(folder, p2, collections = false)
        assertNull(folder.files[capPaths(p2.id, FeatureCapability.Feature.COLLECTIONS).first], "an older app writes no collections file")
        assertEquals(emptySet(), stateIds(published(folder, p1.id)), "an older member never reads a collection state")
        assertEquals(emptySet(), stateIds(p2.store.snapshot.records.keys))
        assertNotNull(p2.store.snapshot.records[N1])
        p2.store.snapshot = edit(p2.store.snapshot, N1, "Wi-Fi (new)", 5) // the older member edits it
        runPhone(folder, p2, collections = false)
        runPhone(folder, p1)
        assertEquals("Wi-Fi (new)", title(p1.store.snapshot, N1))
        assertEquals(listOf(FAMILY), membership(p1.store.snapshot, N1), "the newer member keeps its collections")
        // P2 updates: it writes its file, and the collections follow.
        repeat(2) {
            runPhone(folder, p2)
            runPhone(folder, p1)
        }
        runPhone(folder, p2)
        assertTrue(MEM + N1 in stateIds(published(folder, p1.id)))
        assertEquals(mapOf(FAMILY to "Family"), names(p2.store.snapshot))
        assertEquals(listOf(FAMILY), membership(p2.store.snapshot, N1))
    }

    @Test fun folder_document_capability_does_not_count_for_collections() {
        val folder = folderWithReaders()
        val p1 = phone(folder, "p1", collections = true)
        val p2 = phone(folder, "p2", collections = true)
        val p2Identity = p2.store.snapshot.sync!!.identity
        val (raw, sig) = FeatureCapability.encode(gk1, p2Identity, FeatureCapability.Feature.DOCUMENTS, FixedClock(T0), DetRand("doc"))
        val doc = capPaths(p2.id, FeatureCapability.Feature.DOCUMENTS)
        val col = capPaths(p2.id, FeatureCapability.Feature.COLLECTIONS)
        folder.files[doc.first] = raw
        folder.files[doc.second] = sig
        // Someone with folder access copies P2's document capability under the collections name.
        folder.files[col.first] = raw
        folder.files[col.second] = sig
        assertTrue(capable(folder, p2, FeatureCapability.Feature.DOCUMENTS), "the copied files verify as what they are")
        assertFalse(capable(folder, p2, FeatureCapability.Feature.COLLECTIONS))
        p1.store.snapshot = create(p1.store.snapshot, FAMILY, "Family")
        runPhone(folder, p1)
        assertEquals(emptySet(), stateIds(published(folder, p1.id)), "P2 counts as older until it writes its own file")
        runPhone(folder, p2) // this version replaces the copy with a real one
        assertTrue(capable(folder, p2, FeatureCapability.Feature.COLLECTIONS))
        runPhone(folder, p1)
        assertTrue(CAT + FAMILY in stateIds(published(folder, p1.id)))
    }
}
