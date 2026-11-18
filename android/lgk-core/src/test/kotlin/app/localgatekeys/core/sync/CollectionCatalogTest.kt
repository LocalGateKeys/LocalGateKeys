package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.exporting.CxfExport
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.support.MergeVectors
import app.localgatekeys.core.support.MergeVectors.arr
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Personal collections in the item store (sub-plan 07 Task 5j; the port of LGKCore `CollectionCatalogTests`): the catalog
 * rules Windows has (`collections.py`), the migration of old local collections checked against the desktop's
 * `states.json`, and the shared filter that keeps every collection state out of the item readers in lgk-core (sync view,
 * sync run, CXF export).
 */
class CollectionCatalogTest {
    companion object {
        const val FAMILY = "3f2a6c1e-8b4d-4e7a-9c05-d1e2f3a4b5c6"
        const val WORK = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
        const val NOTE = "11111111-1111-4111-8111-111111111111"
        const val LOGIN = "22222222-2222-4222-8222-222222222222"
        const val DOCUMENT = "33333333-3333-4333-8333-333333333333"
        const val GONE = "44444444-4444-4444-8444-444444444444"
        const val NOTE2 = "55555555-5555-4555-8555-555555555555"
        const val UNKNOWN = "66666666-6666-4666-8666-666666666666"
        const val NOW = 1_800_000_000L
        const val CAT = CollectionStates.CATALOG_PREFIX
        const val MEM = CollectionStates.MEMBERSHIP_PREFIX
        const val LNK = CollectionStates.LINK_PREFIX

        fun s(v: String): JsonValue = JsonValue.Str(v)

        fun item(id: String, kind: String = "note", title: String = "Cabin", extra: Map<String, JsonValue> = emptyMap()): JsonValue {
            val r = linkedMapOf<String, JsonValue>(
                "id" to s(id), "kind" to s(kind), "title" to s(title), "created_at" to JsonValue.Int(1), "updated_at" to JsonValue.Int(1),
            )
            r.putAll(extra)
            return Wrapper.make(if (kind == "web" || kind == "desktop") Namespace.ENTRY else Namespace.ITEM, JsonValue.Obj(r))
        }

        /** A note, a second note, a login and a document. */
        fun base(): StoreSnapshot = StoreSnapshot(
            records = mapOf(
                NOTE to item(NOTE), NOTE2 to item(NOTE2, title = "Boat"), LOGIN to item(LOGIN, kind = "web"),
                DOCUMENT to item(DOCUMENT, kind = "document"),
            ),
            revision = 7,
        )

        fun link(cid: String, mode: String, role: String): JsonValue = CollectionStates.wrapper(CollectionStates.link(cid, mode, role))

        fun membership(item: String, ids: List<String>): JsonValue = CollectionStates.wrapper(CollectionStates.membership(item, ids))
    }

    /** Fresh canonical UUIDs, counting up. */
    class Ids {
        var n = 0
        fun next(): String {
            n += 1
            return "%08x-0000-4000-8000-000000000000".format(n)
        }
    }

    private fun make(snap: StoreSnapshot, name: String, gen: Ids): Pair<StoreSnapshot, String> {
        val (c, id) = CollectionCatalog.create(name, snapshot = snap, now = NOW, newId = gen::next)
        return snap.copy(records = c.records) to id
    }

    private fun expect(failure: CollectionCatalog.Failure, body: () -> Any?) {
        val e = assertFailsWith<CollectionCatalogException> { body() }
        assertEquals(failure, e.failure)
    }

    private fun canonical(v: JsonValue?): ByteArray = CanonicalJson.encode(v ?: fail("missing"), Dialect.UTF8)

    // ---- catalog ----

    @Test fun create_and_rename_follow_the_limits_and_casefold_uniqueness() {
        var snap = base()
        val gen = Ids()
        val (made, family) = CollectionCatalog.create("  Family ", "Home", snap, NOW, gen::next)
        assertEquals(7, made.baseRevision)
        assertEquals(snap.meta, made.meta)
        snap = snap.copy(records = made.records)
        // Exactly the desktop's catalog record (stripped name, no revision or starter flag).
        assertEquals(CollectionStates.wrapper(CollectionStates.catalog(family, "Family", "Home", NOW, NOW)), snap.records[CAT + family])
        expect(CollectionCatalog.Failure.DUPLICATE_NAME) { CollectionCatalog.create("FAMILY", snapshot = snap, now = NOW, newId = gen::next) }
        val (s2, street) = make(snap, "Straße", gen)
        snap = s2
        // Python casefold: "ß" folds to "ss".
        expect(CollectionCatalog.Failure.DUPLICATE_NAME) { CollectionCatalog.create("STRASSE", snapshot = snap, now = NOW, newId = gen::next) }
        expect(CollectionCatalog.Failure.EMPTY_NAME) { CollectionCatalog.create(" \t ", snapshot = snap, now = NOW, newId = gen::next) }
        expect(CollectionCatalog.Failure.LONG_NAME) { CollectionCatalog.create("x".repeat(101), snapshot = snap, now = NOW, newId = gen::next) }
        expect(CollectionCatalog.Failure.INVALID_TEXT) { CollectionCatalog.create("a\u0000b", snapshot = snap, now = NOW, newId = gen::next) }
        expect(CollectionCatalog.Failure.INVALID_ID) { CollectionCatalog.create("Fresh", snapshot = snap, now = NOW, newId = { "NOT-A-UUID" }) }
        expect(CollectionCatalog.Failure.LONG_DESCRIPTION) {
            CollectionCatalog.create("Notes", "d".repeat(501), snap, NOW, gen::next)
        }
        snap = make(snap, "x".repeat(100), gen).first
        assertEquals(family, CollectionCatalog.collections(snap).first().id)

        // Rename: the same name is no change; another's name (ignoring case) is refused; the time never goes back.
        assertNull(CollectionCatalog.rename(family, " Family", snapshot = snap, now = NOW + 5))
        expect(CollectionCatalog.Failure.DUPLICATE_NAME) { CollectionCatalog.rename(family, "strasse", snapshot = snap, now = NOW) }
        assertNotNull(CollectionCatalog.rename(street, "STRASSE", snapshot = snap, now = NOW), "its own name in other case")
        val renamed = assertNotNull(CollectionCatalog.rename(family, "Home", "Ours", snap, NOW - 100))
        snap = snap.copy(records = renamed.records)
        val row = CollectionCatalog.collections(snap).first { it.id == family }
        assertEquals(listOf("Home", "Ours"), listOf(row.name, row.description))
        assertEquals(NOW, row.updatedAt)
        expect(CollectionCatalog.Failure.NOT_FOUND) { CollectionCatalog.rename(UNKNOWN, "X", snapshot = snap, now = NOW) }
    }

    @Test fun the_501st_collection_is_refused() {
        val records = LinkedHashMap(base().records)
        val gen = Ids()
        for (i in 0 until CollectionCatalog.MAX_COLLECTIONS) {
            val id = gen.next()
            records[CAT + id] = CollectionCatalog.catalogWrapper(id, "C$i", "", 1, 1)
        }
        expect(CollectionCatalog.Failure.LIMIT) { CollectionCatalog.create("One more", snapshot = base().copy(records = records), now = NOW, newId = gen::next) }
        // Collections are free: no Pro check anywhere in the catalog.
    }

    @Test fun delete_keeps_the_items_and_clears_memberships_and_trash_rows() {
        var snap = base()
        val gen = Ids()
        val family: String
        val work: String
        make(snap, "Family", gen).let { snap = it.first; family = it.second }
        make(snap, "Work", gen).let { snap = it.first; work = it.second }
        snap = snap.copy(records = CollectionCatalog.setMemberships(NOTE, "note", listOf(family, work), snap)!!.records)
        fun row(title: String, ids: List<String>?): JsonValue {
            val r = linkedMapOf("id" to s(GONE), "kind" to s("note"), "title" to s(title))
            if (ids != null) r["collection_ids"] = JsonValue.Arr(ids.map { s(it) })
            return JsonValue.Obj(r)
        }
        val rows = listOf(row("Old", listOf(family)), row("Older", listOf(family, work)), row("Plain", null))

        val d = CollectionCatalog.delete(family, snap, rows, protected = emptySet())
        val after = snap.copy(records = d.change.records)
        assertNull(after.records[CAT + family])
        assertEquals(snap.records[NOTE], after.records[NOTE], "the item stays")
        assertEquals(listOf(work), CollectionCatalog.memberships(NOTE, after))
        val kept = assertNotNull(d.trash)
        assertNull(obj(kept[0])["collection_ids"])
        assertEquals(JsonValue.Arr(listOf(s(work))), obj(kept[1])["collection_ids"])
        assertEquals(rows[2], kept[2])

        // The last collection of an item: its membership record goes; no trash row changes.
        val last = CollectionCatalog.delete(work, after, listOf(rows[2]), protected = emptySet())
        assertNull(last.change.records[MEM + NOTE])
        assertNull(last.trash)
        assertNotNull(last.change.records[NOTE])
        expect(CollectionCatalog.Failure.NOT_FOUND) { CollectionCatalog.delete(family, after, emptyList(), emptySet()) }
    }

    @Test fun a_shared_collection_is_never_deleted_whichever_device_shares_it() {
        var snap = base()
        val gen = Ids()
        val own: String
        val linked: String
        make(snap, "Own share", gen).let { snap = it.first; own = it.second }
        make(snap, "Shared from my other device", gen).let { snap = it.first; linked = it.second }
        // This device's share record (the app passes its collections as `protected`).
        expect(CollectionCatalog.Failure.SHARED) { CollectionCatalog.delete(own, snap, emptyList(), setOf(own)) }
        // Another of this person's devices shares it: only its `csl:` link is here, whatever the role or mode.
        for ((role, mode) in listOf("owner" to "edit", "member" to "read", "member" to "edit")) {
            val withLink = snap.copy(records = snap.records + (LNK + linked to link(linked, mode, role)))
            expect(CollectionCatalog.Failure.SHARED) { CollectionCatalog.delete(linked, withLink, emptyList(), emptySet()) }
        }
        CollectionCatalog.delete(linked, snap, emptyList(), setOf(own))
    }

    @Test fun starters_are_added_once_by_name_and_only_on_request() {
        var snap = base()
        val gen = Ids()
        snap = make(snap, "work", gen).first
        val (change, made) = CollectionCatalog.starters(snap, NOW, gen::next)
        snap = snap.copy(records = assertNotNull(change).records)
        assertEquals(3, made.size)
        assertEquals(listOf("Emergency", "Personal", "Travel", "work"), CollectionCatalog.collections(snap).map { it.name })
        val again = CollectionCatalog.starters(snap, NOW, gen::next)
        assertNull(again.first)
        assertEquals(emptyList(), again.second)
        // Nothing seeds them on its own: an empty store has no collections.
        assertEquals(emptyList(), CollectionCatalog.collections(base()))
    }

    // ---- memberships ----

    @Test fun memberships_refuse_logins_documents_unknown_ids_a_21st_and_read_only_moves() {
        var snap = base()
        val gen = Ids()
        val ids = ArrayList<String>()
        for (i in 0 until 21) make(snap, "C$i", gen).let { snap = it.first; ids.add(it.second) }
        expect(CollectionCatalog.Failure.NOT_MEMBER) { CollectionCatalog.setMemberships(LOGIN, "web", listOf(ids[0]), snap) }
        expect(CollectionCatalog.Failure.NOT_MEMBER) { CollectionCatalog.setMemberships(DOCUMENT, "document", listOf(ids[0]), snap) }
        expect(CollectionCatalog.Failure.UNKNOWN_COLLECTION) { CollectionCatalog.setMemberships(NOTE, "note", listOf(UNKNOWN), snap) }
        expect(CollectionCatalog.Failure.TOO_MANY) { CollectionCatalog.setMemberships(NOTE, "note", ids, snap) }
        expect(CollectionCatalog.Failure.NOT_FOUND) { CollectionCatalog.setMemberships(GONE, "note", listOf(ids[0]), snap) }
        expect(CollectionCatalog.Failure.RESERVED) { CollectionCatalog.setMemberships(MEM + NOTE, "note", listOf(ids[0]), snap) }

        val twenty = ids.take(20)
        val change = assertNotNull(CollectionCatalog.setMemberships(NOTE, "note", twenty.reversed(), snap))
        assertEquals(membership(NOTE, twenty), change.records[MEM + NOTE])
        assertEquals(snap.records[NOTE], change.records[NOTE], "the item record keeps its v1 shape")
        snap = snap.copy(records = change.records)
        assertNull(CollectionCatalog.setMemberships(NOTE, "note", twenty, snap))
        assertEquals(listOf(NOTE), CollectionCatalog.items(ids[0], snap))
        assertEquals(emptyList(), CollectionCatalog.items(ids[20], snap))

        // Read-only (`ShareAccess.checkWritable` with the old and the new membership): never moved out of, nor into.
        val readOnly = setOf(ids[19], ids[20])
        assertFailsWith<ReadOnlyCollectionException> { CollectionCatalog.setMemberships(NOTE, "note", ids.take(19), snap, readOnly) }
        assertFailsWith<ReadOnlyCollectionException> { CollectionCatalog.setMemberships(NOTE2, "note", listOf(ids[20]), snap, readOnly) }
        // The same ids another device linked as read-only (`csl:` read/member) always count.
        snap = snap.copy(records = snap.records + (LNK + ids[20] to link(ids[20], "read", "member")) + (LNK + ids[18] to link(ids[18], "edit", "member")))
        assertEquals(setOf(ids[20]), CollectionCatalog.linkedReadOnlyIds(snap))
        assertFailsWith<ReadOnlyCollectionException> { CollectionCatalog.setMemberships(NOTE2, "note", listOf(ids[20]), snap) }

        // An old membership of a document (kept by a migration) can be left, never grown.
        snap = snap.copy(records = snap.records + (MEM + DOCUMENT to membership(DOCUMENT, listOf(ids[0], UNKNOWN))))
        expect(CollectionCatalog.Failure.NOT_MEMBER) {
            CollectionCatalog.setMemberships(DOCUMENT, "document", listOf(ids[0], ids[1], UNKNOWN), snap)
        }
        val left = assertNotNull(CollectionCatalog.setMemberships(DOCUMENT, "document", listOf(UNKNOWN), snap))
        assertEquals(listOf(UNKNOWN), CollectionCatalog.memberships(DOCUMENT, StoreSnapshot(left.records)), "an id from another device is kept")
        val none = assertNotNull(CollectionCatalog.setMemberships(DOCUMENT, "document", emptyList(), snap))
        assertNull(none.records[MEM + DOCUMENT])
    }

    @Test fun trash_keeps_the_memberships_and_a_restore_brings_back_the_ones_that_still_exist() {
        var snap = base()
        val gen = Ids()
        val family: String
        val work: String
        make(snap, "Family", gen).let { snap = it.first; family = it.second }
        make(snap, "Work", gen).let { snap = it.first; work = it.second }
        snap = snap.copy(records = CollectionCatalog.setMemberships(NOTE, "note", listOf(family, work), snap)!!.records)
        val record = obj(snap.records[NOTE])["record"]!!
        val trashed = CollectionCatalog.trashRecord(record, NOTE, snap)
        assertEquals(JsonValue.Arr(listOf(family, work).sorted().map { s(it) }), obj(trashed)["collection_ids"])
        var gone = snap.copy(records = CollectionCatalog.withoutMembership(NOTE, snap.records - NOTE))
        assertNull(gone.records[MEM + NOTE])
        // Work is deleted meanwhile: the restore brings back Family only, and the stored record has no collection_ids.
        gone = gone.copy(records = CollectionCatalog.delete(work, gone, emptyList(), emptySet()).change.records)
        val (back, records) = CollectionCatalog.restored(obj(trashed), NOTE, gone.records)
        assertEquals(record, JsonValue.Obj(back))
        assertEquals(listOf(family), CollectionCatalog.memberships(NOTE, StoreSnapshot(records)))
        // A trash record without collections changes nothing.
        assertEquals(record, CollectionCatalog.trashRecord(record, NOTE2, snap))
    }

    @Test fun a_full_restore_keeps_the_catalog_and_the_memberships_of_restored_items() {
        var current = base()
        val gen = Ids()
        val family: String
        make(current, "Family", gen).let { current = it.first; family = it.second }
        current = current.copy(records = CollectionCatalog.setMemberships(NOTE, "note", listOf(family), current)!!.records)
        current = current.copy(records = CollectionCatalog.setMemberships(NOTE2, "note", listOf(family), current)!!.records)
        // The backup brings back the first note only, plus a planted record under a reserved id.
        val restored = mapOf(NOTE to item(NOTE), "col:planted" to item(NOTE2))
        val out = CollectionCatalog.carriedOver(current.records, restored)
        assertEquals(setOf(NOTE, CAT + family, MEM + NOTE), out.keys)
        // A safety copy (a whole store) keeps its own states over the current ones.
        val copy = current.records + (CAT + family to CollectionCatalog.catalogWrapper(family, "Before", "", 1, 1))
        // A collection made after the copy does not come back with it; a share link held now does.
        var now = make(current, "Later", gen).first
        now = now.copy(records = now.records + (LNK + family to link(family, "edit", "owner")))
        val undone = CollectionCatalog.carriedOver(now.records, copy)
        assertEquals(listOf("Before"), CollectionCatalog.collections(StoreSnapshot(undone)).map { it.name })
        assertNotNull(undone[LNK + family])
    }

    // ---- migration of old local collections ----

    @Test fun migrating_old_local_collections_gives_the_desktops_states() {
        val doc = Vectors.json(Vectors.shareCollections("states.json")).obj().fields
        val valid = arr(doc["valid"]).map { obj(it) }.associateBy { str(it["id"])!! }
        val legacy = listOf(
            CollectionCatalog.LegacyCollection(FAMILY, "Family", "Shared at home", 1_799_999_100, 1_799_999_200),
            CollectionCatalog.LegacyCollection(WORK, "Work", "", 1_799_999_000, 1_799_999_000, starter = true),
        )
        val snap = StoreSnapshot(mapOf(NOTE to item(NOTE)), revision = 3)
        val m = assertNotNull(CollectionCatalog.migrate(legacy, mapOf(NOTE to listOf(WORK, FAMILY)), emptyList(), emptyList(), snap))
        val change = assertNotNull(m.change)
        assertEquals(3, change.baseRevision)
        for (id in listOf(CAT + FAMILY, MEM + NOTE)) {
            val v = assertNotNull(valid[id], id)
            assertContentEquals(canonical(v["wrapper"]), canonical(change.records[id]), id)
            assertEquals(str(v["digest"]), SyncMeta.digest(change.records.getValue(id)), id)
        }
        // The other row as Python's `local_view` builds it: never `revision` or `starter`.
        assertEquals(CollectionStates.wrapper(CollectionStates.catalog(WORK, "Work", "", 1_799_999_000, 1_799_999_000)), change.records[CAT + WORK])
        for ((id, w) in change.records) {
            if (!CollectionStates.isStateId(id)) continue
            CollectionStates.unwrap(ItemState(id, mapOf(MergeVectors.A to 1L), false, null, w), isCopy = false)
        }
        assertEquals(snap.records[NOTE], change.records[NOTE])
        assertEquals(listOf(WORK), m.starterIds)
        assertEquals(listOf(2, 0, 1, 0, 0), listOf(m.collections, m.renamed, m.memberships, m.trashMemberships, m.dropped))
        // Run again on the migrated store: nothing more to change.
        val again = assertNotNull(CollectionCatalog.migrate(legacy, mapOf(NOTE to listOf(WORK, FAMILY)), emptyList(), emptyList(), snap.copy(records = change.records)))
        assertNull(again.change)
        assertNull(CollectionCatalog.migrate(emptyList(), emptyMap(), emptyList(), emptyList(), snap))
    }

    @Test fun migration_moves_deleted_items_into_their_trash_rows_renames_clashes_and_drops_only_what_cannot_exist() {
        val other = "77777777-7777-4777-8777-777777777777"
        val store = base().let { it.copy(records = it.records + (CAT + other to CollectionCatalog.catalogWrapper(other, "family", "", 1, 1))) }
        val trashRow = JsonValue.Obj(mapOf("id" to s(GONE), "kind" to s("note"), "title" to s("Old")))
        val goneLogin = "88888888-8888-4888-8888-888888888888"
        val loginRow = JsonValue.Obj(mapOf("id" to s(goneLogin), "kind" to s("web"), "label" to s("Old login")))
        val blank = "99999999-9999-4999-8999-999999999999"
        val legacy = listOf(
            CollectionCatalog.LegacyCollection(FAMILY, "Family", createdAt = 1, updatedAt = 2),
            // Checked non-empty before stripping by an old app: it gets a plain name instead of stopping the migration.
            CollectionCatalog.LegacyCollection(blank, "　", createdAt = 1, updatedAt = 2),
        )
        val memberships = mapOf(
            NOTE to listOf(FAMILY), GONE to listOf(FAMILY), LOGIN to listOf(FAMILY), UNKNOWN to listOf(FAMILY),
            DOCUMENT to listOf(FAMILY), goneLogin to listOf(FAMILY),
        )
        val m = assertNotNull(CollectionCatalog.migrate(legacy, memberships, listOf(trashRow, loginRow), emptyList(), store))
        val records = assertNotNull(m.change).records
        assertEquals(listOf("Collection", "family", "Family (2)"), CollectionCatalog.collections(StoreSnapshot(records)).map { it.name })
        assertEquals(2, m.renamed)
        // The note and the document (lossless: an old membership is kept, never grown) go to the store.
        assertEquals(listOf(FAMILY), CollectionCatalog.memberships(NOTE, StoreSnapshot(records)))
        assertEquals(listOf(FAMILY), CollectionCatalog.memberships(DOCUMENT, StoreSnapshot(records)))
        // The deleted note keeps its collection in its Recently deleted record.
        assertEquals(JsonValue.Arr(listOf(s(FAMILY))), obj(m.trash[0])["collection_ids"])
        // A login never had collections and an item that is nowhere has nothing to keep.
        assertNull(records[MEM + LOGIN])
        assertNull(records[MEM + UNKNOWN])
        // A deleted login's row never gets collections, and a restore of such a row makes no membership.
        assertNull(obj(m.trash[1])["collection_ids"])
        val (loginBack, loginRecords) = CollectionCatalog.restored(
            mapOf("id" to s(goneLogin), "kind" to s("web"), "collection_ids" to JsonValue.Arr(listOf(s(FAMILY)))), goneLogin, records,
        )
        assertNull(loginRecords[MEM + goneLogin])
        assertNull(loginBack["collection_ids"])
        assertEquals(listOf(2, 1, 3), listOf(m.memberships, m.trashMemberships, m.dropped))
    }

    // ---- readers in lgk-core ----

    /**
     * A note with a code, a login, the three collection states, and a planted login-shaped record under a reserved id
     * (only the shared filter keeps it out).
     */
    private fun planted(): StoreSnapshot {
        val totp = JsonValue.Obj(mapOf("secret" to s("JBSWY3DPEHPK3PXP"), "algorithm" to s("SHA1"), "digits" to JsonValue.Int(6), "period" to JsonValue.Int(30)))
        val records = LinkedHashMap(base().records)
        records[NOTE] = item(NOTE, extra = mapOf("totp" to totp))
        records[CAT + FAMILY] = CollectionCatalog.catalogWrapper(FAMILY, "Family", "", 1, 1)
        records[MEM + NOTE] = membership(NOTE, listOf(FAMILY))
        records[LNK + FAMILY] = link(FAMILY, "read", "member")
        records["col:planted"] = Wrapper.make(
            Namespace.ENTRY,
            JsonValue.Obj(
                mapOf(
                    "id" to s("col:planted"), "kind" to s("web"), "label" to s("Planted"), "totp" to totp,
                    "scope" to JsonValue.Obj(mapOf("origin" to s("https://example.com"))), "updated_at" to JsonValue.Int(1),
                ),
            ),
        )
        return base().copy(records = records)
    }

    @Test fun item_records_leave_every_collection_state_out() {
        val snap = planted()
        assertEquals(setOf(NOTE, NOTE2, LOGIN, DOCUMENT), snap.itemRecords.keys)
        assertTrue(CollectionStates.isReserved("x", link(FAMILY, "read", "member")), "a collection wrapper anywhere")
    }

    @Test fun the_sync_view_never_publishes_or_tombstones_collection_states() {
        val snap = planted()
        val published = SyncMeta.live(snap.records.getValue(CAT + FAMILY), mapOf(MergeVectors.B to 2L))
        val meta = mapOf(CAT + FAMILY to published, MEM + GONE to published) // its record is gone: still no tombstone
        val view = SyncMeta.localView(snap.records, meta, MergeVectors.A, NOW)
        assertEquals(setOf(NOTE, NOTE2, LOGIN, DOCUMENT), view.states.keys)
        assertEquals(published, view.meta[CAT + FAMILY])
        assertEquals(published, view.meta[MEM + GONE])
        assertNull(view.meta["col:planted"])
    }

    @Test fun a_sync_run_strips_the_peers_collection_states() {
        val snap = planted()
        val peer = PeerView(
            MergeVectors.B,
            listOf(
                ItemState(CAT + FAMILY, mapOf(MergeVectors.B to 5L), true, NOW - 10, null),
                ItemState(MEM + NOTE2, mapOf(MergeVectors.B to 5L), false, null, membership(NOTE2, listOf(FAMILY))),
            ),
        )
        val report = SyncRunner.run(snap, listOf(peer), MergeVectors.A, NOW)
        assertEquals(emptyList(), report.issues)
        val records = assertNotNull(report.records)
        assertEquals(snap.records[CAT + FAMILY], records[CAT + FAMILY])
        assertNull(records[MEM + NOTE2])
        assertTrue((report.ownStates ?: emptyList()).none { CollectionStates.isStateId(it.itemId) })
    }

    @Test fun cxf_export_skips_collection_states() {
        val snap = planted()
        val plan = CxfExport.plan(snap, listOf("col:planted", CAT + FAMILY))
        assertEquals(0, plan.count)
    }
}
