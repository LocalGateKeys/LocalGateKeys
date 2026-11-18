package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.group.ViewSignature
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.keyring.KeyringException
import app.localgatekeys.core.keyring.KeyringRotate
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.records.ConflictSuffix
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MemoryFolder
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * An item store with the host's Recently deleted: every live item a commit takes out is copied there with its
 * collections first (as the app's sync commit does), and the share groups are kept unless a commit replaces them (as
 * `LocalStore` does).
 */
class TrashingStore : ItemStore {
    private var current = StoreSnapshot()
    private val rows = ArrayList<JsonValue>()

    @Synchronized override fun load(): StoreSnapshot = current

    @Synchronized override fun commit(change: StoreChange) {
        if (change.baseRevision != current.revision) throw FolderSyncException("vault-changed")
        for ((id, w) in current.itemRecords.entries.sortedBy { it.key }) {
            if (change.records[id] != null) continue
            val record = (w as? JsonValue.Obj)?.fields?.get("record") ?: continue
            rows.add(CollectionCatalog.trashRecord(record, id, current))
        }
        val shares = when (val s = change.shares) {
            StoreChange.Shares.Keep -> current.shares
            is StoreChange.Shares.Replace -> s.value
        }
        current = StoreSnapshot(change.records, change.meta, change.sync, current.revision + 1, shares)
    }

    val trash: List<JsonValue> @Synchronized get() = rows.toList()

    val trashIds: Set<String>
        get() = trash.mapNotNull { ((it as? JsonValue.Obj)?.fields?.get("id") as? JsonValue.Str)?.v }.toSet()
}

/**
 * Shared collections in lgk-core (sub-plan 07 Task 5k): [ShareGroups], [ShareItemStore] and `FolderSync(share =)`.
 * Ports of LGKCore `ShareRunnerTests` (Task 5e), themselves ports of the desktop's `test_share_group.py`,
 * `test_vault_bridge_shared.py` and `test_folder_sync_shared.py`, plus the desktop's own share vectors run end to end.
 */
class ShareRunnerTest {
    companion object {
        const val PW = "correct horse battery staple 7!"
        const val PW2 = "another very long passphrase 42?"
        const val T0: Long = 1_800_000_000
        val random = SystemRandomSource()
        val yes: (String) -> Boolean = { true }

        /** A cheap stand-in for Argon2id (tests only): HKDF of the password with the keyring's salt. */
        internal val cheap = KeyringRotate.KeyDerivation { pw, salt ->
            CryptoBox.hkdf(pw.toByteArray(Charsets.UTF_8), salt, "share-runner-test".toByteArray(Charsets.UTF_8), 32)
        }

        const val ITEM_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
        const val ITEM_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2"
        const val ITEM_P = "cccccccc-cccc-4ccc-8ccc-ccccccccccc3"
        const val ITEM_W = "dddddddd-dddd-4ddd-8ddd-ddddddddddd4"
        const val ITEM_M = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee5"
    }

    /** One device: its own item store and Recently deleted. */
    class Device(val install: String) {
        val store = TrashingStore()
        var isPro = true
    }

    /** An owner and a member, each with its own vault, syncing one share group through [folder] (desktop `Share`). */
    class Share(mode: String = "edit", shareFormat: Long = ShareKeyring.SHARE_FORMAT) {
        companion object {
            /** A share v1 group (keyring format 2, views sealed with G), as apps before share v2 made them. */
            fun legacy(): Share = Share(shareFormat = ShareKeyring.LEGACY_SHARE_FORMAT)
        }

        val folder = MemoryFolder()
        val owner = Device("install-owner")
        val member = Device("install-member")
        var clock: Long = T0
        val cid: String
        val gid: String

        init {
            val (change, id) = CollectionCatalog.create("Family", snapshot = owner.store.load(), now = T0)
            owner.store.commit(change)
            val group = ShareGroups.create(
                owner.store, id, PW, "Owner PC", mode, owner.install, true, random, FixedClock(T0), yes, null, cheap, shareFormat,
            )
            cid = id
            gid = group.groupId
        }

        fun tick(): FixedClock {
            clock += 1
            return FixedClock(clock)
        }

        fun fs(d: Device): FolderSync =
            FolderSync(folder, d.install, share = FolderSync.Share(gid, d.isPro, ShareTrash.of(d.store.trash)))

        fun run(d: Device): RunReport = fs(d).runOnce(d.store, random, tick())

        fun join(d: Device, name: String): ShareGroups.Group {
            val raw = assertNotNull(folder.files[FolderLayout.KEYRING_PATH])
            return ShareGroups.join(d.store, raw, PW, name, d.install, d.isPro, random, tick(), null, cheap)
        }

        fun pendingIds(): List<String> = ShareGroups.pendingMembers(owner.store.load(), gid).map { it.deviceId }

        fun pendingNames(): List<String> = ShareGroups.pendingMembers(owner.store.load(), gid).map { it.name ?: "" }.sorted()

        /** The member joins, the owner adopts and approves it, and the member adopts the approval (desktop `join`). */
        fun connect() {
            run(owner)
            join(member, "Member PC")
            run(member)
            run(owner)
            ShareGroups.approve(owner.store, gid, pendingIds())
            run(owner)
            run(member)
        }

        fun record(d: Device): ShareRecord = assertNotNull(ShareGroups.records(d.store.load())[gid])

        fun deviceId(d: Device): String = record(d).state.deviceId
    }

    // ---- helpers ----

    private fun s(v: String) = JsonValue.Str(v)

    private fun noteRecord(id: String, title: String, body: String, at: Long, favorite: Boolean = false, tags: List<String> = emptyList()): JsonValue =
        JsonValue.Obj(
            mapOf(
                "id" to s(id), "kind" to s("note"), "title" to s(title), "created_at" to JsonValue.Int(T0),
                "updated_at" to JsonValue.Int(at), "favorite" to JsonValue.Bool(favorite), "tags" to JsonValue.Arr(tags.map { s(it) }),
                "payload" to JsonValue.Obj(mapOf("body" to s(body), "fields" to JsonValue.Arr(emptyList()), "template_id" to JsonValue.Null)),
            ),
        )

    /** Stores (or replaces) a note in [d]'s vault with exactly [collections]. */
    private fun put(
        d: Device, id: String, title: String, body: String, collections: List<String>, at: Long = T0,
        favorite: Boolean = false, tags: List<String> = emptyList(),
    ) {
        val snap = d.store.load()
        val records = LinkedHashMap(snap.records)
        records[id] = Wrapper.make(Namespace.ITEM, noteRecord(id, title, body, at, favorite, tags))
        CollectionCatalog.setOrRemove(records, CollectionStates.MEMBERSHIP_PREFIX + id, CollectionCatalog.membershipWrapper(id, collections))
        d.store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
    }

    /** Takes [id] out of [d]'s vault (a local delete: the store moves it to Recently deleted). */
    private fun delete(d: Device, id: String) {
        val snap = d.store.load()
        val records = CollectionCatalog.withoutMembership(id, snap.records).filterKeys { it != id }
        d.store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
    }

    private fun record(d: Device, id: String): Map<String, JsonValue>? =
        ((d.store.load().records[id] as? JsonValue.Obj)?.fields?.get("record") as? JsonValue.Obj)?.fields

    private fun body(d: Device, id: String): String? =
        (((record(d, id) ?: return null)["payload"] as? JsonValue.Obj)?.fields?.get("body") as? JsonValue.Str)?.v

    private fun items(d: Device): Set<String> = d.store.load().itemRecords.keys

    private fun collection(d: Device, name: String): String {
        val (change, id) = CollectionCatalog.create(name, snapshot = d.store.load(), now = T0)
        d.store.commit(change)
        return id
    }

    private fun setMemberships(d: Device, id: String, ids: List<String>) {
        CollectionCatalog.setMemberships(id, "note", ids, d.store.load())?.let { d.store.commit(it) }
    }

    private fun kinds(r: RunReport): List<String> = r.issues.map { it.kind }

    private fun reason(f: () -> Any?): String? = try {
        f()
        null
    } catch (e: ShareGroupException) {
        e.reason
    } catch (e: KeyringException) {
        e.reason
    } catch (e: RemovalException) {
        e.reason
    } catch (e: CollectionCatalogException) {
        e.failure.code
    }

    private fun sorted(vararg ids: String): List<String> = CollectionCatalog.sortedIds(ids.toList())

    private fun canonical(v: JsonValue): ByteArray = CanonicalJson.encode(v, Dialect.UTF8)

    // ---- what leaves the device ----

    @Test fun the_member_receives_only_the_shared_item_and_tags_stay_personal() {
        val s = Share()
        val work = collection(s.owner, "Work")
        put(s.owner, ITEM_A, "A", "shared text", listOf(s.cid, work), favorite = true, tags = listOf("home"))
        put(s.owner, ITEM_P, "Personal", "my diary", emptyList())
        put(s.owner, ITEM_W, "Work item", "work", listOf(work))
        put(s.member, ITEM_M, "Member own", "member diary", emptyList())
        s.connect()
        assertEquals(setOf(ITEM_A, ITEM_M), items(s.member))
        val got = assertNotNull(record(s.member, ITEM_A))
        assertEquals("shared text", body(s.member, ITEM_A))
        assertEquals(JsonValue.Arr(emptyList()), got["tags"])
        assertEquals(JsonValue.Bool(false), got["favorite"])
        assertNull(got["collection_ids"], "the store keeps the v1 item shape")
        val memberSnap = s.member.store.load()
        assertEquals(listOf(s.cid), CollectionCatalog.memberships(ITEM_A, memberSnap))
        assertEquals(listOf(s.cid), CollectionCatalog.collections(memberSnap).map { it.id }, "the owner's other collections stay private")
        assertEquals(listOf("Family"), CollectionCatalog.collections(memberSnap).map { it.name })
        // The published share record carries only the collection: no tags, favourite or other collection.
        val published = assertNotNull(s.folder.files[FolderLayout.deviceFile(s.deviceId(s.owner))!!])
        val st = s.record(s.owner).state
        val view = ViewFile.decode(published, assertNotNull(ShareGroups.viewKey(s.record(s.owner))), st.deviceId)
        assertEquals(listOf(ITEM_A), view.second.map { it.itemId })
        val r = assertNotNull(((view.second.first().item as JsonValue.Obj).fields["record"] as? JsonValue.Obj)?.fields)
        assertNull(r["tags"])
        assertNull(r["favorite"])
        assertEquals(JsonValue.Arr(listOf(s(s.cid))), r["collection_ids"])
        // Nothing of the member's own vault went the other way, and the owner's own fields are untouched.
        s.run(s.member)
        s.run(s.owner)
        assertNull(record(s.owner, ITEM_M))
        assertEquals(JsonValue.Arr(listOf(s("home"))), record(s.owner, ITEM_A)?.get("tags"))
        // A tag or favourite change is not an edit of the share.
        put(s.member, ITEM_A, "A", "shared text", listOf(s.cid), favorite = true, tags = listOf("member-tag"))
        s.run(s.member)
        assertEquals(0, s.run(s.owner).applied)
    }

    @Test fun a_member_edit_reaches_the_owner_in_edit_mode() {
        val s = Share()
        val home = collection(s.owner, "Home")
        put(s.owner, ITEM_A, "A", "v1", listOf(s.cid, home))
        s.connect()
        put(s.member, ITEM_A, "A", "v2 by member", listOf(s.cid), at = T0 + 100)
        s.run(s.member)
        val report = s.run(s.owner)
        assertEquals(1, report.applied)
        assertEquals("v2 by member", body(s.owner, ITEM_A))
        assertEquals(sorted(s.cid, home), CollectionCatalog.memberships(ITEM_A, s.owner.store.load()), "the owner keeps its own collections")
    }

    @Test fun both_edit_offline_and_both_versions_survive_on_both() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "v1", listOf(s.cid))
        s.connect()
        put(s.owner, ITEM_A, "A", "owner offline", listOf(s.cid), at = T0 + 50)
        put(s.member, ITEM_A, "A", "member offline", listOf(s.cid), at = T0 + 60)
        s.run(s.member)
        s.run(s.owner)
        s.run(s.member)
        s.run(s.owner)
        for (d in listOf(s.owner, s.member)) {
            val live = CollectionCatalog.items(s.cid, d.store.load())
            assertEquals(2, live.size, "the conflict copy stays in the share")
            assertEquals(listOf("member offline", "owner offline"), live.mapNotNull { body(d, it) }.sorted())
            val copy = live.first { it != ITEM_A }
            val title = assertNotNull((record(d, copy)?.get("title") as? JsonValue.Str)?.v)
            assertTrue(title.endsWith(ConflictSuffix.SUFFIX))
        }
    }

    @Test fun the_owner_untags_an_item_the_member_loses_it_the_owner_keeps_it() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "was shared", listOf(s.cid))
        s.connect()
        assertEquals("was shared", body(s.member, ITEM_A))
        val home = collection(s.member, "Home")
        put(s.member, ITEM_A, "A", "was shared", listOf(s.cid, home), favorite = true, tags = listOf("mine"))
        s.run(s.member)
        setMemberships(s.owner, ITEM_A, emptyList())
        s.run(s.owner)
        val report = s.run(s.member)
        assertEquals(1, report.deleted)
        assertNull(record(s.member, ITEM_A))
        assertTrue(ITEM_A in s.member.store.trashIds)
        assertEquals("was shared", body(s.owner, ITEM_A))
        assertFalse(ITEM_A in s.owner.store.trashIds)
        // Tagging it again shares it again (back from the member's Recently deleted).
        setMemberships(s.owner, ITEM_A, listOf(s.cid))
        s.run(s.owner)
        s.run(s.member)
        assertEquals("was shared", body(s.member, ITEM_A))
        assertEquals(sorted(s.cid, home), CollectionCatalog.memberships(ITEM_A, s.member.store.load()), "its other collections come back with it")
        assertEquals(JsonValue.Arr(listOf(s("mine"))), record(s.member, ITEM_A)?.get("tags"), "this device's own tags")
        assertEquals(JsonValue.Bool(true), record(s.member, ITEM_A)?.get("favorite"))
    }

    @Test fun an_owner_untag_while_a_member_edits_is_skipped_quietly_on_the_owner() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "v1", listOf(s.cid))
        s.connect()
        setMemberships(s.owner, ITEM_A, emptyList())
        s.run(s.owner)
        put(s.member, ITEM_A, "A", "member edit", listOf(s.cid), at = T0 + 100)
        s.run(s.member)
        repeat(2) {
            val report = s.run(s.owner)
            assertEquals(0, report.applied)
            assertFalse("bad-peer-record" in kinds(report), "not a bad peer record")
            assertEquals("v1", body(s.owner, ITEM_A))
            assertEquals(emptyList(), CollectionCatalog.memberships(ITEM_A, s.owner.store.load()))
            assertEquals(true, s.record(s.owner).meta[ITEM_A]?.deleted, "the owner keeps publishing the tombstone")
        }
    }

    @Test fun an_incoming_item_never_overwrites_or_deletes_a_personal_item() {
        val s = Share()
        s.connect()
        put(s.member, ITEM_P, "Mine", "member diary", emptyList())
        put(s.member, ITEM_B, "Trashed mine", "old diary", emptyList())
        delete(s.member, ITEM_B)
        assertTrue(ITEM_B in s.member.store.trashIds)
        // The owner publishes items under those ids (a forged or a colliding id).
        put(s.owner, ITEM_P, "X", "overwritten", listOf(s.cid))
        put(s.owner, ITEM_B, "Y", "restored", listOf(s.cid))
        s.run(s.owner)
        val report = s.run(s.member)
        val refused = report.issues.filter { it.kind == "bad-peer-record" }.map { it.detail.substringAfterLast(':') }
        assertEquals(setOf(ITEM_P, ITEM_B), refused.toSet())
        assertEquals("member diary", body(s.member, ITEM_P))
        assertNull(record(s.member, ITEM_B))
        // A tombstone for a personal item is recorded in the share only.
        delete(s.owner, ITEM_P)
        s.run(s.owner)
        val after = s.run(s.member)
        assertEquals(0, after.deleted)
        assertEquals("member diary", body(s.member, ITEM_P))
        assertFalse(ITEM_P in s.member.store.trashIds)
    }

    // ---- read-only ----

    @Test fun a_read_only_member_never_publishes_a_local_change_and_the_owner_ignores_member_views() {
        val s = Share(mode = "read")
        put(s.owner, ITEM_A, "A", "owner text", listOf(s.cid))
        s.connect()
        assertEquals("owner text", body(s.member, ITEM_A))
        val memberSnap = s.member.store.load()
        val readOnly = ShareGroups.readOnlyCollectionIds(memberSnap)
        assertEquals(setOf(s.cid), readOnly)
        assertEquals(emptySet(), ShareGroups.readOnlyCollectionIds(s.owner.store.load()))
        // Refused up front: an edit, a move out and a move in.
        assertFailsWith<ReadOnlyCollectionException> {
            ShareAccess.checkWritable(readOnly, JsonValue.Obj(mapOf("collection_ids" to JsonValue.Arr(listOf(s(s.cid))))))
        }
        assertFailsWith<ReadOnlyCollectionException> { CollectionCatalog.setMemberships(ITEM_A, "note", emptyList(), memberSnap, readOnly) }
        // Changes that bypass those checks (a bug, a damaged store): an edit and a new tagged item.
        put(s.member, ITEM_A, "A", "member tampered", listOf(s.cid), at = T0 + 100)
        put(s.member, ITEM_B, "Sneaky", "x", listOf(s.cid), at = T0 + 100)
        val report = s.run(s.member)
        assertFalse((report.ownStates ?: emptyList()).any { it.itemId == ITEM_B }, "a new item is never published")
        assertEquals("owner text", body(s.member, ITEM_A), "the owner's version returns")
        // A member view that claims an edit (signed with the member's own key, sealed with the content key it holds) is
        // ignored by the owner.
        val st = s.record(s.member).state
        val gk = assertNotNull(ShareGroups.viewKey(s.record(s.member)))
        val forged = LinkedHashMap((noteRecord(ITEM_A, "A", "forged", T0 + 500) as JsonValue.Obj).fields)
        forged.remove("tags")
        forged.remove("favorite")
        forged["collection_ids"] = JsonValue.Arr(listOf(s(s.cid)))
        val ownerId = s.deviceId(s.owner)
        val state = ItemState(ITEM_A, mapOf(st.deviceId to 99L, ownerId to 99L), false, null, Wrapper.make(Namespace.ITEM, JsonValue.Obj(forged)))
        val raw = ViewFile.encode(gk, st.deviceId, 1000, listOf(state), FixedClock(T0 + 500), random)
        s.folder.files[FolderLayout.deviceFile(st.deviceId)!!] = raw
        s.folder.files[FolderLayout.signatureFile(st.deviceId)!!] = ViewSignature.sign(raw, ViewFile.decodeHeader(raw), st.identity)
        s.run(s.owner)
        assertEquals("owner text", body(s.owner, ITEM_A))
        // The owner edits freely and the edit flows; a delete moves it to the member's Recently deleted.
        put(s.owner, ITEM_A, "A", "owner v2", listOf(s.cid), at = T0 + 600)
        s.run(s.owner)
        s.run(s.member)
        assertEquals("owner v2", body(s.member, ITEM_A))
        delete(s.owner, ITEM_A)
        s.run(s.owner)
        s.run(s.member)
        assertTrue(ITEM_A in s.member.store.trashIds)
    }

    // ---- members ----

    @Test fun approve_accepts_only_pending_ids_and_only_on_the_owner() {
        val s = Share()
        s.run(s.owner)
        s.join(s.member, "Member PC")
        s.run(s.member)
        s.run(s.owner)
        val memberId = s.deviceId(s.member)
        val ownerId = s.deviceId(s.owner)
        assertEquals(listOf("Member PC"), s.pendingNames())
        val refused = listOf(emptyList(), listOf(ownerId), listOf("11111111-1111-4111-8111-111111111111"), listOf(memberId, "x-unknown"))
        for (bad in refused) {
            assertEquals("not-pending", reason { ShareGroups.approve(s.owner.store, s.gid, bad) }, bad.toString())
        }
        assertEquals("not-owner", reason { ShareGroups.approve(s.member.store, s.gid, listOf(memberId)) })
        val approved = ShareGroups.approve(s.owner.store, s.gid, listOf(memberId))
        assertEquals(listOf(memberId), approved.map { it.deviceId })
        assertEquals("Member PC", approved.first().name)
        assertTrue(approved.first().approved)
        assertEquals(emptyList(), s.pendingNames())
    }

    @Test fun a_join_racing_the_owners_approval_is_merged_not_frozen() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "shared", listOf(s.cid))
        val second = Device("install-j2")
        s.run(s.owner)
        s.join(s.member, "J1")
        s.run(s.member)
        s.run(s.owner) // adopts J1's join
        s.join(second, "J2") // J2 joins from the folder before the owner's approval is written
        s.run(second)
        ShareGroups.approve(s.owner.store, s.gid, listOf(s.deviceId(s.member)))
        val report = s.run(s.owner)
        assertTrue("keyring-merged" in kinds(report), kinds(report).toString())
        assertFalse("tampered" in kinds(report))
        assertEquals(listOf("J2"), s.pendingNames(), "the new joiner stays pending")
        for (d in listOf(s.member, second)) assertFalse("tampered" in kinds(s.run(d)))
        assertFalse("tampered" in kinds(s.run(s.owner)))
        assertEquals("shared", body(s.member, ITEM_A))
        // J2 receives the share once the owner approves it too.
        ShareGroups.approve(s.owner.store, s.gid, listOf(s.deviceId(second)))
        s.run(s.owner)
        s.run(second)
        assertEquals("shared", body(second, ITEM_A))
    }

    @Test fun two_people_joining_at_once_the_superseded_one_joins_again() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "shared", listOf(s.cid))
        val second = Device("install-j2")
        s.run(s.owner)
        s.join(s.member, "J1")
        s.join(second, "J2") // both read the same keyring
        s.run(s.member)
        val report = s.run(second)
        assertTrue("superseded" in kinds(report), kinds(report).toString())
        assertFalse("tampered" in kinds(report))
        assertFalse("tampered" in kinds(s.run(s.owner)))
        assertEquals(listOf("J1"), s.pendingNames())
        // Join again: the same group and collection, a new place in the folder keyring.
        val raw = assertNotNull(s.folder.files[FolderLayout.KEYRING_PATH])
        ShareGroups.rejoin(second.store, s.gid, raw, PW, "J2", second.install, true, random, s.tick(), cheap)
        assertEquals(listOf(s.gid), ShareGroups.list(second.store.load()).map { it.groupId })
        assertEquals(1, CollectionCatalog.collections(second.store.load()).size)
        val again = kinds(s.run(second))
        assertFalse("superseded" in again || "tampered" in again, again.toString())
        s.run(s.owner)
        assertEquals(listOf("J1", "J2"), s.pendingNames())
        ShareGroups.approve(s.owner.store, s.gid, s.pendingIds())
        s.run(s.owner)
        s.run(second)
        assertEquals("shared", body(second, ITEM_A))
    }

    @Test fun forged_member_changes_are_refused_and_the_trusted_keyring_is_written_back() {
        val s = Share()
        s.run(s.owner)
        val creation = assertNotNull(s.folder.files[FolderLayout.KEYRING_PATH]) // owner only, owner-signed
        s.connect()
        val trusted = assertNotNull(s.record(s.owner).state.keyring)
        // A member puts back an older owner-signed keyring of the same epoch: it drops an approved member.
        assertEquals("tampered", reason { ShareGroups.adopt(s.member.store, s.gid, creation) })
        s.folder.files[FolderLayout.KEYRING_PATH] = creation
        val report = s.run(s.owner)
        assertTrue("keyring-restored" in kinds(report), kinds(report).toString())
        assertContentEquals(trusted, s.folder.files[FolderLayout.KEYRING_PATH])
        assertEquals(2, s.record(s.owner).state.members.size, "nobody was dropped")
        // A member never writes over another group's keyring; the owner writes its own back (final review finding 1).
        val other = Share()
        other.run(other.owner)
        val otherRing = assertNotNull(other.folder.files[FolderLayout.KEYRING_PATH])
        s.folder.files[FolderLayout.KEYRING_PATH] = otherRing
        assertEquals(listOf("folder-has-other-group"), kinds(s.run(s.member)))
        assertContentEquals(otherRing, s.folder.files[FolderLayout.KEYRING_PATH])
        // Said apart from a plain repair (final review A1), so two owners in one folder show up.
        assertTrue("other-group-replaced" in kinds(s.run(s.owner)))
        assertContentEquals(trusted, s.folder.files[FolderLayout.KEYRING_PATH])
        assertEquals(emptyList(), kinds(s.run(s.member)))
    }

    // ---- final fix wave A: finding 1 (anyone with write access to the folder froze the share) ----

    /** One byte of `password_wrap.ct` flipped (no group key needed: the MAC then fails); re-MACed under [gk] if given. */
    private fun flippedPasswordWrap(raw: ByteArray, gk: GroupKey? = null): ByteArray {
        val ring = LinkedHashMap(obj(CanonicalJson.parse(raw)))
        val wrap = LinkedHashMap(obj(ring["password_wrap"]))
        val ct = Base64Std.decodeStrict(assertNotNull(str(wrap["ct"])))
        ct[0] = (ct[0].toInt() xor 1).toByte()
        wrap["ct"] = JsonValue.Str(Base64Std.encode(ct))
        ring["password_wrap"] = JsonValue.Obj(wrap)
        return canonical(if (gk == null) JsonValue.Obj(ring) else Keyring.finish(ring, gk))
    }

    /** The owner edits the shared item and the member receives the edit. */
    private fun ownerEditReachesMember(s: Share, text: String): Boolean {
        put(s.owner, ITEM_A, "A", text, listOf(s.cid), at = s.clock + 100)
        s.run(s.owner)
        s.run(s.member)
        return body(s.member, ITEM_A) == text
    }

    @Test fun a_flipped_byte_in_the_password_wrap_is_restored_by_the_owner_then_the_share_syncs() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "v1", listOf(s.cid))
        s.connect()
        val trusted = assertNotNull(s.record(s.owner).state.keyring)
        s.folder.files[FolderLayout.KEYRING_PATH] = flippedPasswordWrap(trusted)
        val report = kinds(s.run(s.owner))
        assertTrue("keyring-restored" in report && "tampered" !in report, report.toString())
        assertContentEquals(trusted, s.folder.files[FolderLayout.KEYRING_PATH])
        assertEquals(emptyList(), kinds(s.run(s.member)))
        assertTrue(ownerEditReachesMember(s, "v2"))
    }

    @Test fun a_member_restores_a_keyring_of_its_epoch_that_does_not_authenticate() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "v1", listOf(s.cid))
        s.connect()
        val trusted = assertNotNull(s.record(s.owner).state.keyring)
        s.folder.files[FolderLayout.KEYRING_PATH] = flippedPasswordWrap(trusted)
        val report = kinds(s.run(s.member)) // the member runs first
        assertTrue("keyring-restored" in report && "tampered" !in report, report.toString())
        assertContentEquals(trusted, s.folder.files[FolderLayout.KEYRING_PATH])
        assertFalse("tampered" in kinds(s.run(s.owner)))
        assertTrue(ownerEditReachesMember(s, "v2"))
    }

    @Test fun the_owner_restores_over_bytes_that_do_not_parse_or_a_forged_later_epoch() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "v1", listOf(s.cid))
        s.connect()
        val trusted = assertNotNull(s.record(s.owner).state.keyring)
        for (garbage in listOf("{}", "not json", "{\"group_id\":\"x\"}").map { it.toByteArray() }) {
            s.folder.files[FolderLayout.KEYRING_PATH] = garbage
            // A member cannot tell what the folder should hold: it stops and writes nothing.
            val stopped = kinds(s.run(s.member))
            assertTrue(stopped == listOf("keyring-corrupt") || stopped == listOf("folder-has-other-group"), stopped.toString())
            assertContentEquals(garbage, s.folder.files[FolderLayout.KEYRING_PATH])
            val restored = kinds(s.run(s.owner))
            // A keyring naming another group is said apart (final review A1).
            assertTrue("keyring-restored" in restored || ("other-group-replaced" in restored && stopped == listOf("folder-has-other-group")), restored.toString())
            assertContentEquals(trusted, s.folder.files[FolderLayout.KEYRING_PATH])
        }
        // A later epoch nobody but the owner could sign (the owner signature covers the epoch).
        val ahead = LinkedHashMap(obj(CanonicalJson.parse(trusted)))
        ahead["epoch"] = JsonValue.Int(6)
        s.folder.files[FolderLayout.KEYRING_PATH] = canonical(JsonValue.Obj(ahead))
        val report = kinds(s.run(s.owner))
        assertTrue("keyring-restored" in report && "rejoin-required" !in report, report.toString())
        assertContentEquals(trusted, s.folder.files[FolderLayout.KEYRING_PATH])
        assertTrue(ownerEditReachesMember(s, "v2"))
    }

    @Test fun a_members_rewrite_of_the_password_wrap_is_restored_by_any_device() {
        // A member holds G and can re-MAC a keyring that swaps the password wrap. In share v2 the owner signature covers
        // the password wrap (audit 2026-11-12 F-01), so it does not authenticate: a member's run puts its trusted keyring
        // back, and so does the owner's.
        val s = Share()
        put(s.owner, ITEM_A, "A", "v1", listOf(s.cid))
        s.connect()
        val trusted = assertNotNull(s.record(s.owner).state.keyring)
        val forged = flippedPasswordWrap(trusted, s.record(s.member).state.groupKey())
        s.folder.files[FolderLayout.KEYRING_PATH] = forged
        assertTrue("keyring-restored" in kinds(s.run(s.member)))
        assertContentEquals(trusted, s.folder.files[FolderLayout.KEYRING_PATH])
        s.folder.files[FolderLayout.KEYRING_PATH] = forged
        assertTrue("keyring-restored" in kinds(s.run(s.owner)))
        assertContentEquals(trusted, s.folder.files[FolderLayout.KEYRING_PATH])
        assertTrue(ownerEditReachesMember(s, "v2"))
    }

    // ---- final fix wave B: A2 (a lapsed owner still repairs the keyring) ----

    @Test fun a_lapsed_owner_still_puts_a_damaged_keyring_back_and_syncs_nothing() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "v1", listOf(s.cid))
        s.connect()
        val trusted = assertNotNull(s.record(s.owner).state.keyring)
        s.folder.files[FolderLayout.KEYRING_PATH] = flippedPasswordWrap(trusted)
        s.owner.isPro = false
        val ownView = s.folder.files.filterKeys { it.startsWith("LocalGateKeys Sync/devices/") }
        put(s.owner, ITEM_A, "A", "v2", listOf(s.cid), at = s.clock + 100)
        assertEquals(listOf("keyring-restored", "pro-required"), kinds(s.run(s.owner)))
        assertContentEquals(trusted, s.folder.files[FolderLayout.KEYRING_PATH])
        assertEquals(ownView.keys, s.folder.files.filterKeys { it.startsWith("LocalGateKeys Sync/devices/") }.keys)
        assertTrue(ownView.all { (k, v) -> s.folder.files[k].contentEquals(v) }, "no view written without Pro")
        s.owner.isPro = true
        assertTrue(ownerEditReachesMember(s, "v3"))
    }

    // ---- final fix wave A: finding 2 (a pending member got every item before approval) ----

    @Test fun a_pending_member_adopts_the_keyring_but_merges_and_writes_nothing_until_approved() {
        for (mode in listOf("read", "edit")) {
            val s = Share(mode)
            put(s.owner, ITEM_A, "A", "family wifi", listOf(s.cid))
            s.run(s.owner)
            s.join(s.member, "Member PC")
            if (mode == "edit") put(s.member, ITEM_M, "M", "member text", listOf(s.cid))
            val report = s.run(s.member)
            assertTrue("awaiting-approval" in kinds(report), "$mode ${kinds(report)}")
            assertNull(report.ownStates)
            assertFalse(report.wrote)
            assertFalse(ITEM_A in items(s.member), "$mode: nothing of the owner's arrives before approval")
            assertNull(s.folder.files[FolderLayout.deviceFile(s.deviceId(s.member))!!], "$mode: no own view before approval")
            s.run(s.owner) // adopts the join (pending)
            assertEquals(listOf("Member PC"), s.pendingNames())
            assertFalse(ITEM_M in items(s.owner))
            assertContentEquals(s.record(s.owner).state.keyring, s.record(s.member).state.keyring, "$mode: the keyring is adopted")
            ShareGroups.approve(s.owner.store, s.gid, s.pendingIds())
            s.run(s.owner)
            assertFalse("awaiting-approval" in kinds(s.run(s.member)))
            assertEquals("family wifi", body(s.member, ITEM_A))
            if (mode == "edit") {
                s.run(s.owner)
                assertEquals("member text", body(s.owner, ITEM_M))
            }
        }
    }

    // ---- removal ----

    @Test fun removing_a_member_trashes_the_shared_items_only_and_the_rotation_is_not_for_it() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "shared", listOf(s.cid))
        s.connect()
        assertEquals("shared", body(s.member, ITEM_A))
        put(s.member, ITEM_P, "Mine", "member diary", emptyList())
        val work = collection(s.member, "Work")
        put(s.member, ITEM_W, "Work", "work", listOf(work))
        val memberId = s.deviceId(s.member)
        val notice = ShareGroups.removeMember(s.owner.store, s.gid, memberId, PW2, random, s.tick(), yes, cheap)
        assertEquals(listOf<String?>("Member PC"), ShareGroups.removedMembers(s.owner.store.load(), s.gid).map { it.name })
        // The owner's own device never acts on a notice.
        val ring = assertNotNull(s.record(s.owner).state.keyring)
        assertEquals("owner", reason { ShareGroups.applyShareRemoval(s.owner.store, s.gid, notice, ring, ShareTrash(0)) })
        assertEquals("shared", body(s.owner, ITEM_A))
        // The notice first, then the rotated keyring.
        assertTrue(s.fs(s.owner).publishShareNotice(memberId, notice))
        s.run(s.owner)
        val rotated = assertNotNull(s.folder.files[FolderLayout.KEYRING_PATH])
        assertContentEquals(ring, rotated)
        assertEquals("not-member", reason { ShareGroups.adopt(s.member.store, s.gid, rotated) })
        val report = s.run(s.member)
        assertEquals(listOf("share-removed"), kinds(report))
        assertEquals(s.cid, report.issues.first().detail)
        assertEquals(setOf(ITEM_P, ITEM_W), items(s.member))
        assertTrue(ITEM_A in s.member.store.trashIds)
        assertEquals(emptyMap(), ShareGroups.records(s.member.store.load()))
        assertEquals("shared", body(s.owner, ITEM_A))
    }

    @Test fun a_rotation_without_a_notice_only_stops_the_member() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "shared", listOf(s.cid))
        s.connect()
        ShareGroups.removeMember(s.owner.store, s.gid, s.deviceId(s.member), PW2, random, s.tick(), yes, cheap)
        s.run(s.owner)
        assertEquals(listOf("rejoin-required"), kinds(s.run(s.member)))
        assertEquals("shared", body(s.member, ITEM_A))
    }

    /**
     * The pinned owner is the only signer (desktop audit M10): another approved member, whose signing key this member's
     * keyring lists, cannot remove it, even beside a real rotation that no longer lists it.
     */
    @Test fun a_removal_notice_signed_by_anyone_but_the_owner_is_refused() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "shared", listOf(s.cid))
        s.connect()
        val third = Device("install-c")
        s.join(third, "C")
        s.run(third)
        s.run(s.owner)
        ShareGroups.approve(s.owner.store, s.gid, s.pendingIds())
        s.run(s.owner)
        s.run(s.member)
        s.run(third)
        val b = s.record(s.member).state
        val c = assertNotNull(ShareGroups.records(third.store.load())[s.gid]).state
        val approved = ShareGroups.group(s.record(s.owner)).members.filter { it.approved }.map { it.deviceId }
        assertEquals(setOf(s.deviceId(s.owner), b.deviceId, c.deviceId), approved.toSet())
        val bRing = ShareKeyring.parse(assertNotNull(b.keyring))
        assertNotNull(Keyring.memberSigningKeys(bRing)[c.deviceId], "B's keyring lists C's signing key")
        // The owner really removes B: the rotated keyring no longer lists B, so only the signer rules can refuse.
        val real = ShareGroups.removeMember(s.owner.store, s.gid, b.deviceId, PW2, random, s.tick(), yes, cheap)
        val rotated = assertNotNull(s.record(s.owner).state.keyring)
        val byMember = Removal.makeNotice(c.identity, s.gid, b.deviceId, b.epoch + 1, T0)
        val stranger = Removal.makeNotice(DeviceIdentity.generate(random = random), s.gid, b.deviceId, b.epoch + 1, T0)
        // Self-signed (the builder refuses to make one): the signature never gets checked, the signer is refused first.
        val selfSigned = canonical(
            JsonValue.Obj(
                mapOf(
                    "format" to JsonValue.Int(1), "group_id" to s(s.gid), "device_id" to s(b.deviceId),
                    "epoch" to JsonValue.Int(b.epoch + 1), "signer" to s(b.deviceId), "issued_at" to JsonValue.Int(T0),
                    "sig" to s(Base64Std.encode(b.identity.sign("not the notice".toByteArray()))),
                ),
            ),
        )
        for ((notice, why) in listOf(byMember to "unknown-signer", stranger to "unknown-signer", selfSigned to "stale")) {
            assertEquals(why, reason { ShareGroups.applyShareRemoval(s.member.store, s.gid, notice, rotated, ShareTrash(0)) })
        }
        assertEquals("shared", body(s.member, ITEM_A))
        assertNotNull(ShareGroups.records(s.member.store.load())[s.gid])
        // The owner's own notice beside the same keyring is accepted.
        assertEquals(1, ShareGroups.applyShareRemoval(s.member.store, s.gid, real, rotated, ShareTrash(0)))
    }

    /**
     * Desktop `test_removal_keeps_a_shared_document_that_a_personal_item_links`: documents leave after the items that
     * link them, and one still linked from outside the collection stays.
     */
    @Test fun removal_keeps_a_document_still_linked_from_outside_the_collection() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "shared", listOf(s.cid))
        s.connect()
        val docKept = "11111111-2222-4333-8444-555555555555"
        val docGone = "66666666-7777-4888-8999-aaaaaaaaaaaa"
        fun document(id: String): JsonValue = Wrapper.make(
            Namespace.ITEM,
            JsonValue.Obj(mapOf("id" to s(id), "kind" to s("document"), "title" to s("Doc"), "created_at" to JsonValue.Int(T0), "updated_at" to JsonValue.Int(T0))),
        )
        fun linking(record: JsonValue, doc: String): JsonValue {
            val r = LinkedHashMap((record as JsonValue.Obj).fields)
            val p = LinkedHashMap((r["payload"] as JsonValue.Obj).fields)
            p["document_ids"] = JsonValue.Arr(listOf(s(doc)))
            r["payload"] = JsonValue.Obj(p)
            return JsonValue.Obj(r)
        }
        val m = s.member.store.load()
        val records = LinkedHashMap(m.records)
        records[docKept] = document(docKept)
        records[docGone] = document(docGone)
        for (id in listOf(docKept, docGone)) records[CollectionStates.MEMBERSHIP_PREFIX + id] = CollectionCatalog.membershipWrapper(id, listOf(s.cid))!!
        // The shared item A links one document (A leaves first, so it goes too); a personal note links the other.
        val ra = assertNotNull((records[ITEM_A] as JsonValue.Obj).fields["record"])
        records[ITEM_A] = Wrapper.make(Namespace.ITEM, linking(ra, docGone))
        records[ITEM_P] = Wrapper.make(Namespace.ITEM, linking(noteRecord(ITEM_P, "Mine", "diary", T0), docKept))
        s.member.store.commit(StoreChange(m.revision, records, m.meta, m.sync))
        val notice = ShareGroups.removeMember(s.owner.store, s.gid, s.deviceId(s.member), PW2, random, s.tick(), yes, cheap)
        val ring = assertNotNull(s.record(s.owner).state.keyring)
        assertEquals(2, ShareGroups.applyShareRemoval(s.member.store, s.gid, notice, ring, ShareTrash(0)))
        assertEquals(setOf(ITEM_P, docKept), items(s.member))
        assertEquals(setOf(ITEM_A, docGone), s.member.store.trashIds)
    }

    @Test fun a_share_commit_on_a_changed_vault_or_outside_the_collection_is_refused() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "shared", listOf(s.cid))
        put(s.owner, ITEM_P, "Personal", "diary", emptyList())
        val shareStore = ShareItemStore(s.owner.store, s.gid, ShareTrash(0))
        val view = shareStore.load()
        assertEquals(setOf(ITEM_A), view.records.keys)
        // A personal id in the result never reaches the vault.
        val records = LinkedHashMap(view.records)
        val forged = LinkedHashMap((noteRecord(ITEM_P, "X", "overwritten", T0) as JsonValue.Obj).fields)
        forged.remove("tags")
        forged.remove("favorite")
        forged["collection_ids"] = JsonValue.Arr(listOf(s(s.cid)))
        records[ITEM_P] = Wrapper.make(Namespace.ITEM, JsonValue.Obj(forged))
        assertEquals("bad-remote", reason { shareStore.commit(StoreChange(view.revision, records, view.meta, view.sync)) })
        assertEquals("diary", body(s.owner, ITEM_P))
        // The share state cannot change its key or keyring through a commit.
        val moved = view.sync!!.copy(epoch = view.sync!!.epoch + 1)
        assertEquals("bad-state", reason { shareStore.commit(StoreChange(view.revision, view.records, view.meta, moved)) })
        put(s.owner, ITEM_A, "A", "edited meanwhile", listOf(s.cid), at = T0 + 9)
        assertEquals("store-changed", reason { shareStore.commit(StoreChange(view.revision, view.records, view.meta, view.sync)) })
        assertEquals("edited meanwhile", body(s.owner, ITEM_A))
    }

    @Test fun a_full_trash_refuses_the_removal_and_changes_nothing() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "shared", listOf(s.cid))
        s.connect()
        val notice = ShareGroups.removeMember(s.owner.store, s.gid, s.deviceId(s.member), PW2, random, s.tick(), yes, cheap)
        val ring = assertNotNull(s.record(s.owner).state.keyring)
        assertEquals("trash-full", reason { ShareGroups.applyShareRemoval(s.member.store, s.gid, notice, ring, ShareTrash(ShareTrash.MAX_TRASH)) })
        assertEquals("item-error", reason { ShareGroups.applyShareRemoval(s.member.store, s.gid, notice, ring, ShareTrash(null)) })
        assertEquals("shared", body(s.member, ITEM_A))
        // Through the runner: the run reports `trash-full` itself (never `busy`), and nothing changes.
        assertTrue(s.fs(s.owner).publishShareNotice(s.deviceId(s.member), notice))
        s.run(s.owner)
        val full = FolderSync(s.folder, s.member.install, share = FolderSync.Share(s.gid, true, ShareTrash(ShareTrash.MAX_TRASH)))
        assertEquals(listOf("trash-full"), kinds(full.runOnce(s.member.store, random, s.tick())))
        assertEquals("shared", body(s.member, ITEM_A))
        assertEquals(1, ShareGroups.applyShareRemoval(s.member.store, s.gid, notice, ring, ShareTrash(0)))
    }

    // ---- Pro ----

    private class DerivationCalled : Exception()

    @Test fun a_free_device_cannot_create_join_or_sync_but_can_remove_and_leave() {
        val never = KeyringRotate.KeyDerivation { _, _ -> throw DerivationCalled() }
        val s = Share()
        s.run(s.owner)
        val raw = assertNotNull(s.folder.files[FolderLayout.KEYRING_PATH])
        val free = Device("install-free")
        val mine = collection(free, "Mine")
        assertFailsWith<ShareProRequiredException>("refused before any key derivation") {
            ShareGroups.create(free.store, mine, PW, "Free", "edit", free.install, false, random, s.tick(), yes, null, never)
        }
        assertFailsWith<ShareProRequiredException> {
            ShareGroups.join(free.store, raw, PW, "Free", free.install, false, random, s.tick(), null, never)
        }
        assertNull(free.store.load().shares)
        // A share whose Pro lapsed stops syncing and writes nothing, but removing and leaving still work.
        s.connect()
        s.owner.isPro = false
        val before = s.folder.image()
        assertEquals(listOf("pro-required"), kinds(s.run(s.owner)))
        assertEquals(before, s.folder.image())
        ShareGroups.removeMember(s.owner.store, s.gid, s.deviceId(s.member), PW2, random, s.tick(), yes, cheap)
        s.member.isPro = false
        ShareGroups.leave(s.member.store, s.gid)
        assertEquals(emptyMap(), ShareGroups.records(s.member.store.load()))
        assertEquals(listOf(s.cid), CollectionCatalog.collections(s.member.store.load()).map { it.id }, "the collection stays")
    }

    // ---- secrets ----

    @Test fun share_secrets_never_reach_the_personal_view_a_backup_or_a_description() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "shared", listOf(s.cid))
        s.connect()
        for (d in listOf(s.owner, s.member)) {
            val snap = d.store.load()
            val rec = assertNotNull(ShareGroups.records(snap)[s.gid])
            val secrets = listOf(
                Base64Std.encode(rec.state.key), Base64Std.encode(rec.state.identity.signingPrivateKey),
                Base64Std.encode(rec.state.identity.exchangePrivateKey), s.gid, rec.state.deviceId,
            )
            // The personal view (what personal sync and the encrypted backup carry), collections on.
            val view = SyncMeta.localView(snap.records, snap.meta, "personal-device", T0, true, ShareGroups.collectionShares(snap))
            val text = String(canonical(JsonValue.Arr(view.states.values.mapNotNull { it.item })), Charsets.UTF_8)
            for (secret in secrets) assertFalse(text.contains(secret))
            // Only the link (mode and role) says the collection is shared.
            val link = assertNotNull(view.states[CollectionStates.LINK_PREFIX + s.cid]?.item)
            val r = assertNotNull(((link as JsonValue.Obj).fields["record"] as? JsonValue.Obj)?.fields)
            assertEquals(setOf("kind", "collection_id", "mode", "role"), r.keys)
            assertNull(view.states.keys.firstOrNull { it.contains(s.gid) })
            // Never in a description either.
            val group = ShareGroups.group(rec)
            val described = "$rec $group ${group.members} ${ShareGroupException("x", "y")} ${ShareTrash.of(d.store.trash)} $snap"
            for (secret in secrets.take(3)) assertFalse(described.contains(secret))
            assertFalse(described.contains("Family"))
        }
    }

    // ---- stored shape ----

    @Test fun stored_share_groups_are_checked_and_a_damaged_one_fails_closed() {
        val s = Share(mode = "read")
        s.connect()
        val snap = s.member.store.load()
        val decoded = ShareGroups.records(snap)
        assertEquals(snap.shares, ShareRecord.encode(decoded), "the stored shape round-trips")
        assertEquals(mapOf(s.cid to CollectionShares.Link("read", "member")), ShareGroups.shareLinks(snap))
        val groups = LinkedHashMap((snap.shares as JsonValue.Obj).fields)
        val rec = LinkedHashMap((groups[s.gid] as JsonValue.Obj).fields)
        val cases = ArrayList<JsonValue>()
        rec["shared_mode"] = s("edit")
        cases.add(JsonValue.Obj(LinkedHashMap(rec))) // not what the keyring pins
        rec["shared_mode"] = s("read")
        rec["role"] = s("owner")
        cases.add(JsonValue.Obj(LinkedHashMap(rec))) // not the owner
        rec["role"] = s("member")
        rec["extra"] = JsonValue.Bool(true)
        cases.add(JsonValue.Obj(LinkedHashMap(rec)))
        rec.remove("extra")
        val state = LinkedHashMap((rec["state"] as JsonValue.Obj).fields)
        state["key"] = s(Base64Std.encode(ByteArray(31)))
        cases.add(JsonValue.Obj(LinkedHashMap(rec).also { it["state"] = JsonValue.Obj(state) })) // no usable key
        for (bad in cases) {
            groups[s.gid] = bad
            val damaged = snap.copy(shares = JsonValue.Obj(LinkedHashMap(groups)))
            assertEquals("bad-state", reason { ShareGroups.records(damaged) })
            assertEquals(setOf(s.cid), ShareGroups.readOnlyCollectionIds(damaged), "fails closed")
            assertNull(ShareGroups.shareLinks(damaged))
            assertTrue(s.cid in ShareGroups.protectedCollectionIds(damaged))
            // A share run on a damaged record stops before reading or writing anything.
            val store = TrashingStore()
            val base = store.load()
            store.commit(StoreChange(base.revision, damaged.records, damaged.meta, damaged.sync, StoreChange.Shares.Replace(damaged.shares)))
            val before = s.folder.image()
            val fs = FolderSync(s.folder, s.member.install, share = FolderSync.Share(s.gid, true, ShareTrash(0)))
            assertEquals(listOf("state-corrupt"), kinds(fs.runOnce(store, random, s.tick())))
            assertEquals(before, s.folder.image())
        }
        val garbage = snap.copy(shares = s("damaged"))
        assertEquals(setOf(s.cid), ShareGroups.readOnlyCollectionIds(garbage), "unreadable: every collection")
    }

    @Test fun create_and_join_refusals() {
        val s = Share()
        s.run(s.owner)
        val raw = assertNotNull(s.folder.files[FolderLayout.KEYRING_PATH])
        fun create(d: Device, cid: String) {
            ShareGroups.create(d.store, cid, PW, "PC", "edit", d.install, true, random, s.tick(), yes, null, cheap)
        }
        assertEquals("already-shared", reason { create(s.owner, s.cid) })
        assertEquals("no-collection", reason { create(s.owner, "99999999-9999-4999-8999-999999999999") })
        assertEquals("already-joined", reason { s.join(s.owner, "Again") })
        // A vault that already has the collection (by id) never marks it shared.
        val clash = Device("install-clash")
        val s0 = clash.store.load()
        val records = LinkedHashMap(s0.records)
        records[CollectionStates.CATALOG_PREFIX + s.cid] = CollectionCatalog.catalogWrapper(s.cid, "Mine", "", T0, T0)
        clash.store.commit(StoreChange(s0.revision, records, s0.meta, s0.sync))
        assertEquals("collection-exists", reason { s.join(clash, "Clash") })
        assertNull(clash.store.load().shares)
        // A wrong password changes nothing.
        val wrong = Device("install-wrong")
        assertNotNull(reason { ShareGroups.join(wrong.store, raw, "not the share password at all 9", "W", wrong.install, true, random, s.tick(), null, cheap) })
        assertEquals(StoreSnapshot(), wrong.store.load())
        // A name clash keeps both collections.
        val named = Device("install-named")
        collection(named, "Family")
        s.join(named, "Named")
        assertEquals(listOf("Family", "Family (2)"), CollectionCatalog.collections(named.store.load()).map { it.name }.sorted())
        // A run with another install id, or of a group this vault is not in, stops at once.
        assertEquals(listOf("rejoin-required"), kinds(FolderSync(s.folder, "another-install", share = FolderSync.Share(s.gid, true, ShareTrash(0))).runOnce(s.owner.store, random, s.tick())))
        assertEquals(listOf("not-joined"), kinds(FolderSync(s.folder, "install-wrong", share = FolderSync.Share(s.gid, true, ShareTrash(0))).runOnce(wrong.store, random, s.tick())))
        assertEquals("bad-share", assertFailsWith<FolderSyncException> { FolderSync(s.folder, "x", share = FolderSync.Share("not a group id!", true, ShareTrash(0))) }.reason)
        // The folder reference round-trips; one the stored record could not hold is refused before anything is written.
        val folderRef = "content://tree/primary%3ALocalGateKeys".toByteArray()
        ShareGroups.setFolder(s.owner.store, s.gid, folderRef)
        assertContentEquals(folderRef, s.record(s.owner).folder)
        val before = s.owner.store.load()
        assertEquals("bad-folder", reason { ShareGroups.setFolder(s.owner.store, s.gid, ByteArray(ShareRecord.MAX_FOLDER_BYTES + 1)) })
        assertEquals(before, s.owner.store.load())
    }

    @Test fun a_folder_reference_too_large_is_refused_by_create_and_join_before_anything_is_written() {
        // Task 5k review minor 6(b): `bad-folder` through create and join, not only setFolder.
        val s = Share()
        s.run(s.owner)
        val (change, other) = CollectionCatalog.create("Work", snapshot = s.owner.store.load(), now = T0)
        s.owner.store.commit(change)
        val big = ByteArray(ShareRecord.MAX_FOLDER_BYTES + 1)
        val owner = s.owner.store.load()
        assertEquals("bad-folder", reason {
            ShareGroups.create(s.owner.store, other, PW, "PC", "edit", s.owner.install, true, random, s.tick(), yes, big, cheap)
        })
        assertEquals(owner, s.owner.store.load())
        val raw = assertNotNull(s.folder.files[FolderLayout.KEYRING_PATH])
        assertEquals("bad-folder", reason {
            ShareGroups.join(s.member.store, raw, PW, "Member", s.member.install, true, random, s.tick(), big, cheap)
        })
        assertEquals(StoreSnapshot(), s.member.store.load())
    }

    @Test fun a_folder_keyring_that_changes_a_pinned_fact_stops_the_run_as_tampered_and_writes_nothing() {
        // Task 5k review minor 6(a): at runner level. The folder gets a keyring of the same group, valid under the group key
        // and signed by the owner's own key, that changes the pinned mode (edit -> read): the member's run stops with
        // `tampered` and its store does not change.
        val s = Share()
        s.connect()
        val owner = s.record(s.owner)
        val gk = owner.state.groupKey()
        val genuine = ShareKeyring.parse(assertNotNull(s.folder.files[FolderLayout.KEYRING_PATH]))
        val body = LinkedHashMap(obj(genuine))
        body["metadata"] = JsonValue.Obj(LinkedHashMap(obj(body["metadata"])).also { it["shared_mode"] = s("read") })
        val approved = assertNotNull(ShareKeyring.approvedMembers(genuine))
        // Share v2: the owner holds the content key and signs the content block too.
        val content = ShareKeyring.openContentKey(genuine, owner.state.identity)
        val forged = Keyring.finish(ShareKeyring.signOwner(body, owner.state.identity, approved, content), gk)
        s.folder.files[FolderLayout.KEYRING_PATH] = canonical(forged)
        val storeBefore = s.member.store.load()
        val pinBefore = s.record(s.member).pin
        val report = s.run(s.member)
        assertEquals(listOf("tampered"), kinds(report))
        assertEquals(storeBefore, s.member.store.load())
        assertEquals("edit", s.record(s.member).pin.sharedMode)
        assertEquals(pinBefore, s.record(s.member).pin)
    }

    @Test fun the_host_folder_steps_never_write_over_another_group_or_a_newer_keyring() {
        val s = Share()
        val fs = s.fs(s.owner)
        assertFalse(fs.holdsKeyring())
        assertTrue(fs.writeShareKeyring(s.owner.store, s.gid))
        assertTrue(fs.holdsKeyring())
        assertContentEquals(s.record(s.owner).state.keyring, s.folder.files[FolderLayout.KEYRING_PATH])
        // After an approve the grown keyring goes over the older one.
        s.join(s.member, "Member PC")
        s.run(s.member)
        s.run(s.owner)
        ShareGroups.approve(s.owner.store, s.gid, s.pendingIds())
        assertTrue(fs.writeShareKeyring(s.owner.store, s.gid))
        assertContentEquals(s.record(s.owner).state.keyring, s.folder.files[FolderLayout.KEYRING_PATH])
        // Another group's keyring, or bytes that do not parse, are never replaced.
        val other = Share()
        other.run(other.owner)
        val foreign = assertNotNull(other.folder.files[FolderLayout.KEYRING_PATH])
        for (bytes in listOf(foreign, "not json".toByteArray())) {
            s.folder.files[FolderLayout.KEYRING_PATH] = bytes
            assertFalse(fs.writeShareKeyring(s.owner.store, s.gid))
            assertContentEquals(bytes, s.folder.files[FolderLayout.KEYRING_PATH])
        }
        assertFalse(fs.writeShareKeyring(s.owner.store, "99999999-9999-4999-8999-999999999999"))
        // A keyring of a later format (a newer app wrote it), even of an older epoch, is never replaced.
        val newer = LinkedHashMap(obj(CanonicalJson.parse(assertNotNull(s.record(s.owner).state.keyring))))
        newer["format"] = JsonValue.Int(4)
        newer["epoch"] = JsonValue.Int(0)
        val newerBytes = canonical(JsonValue.Obj(newer))
        s.folder.files[FolderLayout.KEYRING_PATH] = newerBytes
        assertFalse(fs.writeShareKeyring(s.owner.store, s.gid))
        assertContentEquals(newerBytes, s.folder.files[FolderLayout.KEYRING_PATH])
    }

    // ---- share v2 (docs/superpowers/specs/2026-11-12-collections-crypto-gating.md) ----

    @Test fun the_share_password_alone_opens_no_item() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "family wifi", listOf(s.cid))
        s.run(s.owner)
        s.join(s.member, "Member PC")
        val first = kinds(s.run(s.member)) // writes its join (the folder is behind) and waits
        assertTrue("awaiting-approval" in first && "tampered" !in first, first.toString())
        assertEquals(2, ShareGroups.list(s.member.store.load()).single().version)
        // The pending member holds G and the folder's views, but no content key: G opens none of them.
        assertNull(ShareGroups.viewKey(s.member.store.load(), s.gid))
        val published = assertNotNull(s.folder.files[FolderLayout.deviceFile(s.deviceId(s.owner))!!])
        val st = s.record(s.member).state
        val ownerId = s.deviceId(s.owner)
        assertEquals("auth-failed", try {
            ViewFile.decode(published, GroupKey(st.groupId, st.epoch, st.key), ownerId)
            null
        } catch (e: app.localgatekeys.core.group.SyncFormatException) {
            e.reason
        })
        assertFalse(ITEM_A in items(s.member))
        s.run(s.owner)
        ShareGroups.approve(s.owner.store, s.gid, s.pendingIds())
        s.run(s.owner)
        assertEquals(emptyList(), kinds(s.run(s.member)))
        assertEquals("family wifi", body(s.member, ITEM_A))
        assertContentEquals(
            assertNotNull(ShareGroups.viewKey(s.owner.store.load(), s.gid)).key,
            assertNotNull(ShareGroups.viewKey(s.member.store.load(), s.gid)).key,
        )
    }

    @Test fun a_content_wrap_that_does_not_open_to_the_committed_key_stops_the_run_as_tampered() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "v1", listOf(s.cid))
        s.connect()
        // A keyring the owner signed whose wrap for the member is the owner's own (the member cannot open it).
        val ownerRec = s.record(s.owner)
        val genuine = ShareKeyring.parse(assertNotNull(ownerRec.state.keyring))
        val ring = LinkedHashMap(obj(genuine))
        val content = LinkedHashMap(obj(ring["content"]))
        val wraps = LinkedHashMap(obj(content["wraps"]))
        val memberId = s.deviceId(s.member)
        wraps[memberId] = wraps.getValue(s.deviceId(s.owner))
        content["wraps"] = JsonValue.Obj(wraps)
        ring["content"] = JsonValue.Obj(content)
        val ck = ShareKeyring.openContentKey(genuine, ownerRec.state.identity)
        val signed = ShareKeyring.signOwner(ring, ownerRec.state.identity, ShareKeyring.approvedMembers(genuine), ck)
        val bytes = canonical(Keyring.finish(signed, ownerRec.state.groupKey()))
        // The member trusts it (stored) and the folder holds the same bytes: the run stops as tampered, nothing written.
        val rec = s.record(s.member)
        val damaged = rec.copy(state = rec.state.copy(keyring = bytes))
        assertEquals("content-key", reason { ShareGroups.viewKey(damaged) })
        val snap = s.member.store.load()
        s.member.store.commit(StoreChange(snap.revision, snap.records, snap.meta, snap.sync, StoreChange.Shares.Replace(ShareRecord.encode(mapOf(s.gid to damaged)))))
        s.folder.files[FolderLayout.KEYRING_PATH] = bytes
        val ownFile = s.folder.files[FolderLayout.deviceFile(memberId)!!]
        val report = s.run(s.member)
        assertEquals(listOf("tampered"), kinds(report))
        assertFalse(report.wrote)
        assertContentEquals(ownFile, s.folder.files[FolderLayout.deviceFile(memberId)!!])
    }

    @Test fun a_newer_keyring_format_asks_for_an_update_and_is_never_overwritten() {
        val s = Share()
        put(s.owner, ITEM_A, "A", "v1", listOf(s.cid))
        s.connect()
        val newer = LinkedHashMap(obj(CanonicalJson.parse(assertNotNull(s.folder.files[FolderLayout.KEYRING_PATH]))))
        newer["format"] = JsonValue.Int(4)
        newer["epoch"] = JsonValue.Int(9)
        val bytes = canonical(JsonValue.Obj(newer))
        s.folder.files[FolderLayout.KEYRING_PATH] = bytes
        for (d in listOf(s.owner, s.member)) {
            val before = d.store.load()
            assertEquals(listOf("update-required"), kinds(s.run(d)))
            assertContentEquals(bytes, s.folder.files[FolderLayout.KEYRING_PATH], "never written over")
            assertEquals(before, d.store.load())
        }
        assertEquals("newer-format", reason { ShareGroups.adopt(s.member.store, s.gid, bytes) })
    }

    @Test fun a_v1_share_keeps_syncing_until_the_owner_upgrades_it() {
        val s = Share()
        val v1 = Share.legacy()
        put(v1.owner, ITEM_A, "A", "v1 text", listOf(v1.cid))
        v1.connect()
        assertEquals("v1 text", body(v1.member, ITEM_A))
        assertEquals(1, ShareGroups.list(v1.owner.store.load()).single().version)
        assertTrue(ShareGroups.needsUpgrade(v1.owner.store.load(), v1.gid))
        assertFalse(ShareGroups.needsUpgrade(v1.member.store.load(), v1.gid))
        assertFalse(ShareGroups.needsUpgrade(s.owner.store.load(), s.gid))
        // v1 views are sealed with G.
        val st = v1.record(v1.member).state
        assertContentEquals(st.key, assertNotNull(ShareGroups.viewKey(v1.member.store.load(), v1.gid)).key)
        // A third person joins (pending), then the owner upgrades with the same password.
        val third = Device("install-third")
        v1.run(v1.owner)
        v1.join(third, "Third PC")
        v1.run(third)
        v1.run(v1.owner)
        assertEquals("not-owner", reason { ShareGroups.upgrade(v1.member.store, v1.gid, PW, random, yes, cheap) })
        assertEquals("weak-password", reason { ShareGroups.upgrade(v1.owner.store, v1.gid, PW, random, { false }, cheap) })
        val upgraded = ShareGroups.upgrade(v1.owner.store, v1.gid, PW, random, yes, cheap)
        assertEquals(2, upgraded.version)
        assertEquals(listOf("Third PC"), v1.pendingNames(), "a pending member stays pending")
        assertEquals("already-upgraded", reason { ShareGroups.upgrade(v1.owner.store, v1.gid, PW, random, yes, cheap) })
        assertFalse(ShareGroups.needsUpgrade(v1.owner.store.load(), v1.gid))
        assertTrue(v1.fs(v1.owner).writeShareKeyring(v1.owner.store, v1.gid))
        // The approved member syncs on without typing anything; the pending one opens nothing.
        assertTrue(ownerEditReachesMember(v1, "v2 text"))
        assertEquals(2, v1.record(v1.member).state.epoch)
        assertNotNull(ShareGroups.viewKey(v1.member.store.load(), v1.gid))
        assertEquals(listOf("awaiting-approval"), kinds(v1.run(third)))
        assertNull(ShareGroups.viewKey(third.store.load(), v1.gid))
    }

    @Test fun removing_from_a_v1_share_upgrades_it() {
        val v1 = Share.legacy()
        put(v1.owner, ITEM_A, "A", "v1 text", listOf(v1.cid))
        v1.connect()
        val third = Device("install-third")
        v1.join(third, "Third PC")
        v1.run(third)
        v1.run(v1.owner)
        ShareGroups.approve(v1.owner.store, v1.gid, v1.pendingIds())
        v1.run(v1.owner)
        v1.run(third)
        assertEquals("v1 text", body(third, ITEM_A))
        val notice = ShareGroups.removeMember(v1.owner.store, v1.gid, v1.deviceId(third), PW2, random, v1.tick(), yes, cheap)
        assertTrue(v1.fs(v1.owner).publishShareNotice(v1.deviceId(third), notice))
        assertTrue(v1.fs(v1.owner).writeShareKeyring(v1.owner.store, v1.gid))
        assertEquals(2, ShareGroups.list(v1.owner.store.load()).single().version)
        assertTrue(ownerEditReachesMember(v1, "after removal"))
        assertNotNull(ShareGroups.viewKey(v1.member.store.load(), v1.gid))
    }

    // ---- the desktop's share vectors, end to end ----

    private val vec: Map<String, JsonValue> by lazy { Vectors.json(Vectors.shareCollections("keyring.json")).obj().fields }

    /** A member device of the vectors' share (B or C at epoch 1, holding `join_c`), with one shared item stored. */
    private fun vectorMember(who: String): Pair<TrashingStore, ShareRecord> {
        val gid = str(vec["group_id"])!!
        val cid = str(vec["collection_id"])!!
        val gk1 = GroupKey(gid, 1, Vectors.hex(str(obj(vec["create"])["group_key_hex"])!!))
        val joinedC = obj(vec["join_c"])["keyring"]!!
        val identity = SyncFixtures.identity(who)
        val state = SyncGroupState(
            gid, 1, gk1.key, identity, "install-$who", true, membersEpoch = 1, members = ShareKeyring.memberIds(joinedC),
            keyring = canonical(joinedC), unackedMembers = ShareKeyring.pending(joinedC, identity.deviceId),
        )
        val record = ShareRecord(ShareRecord.Role.MEMBER, ShareKeyring.Pin.of(joinedC), state)
        val store = TrashingStore()
        val records = LinkedHashMap<String, JsonValue>()
        records[CollectionStates.CATALOG_PREFIX + cid] = CollectionCatalog.catalogWrapper(cid, "Family", "", T0, T0)
        records[ITEM_A] = Wrapper.make(Namespace.ITEM, noteRecord(ITEM_A, "A", "shared", T0))
        records[CollectionStates.MEMBERSHIP_PREFIX + ITEM_A] = CollectionCatalog.membershipWrapper(ITEM_A, listOf(cid))!!
        records[ITEM_P] = Wrapper.make(Namespace.ITEM, noteRecord(ITEM_P, "Mine", "diary", T0))
        store.commit(StoreChange(0, records, emptyMap(), null, StoreChange.Shares.Replace(ShareRecord.encode(mapOf(gid to record)))))
        assertEquals(mapOf(gid to record), ShareGroups.records(store.load()), "the vectors' state is a valid stored record")
        return store to record
    }

    @Test fun the_desktop_owners_removal_notice_and_rotation_remove_this_member() {
        val (store, record) = vectorMember("B")
        val r = obj(vec["remove_b"])
        val folder = MemoryFolder()
        folder.files[FolderLayout.KEYRING_PATH] = canonical(r["keyring"]!!)
        folder.files[Removal.noticePath(record.state.deviceId)!!] = str(r["notice"])!!.toByteArray(Charsets.US_ASCII)
        val fs = FolderSync(folder, "install-B", share = FolderSync.Share(record.groupId, true, ShareTrash.of(store.trash)))
        val report = fs.runOnce(store, random, FixedClock((vec["now"] as JsonValue.Int).v + 1000))
        assertEquals(listOf("share-removed"), kinds(report))
        assertEquals(record.collectionId, report.issues.first().detail)
        assertEquals(setOf(ITEM_P), store.load().itemRecords.keys)
        assertEquals(setOf(ITEM_A), store.trashIds)
        assertEquals(emptyMap(), ShareGroups.records(store.load()))
        assertEquals(listOf(record.collectionId), CollectionCatalog.collections(store.load()).map { it.id }, "the collection stays")
    }

    @Test fun the_desktops_forged_notice_is_refused_and_nothing_changes() {
        val (store, record) = vectorMember("C")
        val forged = obj(vec["forged_notice"])
        assertEquals("C", str(forged["device"]))
        val folder = MemoryFolder()
        folder.files[FolderLayout.KEYRING_PATH] = canonical(obj(vec["remove_b"])["keyring"]!!)
        folder.files[Removal.noticePath(record.state.deviceId)!!] = str(forged["notice"])!!.toByteArray(Charsets.UTF_8)
        val before = store.load()
        val fs = FolderSync(folder, "install-C", share = FolderSync.Share(record.groupId, true, ShareTrash.of(store.trash)))
        val report = fs.runOnce(store, random, FixedClock((vec["now"] as JsonValue.Int).v + 1000))
        assertEquals(listOf("rejoin-required"), kinds(report))
        assertTrue(report.issues.first().detail.contains(str(forged["reason"])!!), report.issues.first().detail)
        assertEquals(before, store.load())
        assertEquals(emptySet(), store.trashIds)
    }
}
