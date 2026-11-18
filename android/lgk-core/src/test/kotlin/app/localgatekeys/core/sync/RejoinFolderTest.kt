package app.localgatekeys.core.sync

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MemoryFolder
import app.localgatekeys.core.support.MemoryStore
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.SyncFixtures.GROUP_ID
import app.localgatekeys.core.support.SyncFixtures.KEYRING_PATH
import app.localgatekeys.core.support.SyncFixtures.T0
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * A device that left a cloud-folder group joins the same folder again with what Leave kept (design 2026-11-17
 * keep-device-id-on-rejoin, rules 3 and 6): one member entry under the same id, and its counters continue, so the other
 * members take nothing it writes for a replay or a rollback.
 */
class RejoinFolderTest {
    private val pw = SyncFixtures.pwKey("1")

    /** Refusals that would mean a peer took the rejoined device for a replay, a rollback or a forgery. */
    private val replayKinds = setOf(
        "rollback", "suspicious-rewrite", "implausible-counter", "view-forged", "view-unsigned", "signer-changed",
        "own-file-rewritten", "peer-vault-rollback", "vault-rollback",
    )

    private var step = 0
    private fun now(): Long = T0 + 1000 + 10L * ++step

    private fun note(id: String, title: String, at: Long): JsonValue {
        fun s(v: String) = JsonValue.Str(v)
        val r = JsonValue.Obj(
            mapOf(
                "id" to s(id), "kind" to s("note"), "title" to s(title), "created_at" to JsonValue.Int(T0),
                "updated_at" to JsonValue.Int(at), "favorite" to JsonValue.Bool(false), "tags" to JsonValue.Arr(emptyList()),
                "payload" to JsonValue.Obj(mapOf("body" to s(title), "fields" to JsonValue.Arr(emptyList()), "template_id" to JsonValue.Null)),
            ),
        )
        return Wrapper.make(Namespace.ITEM, Normalise.normalForm(Namespace.ITEM, r))
    }

    private fun put(store: MemoryStore, n: Int, title: String) {
        val snap = store.load()
        val id = "00000000-0000-4000-8000-%012d".format(n)
        store.commit(StoreChange(snap.revision, snap.records + (id to note(id, title, T0 + n)), snap.meta, snap.sync))
    }

    private fun has(store: MemoryStore, n: Int): Boolean = store.load().records.containsKey("00000000-0000-4000-8000-%012d".format(n))

    /** A member that was in the group from the start (the vector keyring at epoch 1). */
    private inner class Member(name: String, folder: MemoryFolder) {
        val identity: DeviceIdentity = SyncFixtures.identity(name)
        val fs = FolderSync(folder, "install-$name")
        val store = MemoryStore(
            StoreSnapshot(
                sync = SyncGroupState(
                    groupId = GROUP_ID, epoch = 1, key = SyncFixtures.epochKey("1").key, identity = identity, installId = "install-$name",
                    membersEpoch = 1, members = listOf("A", "B", "C").map { SyncFixtures.identity(it).deviceId }.sorted(),
                    keyring = Vectors.sync("keyring_epoch1.json").readBytes(),
                ),
            ),
        )

        fun sync(): RunReport = fs.runOnce(store, DetRand("member|${identity.deviceId}|$step"), FixedClock(now()))
    }

    private inner class Phone(val folder: MemoryFolder) {
        val fs = FolderSync(folder, "install-phone")
        val store = MemoryStore()
        val state: SyncGroupState get() = store.load().sync!!

        fun join(kept: KeptIdentity? = null, name: String = "Pixel"): RunReport =
            fs.join(store, name, DetRand("join|$step"), FixedClock(now()), kept) { pw }

        fun sync(): RunReport = fs.runOnce(store, DetRand("phone|$step"), FixedClock(now()))

        /** Leave sync as the app does it: keep the identity, then clear the group state (items stay). */
        fun leave(): KeptIdentity {
            val kept = KeptIdentity.of(state)
            val snap = store.load()
            store.commit(StoreChange(snap.revision, snap.records, snap.meta, null))
            return kept
        }
    }

    private fun kinds(r: RunReport) = r.issues.map { it.kind }

    private fun members(folder: MemoryFolder): List<String> =
        ((Keyring.obj(Keyring.parse(folder.files[KEYRING_PATH]!!))["members"] as JsonValue.Arr).items)
            .map { Keyring.str(Keyring.obj(it)["device_id"])!! }

    private fun setup(): Triple<MemoryFolder, Member, Phone> {
        val folder = MemoryFolder()
        folder.files[KEYRING_PATH] = Vectors.sync("keyring_epoch1.json").readBytes()
        val a = Member("A", folder)
        assertEquals(emptyList(), kinds(a.sync()))
        val phone = Phone(folder)
        assertEquals(emptyList(), kinds(phone.join()))
        put(phone.store, 1, "From the phone")
        assertEquals(emptyList(), kinds(phone.sync()))
        assertEquals(emptyList(), kinds(a.sync()))
        assertTrue(has(a.store, 1))
        return Triple(folder, a, phone)
    }

    @Test fun leaving_and_joining_the_same_folder_again_keeps_one_member_and_the_id() {
        val (folder, a, phone) = setup()
        val id = phone.state.deviceId
        // An acknowledged rollback raised this vault's generation offset: the rejoin must keep it.
        val snap = phone.store.load()
        phone.store.commit(StoreChange(snap.revision, snap.records, snap.meta, phone.state.copy(generationOffset = 5)))
        val counterBefore = phone.state.ownCounter
        val before = members(folder)
        assertEquals(1, before.count { it == id })

        val kept = phone.leave()
        put(phone.store, 2, "Written while out of sync")
        put(a.store, 3, "Written on A meanwhile")
        assertEquals(emptyList(), kinds(a.sync()))

        val report = phone.join(kept, name = "Pixel again")
        assertTrue(kinds(report).none { it in replayKinds }, kinds(report).toString())
        assertEquals(id, phone.state.deviceId)
        assertEquals(kept.identity, phone.state.identity)
        // One entry, in its place, rewritten (the new name reads back); the keyring still opens for A.
        assertEquals(before, members(folder))
        val ring = Keyring.parse(folder.files[KEYRING_PATH]!!)
        assertEquals(SyncFixtures.epochKey("1"), Keyring.accept(ring, SyncFixtures.epochKey("1"), a.identity))
        assertEquals("Pixel again", Keyring.memberNames(ring, SyncFixtures.epochKey("1"))[id])
        // The counters continue.
        assertTrue(phone.state.ownCounter > counterBefore, "own counter ${phone.state.ownCounter} <= $counterBefore")
        assertEquals(5, phone.state.generationOffset)

        // A takes the rejoined device's file (no replay or rollback refusal); items go both ways.
        val seen = a.sync()
        assertTrue(kinds(seen).none { it in replayKinds }, kinds(seen).toString())
        assertTrue(has(a.store, 2))
        assertEquals(phone.state.ownCounter, a.store.load().sync!!.lastSeen[id])
        assertEquals(emptyList(), kinds(phone.sync()))
        assertTrue(has(phone.store, 3))
    }

    @Test fun the_own_file_counter_continues_even_when_the_file_is_gone() {
        val (folder, a, phone) = setup()
        val id = phone.state.deviceId
        val last = a.store.load().sync!!.lastSeen[id]!!
        val kept = phone.leave()
        // Someone tidied the folder: without the kept counter the new file would start at 1, below what A accepted.
        folder.remove(SyncFixtures.devPath(id))
        folder.remove(FolderLayout.signatureFile(id)!!)
        put(phone.store, 2, "After the rejoin")
        phone.join(kept)
        assertTrue(phone.state.ownCounter > last)
        val seen = a.sync()
        assertTrue(kinds(seen).none { it in replayKinds }, kinds(seen).toString())
        assertTrue(has(a.store, 2))
    }

    @Test fun a_listed_id_with_other_keys_a_removal_notice_or_another_group_joins_with_a_new_identity() {
        val (folder, _, phone) = setup()
        val id = phone.state.deviceId
        val kept = phone.leave()

        // The keyring lists the id with other keys: not this device's entry.
        val impostor = KeptIdentity(GROUP_ID, DeviceIdentity(id, ByteArray(32) { 1 }, ByteArray(32) { 2 }), 9, 0)
        assertEquals(FolderSync.KeptUse.NONE, phone.fs.keptUse(Keyring.parse(folder.files[KEYRING_PATH]!!), impostor))
        // Another group's kept identity is left alone.
        val elsewhere = KeptIdentity("7c1d8e4f-0000-4000-8000-000000000001", kept.identity, 9, 0)
        assertEquals(FolderSync.KeptUse.NONE, phone.fs.keptUse(Keyring.parse(folder.files[KEYRING_PATH]!!), elsewhere))
        // Listed with the same keys: rewritten in place; not listed: added under the kept id.
        assertEquals(FolderSync.KeptUse.REPLACE, phone.fs.keptUse(Keyring.parse(folder.files[KEYRING_PATH]!!), kept))
        val stranger = KeptIdentity(GROUP_ID, DeviceIdentity.generate(random = DetRand("stranger")), 0, 0)
        assertEquals(FolderSync.KeptUse.ADD, phone.fs.keptUse(Keyring.parse(folder.files[KEYRING_PATH]!!), stranger))

        // A removal notice for the id (any file under its name): a new identity, the old entry untouched.
        folder.files[Removal.noticePath(id)!!] = "anything".toByteArray()
        val before = members(folder)
        assertEquals(emptyList(), kinds(phone.join(kept)).filter { it in replayKinds })
        assertNotEquals(id, phone.state.deviceId)
        assertEquals(before + phone.state.deviceId, members(folder))
        assertEquals(0L, phone.state.generationOffset)
    }

    @Test fun a_kept_identity_is_used_only_from_no_group() {
        val (folder, _, phone) = setup()
        val kept = KeptIdentity.of(phone.state)
        // Still in the group (not healthy is the only way a join goes on): the store's own identity wins, as before.
        val snap = phone.store.load()
        phone.store.commit(StoreChange(snap.revision, snap.records, snap.meta, phone.state.copy(hasFolder = false)))
        phone.join(kept)
        assertNotEquals(kept.deviceId, phone.state.deviceId)
        assertEquals(1, members(folder).count { it == phone.state.deviceId })
    }

    @Test fun the_kept_identity_round_trips_and_refuses_anything_else() {
        val id = SyncFixtures.identity("B")
        val kept = KeptIdentity(GROUP_ID, id, 12, 3)
        val back = KeptIdentity.decode(kept.encode())
        assertEquals(GROUP_ID, back.groupId)
        assertEquals(id, back.identity)
        assertEquals(12, back.ownCounter)
        assertEquals(3, back.generationOffset)
        assertContentEquals(kept.encode(), back.encode())
        assertFalse(kept.toString().contains(app.localgatekeys.core.primitives.Base64Std.encode(id.signingPrivateKey)))
        assertFailsWith<IllegalArgumentException> { KeptIdentity.decode("{}".toByteArray()) }
        assertFailsWith<IllegalArgumentException> { KeptIdentity.decode("not json".toByteArray()) }
        val extra = String(kept.encode()).replace("{", "{\"x\":1,").toByteArray()
        assertFailsWith<IllegalArgumentException> { KeptIdentity.decode(extra) }
        assertFailsWith<IllegalArgumentException> { KeptIdentity(GROUP_ID, id, -1, 0) }
        // Continuing a joined state never lowers what the join set.
        val joined = SyncGroupState(GROUP_ID, 1, ByteArray(32), id, "install", ownCounter = 20)
        assertEquals(20, kept.continuing(joined).ownCounter)
        assertEquals(3, kept.continuing(joined).generationOffset)
    }
}
