package app.localgatekeys.core.sync

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.keyring.KeyringException
import app.localgatekeys.core.keyring.KeyringRotate
import app.localgatekeys.core.lan.LanPeer
import app.localgatekeys.core.lan.LanPeers
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MemoryFolder
import app.localgatekeys.core.support.MemoryStore
import app.localgatekeys.core.support.MergeVectors.arr
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.QueueRandom
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.SyncFixtures.KEYRING_PATH
import app.localgatekeys.core.support.SyncFixtures.T0
import app.localgatekeys.core.support.Vectors
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Giving a Wi-Fi-only group a cloud folder (desktop `add_folder_to_group`, Swift `testAddFolderToWiFiGroup`) and the
 * keyring it writes (`create_for_existing_group`, vector `mac/keyring_write.json` "existing").
 */
class AddFolderToGroupTest {
    private val password = "correct horse battery staple 42!"
    private val yes: (String) -> Boolean = { true }
    private val cheap = KeyringRotate.KeyDerivation { pw, salt ->
        MessageDigest.getInstance("SHA-256").digest(pw.toByteArray(Charsets.UTF_8) + salt)
    }

    private fun reason(f: () -> Any?): String? = try {
        f()
        null
    } catch (e: FolderSyncException) {
        e.reason
    } catch (e: KeyringException) {
        e.reason
    }

    /** The member's `signing_proof` is a signature: compared by verifying (accept), not by bytes. */
    private fun withoutProof(ring: JsonValue): ByteArray {
        val o = LinkedHashMap(obj(ring))
        o["members"] = JsonValue.Arr(arr(o["members"]).map { m -> JsonValue.Obj(LinkedHashMap(obj(m)).also { it.remove("signing_proof") }) })
        o.remove("mac")
        return CanonicalJson.encode(JsonValue.Obj(o), Dialect.UTF8)
    }

    @Test fun first_keyring_of_an_existing_group_matches_the_desktop_writer() {
        val write = Vectors.json(Vectors.sync("mac/keyring_write.json")).obj().fields
        val ex = obj(write["existing"])
        val a = SyncFixtures.identity("A")
        val gk = GroupKey(str(ex["group_id"])!!, 3, Vectors.hex(str(ex["group_key_hex"])!!))
        val known = obj(write["argon2"]).mapValues { Vectors.hex(str(it.value)!!) }
        val table = KeyringRotate.KeyDerivation { pw, salt -> known["$pw|${Base64Std.encode(salt)}"] ?: ByteArray(32) }
        val random = QueueRandom(arr(ex["random_reads_hex"]).map { Vectors.hex(str(it)!!) })
        val now = (write["now"] as JsonValue.Int).v
        val ring = KeyringRotate.createForExistingGroup(gk, str(write["password"])!!, a, str(write["name"])!!, random, now, yes, table)
        assertTrue(random.isEmpty)
        assertContentEquals(withoutProof(ex["keyring"]!!), withoutProof(ring))
        assertEquals(JsonValue.Null, obj(ring)["prev_mac"])
        assertEquals(gk, Keyring.accept(ring, gk, a))
        assertEquals(gk, Keyring.accept(ex["keyring"]!!, gk, a))
        assertEquals("weak-password", reason { KeyringRotate.createForExistingGroup(gk, "x", a, "Phone", DetRand("w"), now, { false }, table) })
    }

    @Test fun a_wifi_group_gets_a_folder_and_its_peer_attaches() {
        val wifi = LanPeers.createWifiGroup("phone-install", DetRand("wifi"))
        assertFalse(wifi.hasFolder)
        val peerIdentity = DeviceIdentity.generate(random = DetRand("peer"))
        val peerState = wifi.copy(identity = peerIdentity, installId = "peer-install")
        val phone = MemoryStore(StoreSnapshot(sync = wifi))
        val peer = MemoryStore(StoreSnapshot(sync = peerState))
        val folder = MemoryFolder()
        val fs = FolderSync(folder, "phone-install")
        val report = fs.addFolderToGroup(phone, password, "Phone", false, DetRand("add"), FixedClock(T0), yes, cheap)
        assertEquals(emptyList(), report.issues)
        val s = phone.snapshot.sync!!
        assertTrue(s.hasFolder)
        assertEquals(1, s.epoch)
        assertContentEquals(wifi.key, s.key)
        assertEquals(wifi.identity, s.identity)
        assertEquals(listOf(wifi.deviceId), s.members)
        val ring = Keyring.parse(folder.read(KEYRING_PATH, 1 shl 20))
        assertEquals(JsonValue.Null, obj(ring)["prev_mac"])
        assertEquals(wifi.groupKey(), Keyring.accept(ring, wifi.groupKey(), wifi.identity))
        assertEquals("already-has-folder", reason { fs.addFolderToGroup(phone, password, "Phone", false, DetRand("x"), FixedClock(T0), yes, cheap) })

        // The peer adds the same folder: it attaches with the password and keeps its identity.
        val fsPeer = FolderSync(folder, "peer-install")
        val attached = fsPeer.addFolderToGroup(peer, password, "Laptop", false, DetRand("peer-add"), FixedClock(T0 + 5), yes, cheap)
        assertEquals(emptyList(), attached.issues)
        assertEquals(peerIdentity, peer.snapshot.sync!!.identity)
        assertEquals(setOf(wifi.deviceId, peerState.deviceId), peer.snapshot.sync!!.members.toSet())
        // A wrong password leaves a third device untouched.
        val third = MemoryStore(StoreSnapshot(sync = wifi.copy(identity = DeviceIdentity.generate(random = DetRand("third")), installId = "third")))
        assertEquals("password", reason { FolderSync(folder, "third").addFolderToGroup(third, "another long phrase 77?", "Tablet", false, DetRand("t"), FixedClock(T0 + 9), yes, cheap) })
        assertEquals(0, third.commits)
    }

    @Test fun refusals_leave_store_and_folder_untouched() {
        val wifi = LanPeers.createWifiGroup("phone-install", DetRand("wifi"))
        val empty = MemoryFolder()
        assertEquals("not-joined", reason { FolderSync(empty, "phone-install").addFolderToGroup(MemoryStore(), password, "Phone", false, DetRand("x"), FixedClock(T0), yes, cheap) })
        val store = MemoryStore(StoreSnapshot(sync = wifi))
        assertEquals("rejoin-required", reason { FolderSync(empty, "other-install").addFolderToGroup(store, password, "Phone", false, DetRand("x"), FixedClock(T0), yes, cheap) })
        assertEquals("weak-password", reason { FolderSync(empty, "phone-install").addFolderToGroup(store, password, "Phone", false, DetRand("x"), FixedClock(T0), { false }, cheap) })
        // A folder that holds another group.
        val other = MemoryFolder()
        val otherGroup = LanPeers.createWifiGroup("o", DetRand("other"))
        FolderSync(other, "o").addFolderToGroup(MemoryStore(StoreSnapshot(sync = otherGroup)), password, "Other", false, DetRand("o"), FixedClock(T0), yes, cheap)
        val before = other.read(KEYRING_PATH, 1 shl 20)
        assertEquals("folder-has-other-group", reason { FolderSync(other, "phone-install").addFolderToGroup(store, password, "Phone", false, DetRand("x"), FixedClock(T0), yes, cheap) })
        assertContentEquals(before, other.read(KEYRING_PATH, 1 shl 20))
        assertEquals(0, store.commits)
        // A failed commit takes the keyring back.
        store.failCommits = true
        assertEquals("store-offline", reason { FolderSync(empty, "phone-install").addFolderToGroup(store, password, "Phone", false, DetRand("x"), FixedClock(T0), yes, cheap) })
        assertFalse(empty.exists(KEYRING_PATH))
    }

    @Test fun a_removed_wifi_peer_needs_a_fresh_key() {
        val wifi = LanPeers.createWifiGroup("phone-install", DetRand("wifi2"))
        val removed = wifi.copy(
            lanPeers = listOf(LanPeer("gone-1", wifi.groupId, signingPublic = ByteArray(32) { 1 }, exchangePublic = ByteArray(32) { 2 }, revoked = true)),
        )
        val store = MemoryStore(StoreSnapshot(sync = removed))
        val folder = MemoryFolder()
        val fs = FolderSync(folder, "phone-install")
        assertEquals("lan-peer-removed", reason { fs.addFolderToGroup(store, password, "Phone", false, DetRand("x"), FixedClock(T0), yes, cheap) })
        assertEquals(0, store.commits)
        assertFalse(folder.exists(KEYRING_PATH))
        fs.addFolderToGroup(store, password, "Phone", true, DetRand("fresh"), FixedClock(T0), yes, cheap)
        val s = store.snapshot.sync!!
        assertEquals(2, s.epoch)
        assertFalse(s.key.contentEquals(removed.key))
        assertEquals(removed.groupId, s.groupId)
        assertNotEquals(removed.groupKey(), s.groupKey())
        assertEquals(s.groupKey(), Keyring.accept(Keyring.parse(folder.read(KEYRING_PATH, 1 shl 20)), s.groupKey(), s.identity))
    }
}
