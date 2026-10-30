package app.localgatekeys.android.attachments

import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.sync.FolderOpening
import app.localgatekeys.android.sync.LanTransporting
import app.localgatekeys.android.sync.LockedStore
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncDependencies
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.BlobFetch
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.PinnedPeer
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.sync.AttachmentRef
import app.localgatekeys.core.sync.DirectoryAttachmentVault
import app.localgatekeys.core.sync.Documents
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue

class DocumentStoreTest {
    @get:Rule val tmp = TemporaryFolder()

    private val clock = object : UnixClock { override val now: Long = 1_800_000_000 }

    private fun docs(store: LockedStore = LockedStore()) =
        DocumentStore(store, DirectoryAttachmentVault(File(tmp.root, "att")), SystemRandomSource(), clock) to store

    @Test fun add_needs_pro_and_respects_the_size_limit() {
        val (d, store) = docs()
        assertEquals(DocumentStore.AddResult.PRO_REQUIRED, d.add(ByteArray(3), "a.txt", "text/plain", "", false).first)
        assertEquals(DocumentStore.AddResult.TOO_LARGE, d.add(ByteArray(25 * 1024 * 1024 + 1), "a.bin", null, "", true).first)
        assertTrue(store.load().records.isEmpty())
    }

    @Test fun add_read_rename_delete() {
        val (d, store) = docs()
        val data = "synthetic passport scan\n".toByteArray()
        val (r, id) = d.add(data, "passport.pdf", "application/pdf", "", true)
        assertEquals(DocumentStore.AddResult.ADDED, r)
        val wrapper = store.load().records.getValue(id!!)
        val ref = Documents.refOf(wrapper)!!
        assertEquals("passport.pdf", ref.name)
        assertArrayEquals(data, d.read(id))
        // The file on disk is the sealed blob, never the plaintext.
        val onDisk = File(tmp.root, "att").listFiles()!!.single().readBytes()
        assertFalse(String(onDisk, Charsets.ISO_8859_1).contains("passport scan"))
        // It syncs: the local view publishes it with its reference, and the runner accepts it when the file is there.
        val state = SyncMeta.localView(store.load().records, emptyMap(), "d4444444-0000-4000-8000-00000000000d", clock.now).states.getValue(id)
        assertEquals(wrapper, state.item)
        assertEquals(SaveResult.SAVED, d.rename(id, "My passport"))
        assertEquals("passport.pdf", Documents.refOf(store.load().records[id])!!.name)
        assertEquals(SaveResult.SAVED, d.delete(id))
        assertNull(store.load().records[id])
        assertFalse(d.vault.has(ref))
    }

    @Test fun safe_names() {
        assertEquals("a_b", DocumentText.safeName("a/b"))
        assertEquals("document", DocumentText.safeName(".."))
        assertEquals("x_y", DocumentText.safeName("x\u0000y"))
        assertEquals("application/pdf", DocumentText.safeMime("bogus", "x.pdf"))
    }

    /** Wi-Fi: the phone fetches the file of a received document, then applies it, and marks the peer. */
    @Test fun lan_run_fetches_files_then_applies() = runBlocking {
        val src = docs(LockedStore()).first
        val (_, pcId) = src.add("from the PC".toByteArray(), "note.txt", "text/plain", "", true)
        val pcRecords = (src.vault to null).let { _ -> (srcStore(src)) }
        val pc = DeviceIdentity.generate(random = SystemRandomSource())
        val me = DeviceIdentity.generate(random = SystemRandomSource())
        val groupKey = GroupKey("5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64", 1, ByteArray(32) { 9 })
        val peerStates = SyncMeta.localView(pcRecords, emptyMap(), pc.deviceId, clock.now).states.values.toList()
        val ref = Documents.refs(peerStates).single()
        val blob = src.vault.blob(ref)!!
        var asked: List<AttachmentRef>? = null
        val lan = object : LanTransporting {
            override fun exchangeViews(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, localStates: List<ItemState>, ownCounter: Long) =
                peerStates
            override fun enroll(endpoint: LanEndpoint, request: ByteArray, onConnected: () -> Unit): ByteArray = error("no")
            override fun fetchBlobs(peer: PinnedPeer, identity: DeviceIdentity, groupKey: GroupKey, refs: List<AttachmentRef>, probe: Boolean): BlobFetch {
                asked = refs
                return BlobFetch(refs.associate { it.blob to blob }, capable = true)
            }
        }
        val slots = SecretSlots(tmp.newFile("secrets.bin").also { it.delete() }, ByteArray(32) { 3 }, SystemRandomSource())
        val installId = slots.installId()
        val store = LockedStore(StoreSnapshot(sync = SyncGroupState(groupKey.groupId, 1, groupKey.key, me, installId, hasFolder = false)))
        val vault = DirectoryAttachmentVault(File(tmp.root, "phone"))
        val deps = SyncDependencies(
            slots = slots, folders = FolderOpening.UNAVAILABLE, lan = lan, random = SystemRandomSource(), clock = clock,
            licenseKeys = emptyMap(), attachments = vault,
        )
        val peer = PinnedPeer(pc.deviceId, groupKey.groupId, pc.signingPublicKey, pc.exchangePublicKey, LanEndpoint("192.168.1.20", 47821))
        val report = SyncCoordinator.lanRun(store, deps, installId, peer)
        assertEquals(emptyList<String>(), report.issues.map { it.kind })
        assertEquals(listOf(ref), asked)
        assertTrue(vault.has(ref))
        assertNotNull(store.load().records[pcId])
        assertEquals(listOf(pc.deviceId), store.load().sync!!.attachmentPeers)
    }

    private fun srcStore(d: DocumentStore): Map<String, JsonValue> {
        val f = DocumentStore::class.java.getDeclaredField("store").apply { isAccessible = true }
        return (f.get(d) as LockedStore).load().records
    }
}
