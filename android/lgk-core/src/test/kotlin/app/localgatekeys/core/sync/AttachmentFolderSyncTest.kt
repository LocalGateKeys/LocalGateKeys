package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.group.ViewSignature
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MemoryFolder
import app.localgatekeys.core.support.MemoryStore
import app.localgatekeys.core.support.MergeVectors.A
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.SyncFixtures.INSTALL
import app.localgatekeys.core.support.SyncFixtures.T0
import app.localgatekeys.core.support.SyncFixtures.devPath
import app.localgatekeys.core.support.SyncFixtures.epochKey
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Folder transport with attachments (desktop `tests/test_attachment_sync_e2e.py`, folder half). */
class AttachmentFolderSyncTest {
    private val tmp: File = Files.createTempDirectory("lgk-att-folder").toFile()

    @AfterTest fun cleanup() {
        tmp.deleteRecursively()
    }

    private val docId = "7a1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5"
    private val attId = "6f1c2d3e-4b5a-4c6d-8e7f-90a1b2c3d4e5"
    private val key = ByteArray(32) { it.toByte() }
    private val sealed = AttachmentRef.seal(attId, "passport.pdf", "application/pdf", key, "synthetic passport scan\n".toByteArray())
    private val ref = sealed.first
    private val blob = sealed.second

    private fun documentWrapper(id: String = docId, r: AttachmentRef = ref): JsonValue {
        val record = JsonValue.Obj(
            mapOf(
                "id" to JsonValue.Str(id), "kind" to JsonValue.Str("document"), "title" to JsonValue.Str("Passport"),
                "created_at" to JsonValue.Int(T0), "updated_at" to JsonValue.Int(T0), "favorite" to JsonValue.Bool(false),
                "tags" to JsonValue.Arr(emptyList()),
                "payload" to JsonValue.Obj(
                    mapOf(
                        "attachment_id" to JsonValue.Str(r.attachmentId), "description" to JsonValue.Str(""),
                        "template_id" to JsonValue.Null,
                    ),
                ),
            ),
        )
        return JsonValue.Obj(
            mapOf(
                "ns" to JsonValue.Str("item"), "schema" to JsonValue.Int(1), "updated_at" to JsonValue.Int(T0),
                "record" to record, "attachment" to r.toJson(),
            ),
        )
    }

    private class Phone(val folder: MemoryFolder, val store: MemoryStore, val fs: FolderSync, val vault: DirectoryAttachmentVault)

    private fun phone(): Phone {
        val folder = SyncFixtures.seededFolder(signed = true)
        val store = MemoryStore()
        val vault = DirectoryAttachmentVault(File(tmp, "phone"))
        val fs = FolderSync(folder, INSTALL, attachments = vault)
        fs.join(store, "Pixel", DetRand("att|join"), FixedClock(T0 + 1000)) { SyncFixtures.pwKey("1") }
        return Phone(folder, store, fs, vault)
    }

    /** Rewrites A's view (counter 8) with one more state, signed by A. */
    private fun addToA(folder: MemoryFolder, extra: ItemState) {
        val a = ViewFile.decode(folder.files[devPath(A)]!!, epochKey("1"), A)
        val raw = ViewFile.encode(epochKey("1"), A, 8, a.second + extra, FixedClock(T0 + 1050), DetRand("a8"))
        folder.files[devPath(A)] = raw
        folder.files[FolderLayout.signatureFile(A)!!] = ViewSignature.sign(raw, ViewFile.decodeHeader(raw), SyncFixtures.identity("A"))
    }

    private fun capable(folder: MemoryFolder, who: String, id: String) {
        val raw = ViewFile.encode(epochKey("1"), id, 0, emptyList(), FixedClock(T0 + 1000), DetRand("cap$who"))
        folder.files[FolderLayout.capabilityFile(id)!!] = raw
        folder.files[FolderLayout.capabilitySignatureFile(id)!!] = ViewSignature.sign(raw, ViewFile.decodeHeader(raw), SyncFixtures.identity(who))
    }

    @Test fun received_document_waits_for_its_file_then_applies() {
        val p = phone()
        val me = p.store.snapshot.sync!!.deviceId
        assertNotNull(p.folder.files[FolderLayout.capabilityFile(me)!!], "the phone announces support")
        assertTrue(p.fs.folderCapable(epochKey("1"), me, app.localgatekeys.core.primitives.Base64Std.encode(p.store.snapshot.sync!!.identity.signingPublicKey)))
        addToA(p.folder, ItemState(docId, mapOf(A to 1L), false, null, documentWrapper()))
        var r = p.fs.runOnce(p.store, DetRand("r1"), FixedClock(T0 + 1100))
        assertTrue(r.issues.any { it.kind == "attachment-missing" }, r.issues.toString())
        assertNull(p.store.snapshot.records[docId])
        // The blob arrives in the folder: imported, then the item is stored.
        p.folder.files[FolderLayout.blobFile(ref.blob)!!] = blob
        r = p.fs.runOnce(p.store, DetRand("r2"), FixedClock(T0 + 1200))
        assertFalse(r.issues.any { it.kind.startsWith("attachment") }, r.issues.toString())
        assertNotNull(p.store.snapshot.records[docId])
        assertTrue(p.vault.has(ref))
    }

    @Test fun tampered_folder_blob_is_never_stored() {
        val p = phone()
        addToA(p.folder, ItemState(docId, mapOf(A to 1L), false, null, documentWrapper()))
        val bad = blob.copyOf().also { it[40] = (it[40].toInt() xor 1).toByte() }
        p.folder.files[FolderLayout.blobFile(ref.blob)!!] = bad
        val r = p.fs.runOnce(p.store, DetRand("r1"), FixedClock(T0 + 1100))
        assertTrue(r.issues.any { it.kind == "attachment-missing" }, r.issues.toString())
        assertFalse(p.vault.has(ref))
        assertNull(p.store.snapshot.records[docId])
    }

    @Test fun own_documents_wait_until_every_member_is_capable() {
        val p = phone()
        val me = p.store.snapshot.sync!!.deviceId
        p.vault.store(ref, blob)
        val snap = p.store.snapshot
        p.store.snapshot = snap.copy(records = snap.records + (docId to documentWrapper()), revision = snap.revision)
        p.fs.runOnce(p.store, DetRand("r1"), FixedClock(T0 + 1100))
        var own = ViewFile.decode(p.folder.files[devPath(me)]!!, epochKey("1"), me).second
        assertFalse(own.any { it.itemId == docId }, "not published while A, B and C cannot read documents")
        assertNull(p.folder.files[FolderLayout.blobFile(ref.blob)!!])
        // A forged capability (C's file signed by A) does not count.
        capable(p.folder, "A", A)
        capable(p.folder, "B", SyncFixtures.devices[1].id)
        val forged = ViewFile.encode(epochKey("1"), SyncFixtures.devices[2].id, 0, emptyList(), FixedClock(T0), DetRand("f"))
        p.folder.files[FolderLayout.capabilityFile(SyncFixtures.devices[2].id)!!] = forged
        p.folder.files[FolderLayout.capabilitySignatureFile(SyncFixtures.devices[2].id)!!] =
            ViewSignature.sign(forged, ViewFile.decodeHeader(forged), SyncFixtures.identity("A"))
        p.fs.runOnce(p.store, DetRand("r2"), FixedClock(T0 + 1200))
        own = ViewFile.decode(p.folder.files[devPath(me)]!!, epochKey("1"), me).second
        assertFalse(own.any { it.itemId == docId })
        capable(p.folder, "C", SyncFixtures.devices[2].id)
        p.fs.runOnce(p.store, DetRand("r3"), FixedClock(T0 + 1300))
        own = ViewFile.decode(p.folder.files[devPath(me)]!!, epochKey("1"), me).second
        assertTrue(own.any { it.itemId == docId }, "published once every member is capable")
        assertEquals(blob.toList(), p.folder.files[FolderLayout.blobFile(ref.blob)!!]!!.toList(), "blob written with the view")
    }

    @Test fun without_a_vault_documents_stay_refused_as_before() {
        val r = SyncRunner.run(
            app.localgatekeys.core.sync.StoreSnapshot(),
            listOf(PeerView(A, listOf(ItemState(docId, mapOf(A to 1L), false, null, documentWrapper())))),
            SyncFixtures.PHONE, T0,
        )
        assertEquals(listOf("bad-peer-record"), r.issues.map { it.kind })
        val ok = SyncRunner.run(
            app.localgatekeys.core.sync.StoreSnapshot(),
            listOf(PeerView(A, listOf(ItemState(docId, mapOf(A to 1L), false, null, documentWrapper())))),
            SyncFixtures.PHONE, T0, documents = { true },
        )
        assertEquals(emptyList(), ok.issues)
        assertNotNull(ok.records?.get(docId))
        // Republished byte for byte, the attachment reference included.
        val again = SyncMeta.localView(ok.records!!, ok.meta!!, SyncFixtures.PHONE, T0).states.getValue(docId)
        assertEquals(documentWrapper(), again.item)
    }
}
