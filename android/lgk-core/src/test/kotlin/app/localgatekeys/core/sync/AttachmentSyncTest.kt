package app.localgatekeys.core.sync

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.support.Vectors
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The shared vectors `tests/vectors/sync/attachments/vectors.json`, byte for byte. */
class AttachmentSyncTest {
    private val v = Vectors.json(Vectors.sync("attachments/vectors.json")).obj().fields

    private fun b64(s: String) = Base64Std.decodeStrict(s)

    private fun Map<String, JsonValue>.s(k: String) = getValue(k).str()

    private fun Map<String, JsonValue>.i(k: String) = (getValue(k) as JsonValue.Int).v

    @Test fun constants_match() {
        val c = v.getValue("constants").obj().fields
        assertEquals(c.i("max_blob_bytes"), AttachmentSync.MAX_BLOB_BYTES.toLong())
        assertEquals(c.i("max_file_bytes"), AttachmentSync.MAX_FILE_BYTES.toLong())
        assertEquals(c.i("pad_block"), AttachmentSync.PAD_BLOCK.toLong())
        assertEquals(c.i("chunk_bytes"), AttachmentSync.CHUNK_BYTES.toLong())
        assertEquals(c.i("max_attachments"), AttachmentSync.MAX_ATTACHMENTS.toLong())
        assertEquals(c.i("sweep_min_age_seconds"), AttachmentSync.SWEEP_MIN_AGE_SECONDS)
        assertEquals(c.s("blob_magic"), String(AttachmentSync.BLOB_MAGIC, Charsets.US_ASCII))
        assertEquals(c.s("blob_aad"), AttachmentSync.BLOB_AAD)
        assertEquals(c.s("nonce_label"), AttachmentSync.NONCE_LABEL)
        assertEquals(1L, (v.getValue("format") as JsonValue.Int).v)
    }

    @Test fun blobs_seal_and_open_byte_for_byte() {
        val rows = v.getValue("blobs").arr()
        assertEquals(5, rows.size)
        for (row in rows) {
            val r = row.obj().fields
            val name = r.s("name")
            val key = b64(r.s("key"))
            val id = r.s("attachment_id")
            val data = b64(r.s("plaintext"))
            val blob = AttachmentSync.sealBlob(key, id, data)
            assertContentEquals(b64(r.s("blob")), blob, name)
            assertEquals(r.s("blob_id"), AttachmentSync.blobId(blob), name)
            assertEquals(r.i("blob_size"), blob.size.toLong(), name)
            assertEquals(r.i("padded_length"), AttachmentSync.paddedLength(data.size.toLong()), name)
            assertEquals(r.s("nonce"), Vectors.hexString(AttachmentSync.blobNonce(key, id, data)), name)
            assertEquals(r.s("plaintext_sha256"), Vectors.hexString(AttachmentSync.sha256(data)), name)
            val ref = AttachmentRef.fromJson(r.getValue("ref"))
            assertEquals(r.s("ref_canonical"), String(CanonicalJson.encode(ref.toJson(), Dialect.UTF8), Charsets.UTF_8), name)
            assertContentEquals(data, AttachmentSync.openBlob(blob, ref), name)
            val (sealedRef, again) = AttachmentRef.seal(id, ref.name, ref.mimeType, key, data)
            assertEquals(ref, sealedRef, name)
            assertContentEquals(blob, again, name)
        }
    }

    @Test fun refused_blobs_give_the_vector_reason() {
        val rows = v.getValue("refused_blobs").arr()
        assertEquals(7, rows.size)
        for (row in rows) {
            val r = row.obj().fields
            val ref = AttachmentRef.fromJson(r.getValue("ref"))
            val e = assertFailsWith<AttachmentSyncException>(r.s("name")) { AttachmentSync.openBlob(b64(r.s("blob")), ref) }
            assertEquals(r.s("reason"), e.reason, r.s("name"))
        }
    }

    @Test fun refused_refs_are_refused() {
        val rows = v.getValue("refused_refs").arr()
        assertEquals(9, rows.size)
        for (row in rows) assertFailsWith<AttachmentSyncException>(row.toString()) { AttachmentRef.fromJson(row) }
    }

    @Test fun lan_messages_byte_for_byte() {
        val lan = v.getValue("lan").obj().fields
        val two = v.getValue("blobs").arr().map { it.obj().fields }.first { it.s("name") == "two-buckets" }
        val blob = b64(two.s("blob"))
        val id = two.s("blob_id")
        assertEquals(lan.s("blob_get"), String(AttachmentSync.blobGet(id, 0), Charsets.US_ASCII))
        val chunks = lan.getValue("chunks").arr().map { it.str() }
        assertEquals(chunks.size, (blob.size + AttachmentSync.CHUNK_BYTES - 1) / AttachmentSync.CHUNK_BYTES)
        val dl = AttachmentSync.BlobDownload(AttachmentRef.fromJson(two.getValue("ref")))
        var whole: ByteArray? = null
        for ((seq, text) in chunks.withIndex()) {
            assertEquals(text, String(AttachmentSync.blobChunk(blob, seq), Charsets.US_ASCII))
            whole = dl.add(CanonicalJson.parse(text.toByteArray()).obj().fields)
        }
        assertContentEquals(blob, whole)
        assertNull(AttachmentSync.parseMessage(CanonicalJson.parse(lan.s("blob_get").toByteArray()).obj().fields))
    }

    @Test fun download_refuses_wrong_chunks() {
        val two = v.getValue("blobs").arr().map { it.obj().fields }.first { it.s("name") == "two-buckets" }
        val blob = b64(two.s("blob"))
        val ref = AttachmentRef.fromJson(two.getValue("ref"))
        val chunk = CanonicalJson.parse(AttachmentSync.blobChunk(blob, 0)).obj().fields
        val bad = LinkedHashMap(chunk)
        bad["seq"] = JsonValue.Int(1)
        assertFailsWith<AttachmentSyncException> { AttachmentSync.BlobDownload(ref).add(bad) }
        val extra = LinkedHashMap(chunk)
        extra["x"] = JsonValue.Int(1)
        assertFailsWith<AttachmentSyncException> { AttachmentSync.BlobDownload(ref).add(extra) }
        val flipped = blob.copyOf().also { it[100] = (it[100].toInt() xor 1).toByte() }
        val forged = CanonicalJson.parse(AttachmentSync.blobChunk(flipped, 0)).obj().fields.toMutableMap()
        forged["blob"] = JsonValue.Str(ref.blob)
        val e = assertFailsWith<AttachmentSyncException> { AttachmentSync.BlobDownload(ref).add(forged) }
        assertEquals("tampered", e.reason)
    }

    @Test fun directory_vault_stores_verifies_and_collects() {
        val dir = Files.createTempDirectory("lgk-att").toFile()
        try {
            val vault = DirectoryAttachmentVault(File(dir, "attachments"))
            val r = v.getValue("blobs").arr().map { it.obj().fields }.first { it.s("name") == "small" }
            val ref = AttachmentRef.fromJson(r.getValue("ref"))
            val blob = b64(r.s("blob"))
            assertFalse(vault.has(ref))
            val tampered = blob.copyOf().also { it[50] = (it[50].toInt() xor 1).toByte() }
            assertFailsWith<AttachmentSyncException> { vault.store(ref, tampered) }
            assertFalse(vault.has(ref))
            vault.store(ref, blob)
            assertTrue(vault.has(ref))
            assertContentEquals(blob, vault.blob(ref))
            assertContentEquals(b64(r.s("plaintext")), vault.open(ref))
            val wrapper = JsonValue.Obj(
                mapOf(
                    "ns" to JsonValue.Str("item"),
                    "record" to JsonValue.Obj(mapOf("kind" to JsonValue.Str("document"))),
                    "attachment" to ref.toJson(),
                ),
            )
            assertEquals(0, vault.collectGarbage(mapOf("a" to wrapper), System.currentTimeMillis() + 3_600_000))
            assertNotNull(vault.blob(ref))
            assertEquals(1, vault.collectGarbage(emptyMap(), System.currentTimeMillis() + 3_600_000))
            assertFalse(vault.has(ref))
        } finally {
            dir.deleteRecursively()
        }
    }
}
