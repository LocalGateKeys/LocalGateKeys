package app.localgatekeys.core.sync

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.CryptoBoxException
import app.localgatekeys.core.primitives.Hex
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** A blob, reference or message was refused; [reason] is the stable code the shared vectors use. */
class AttachmentSyncException(val reason: String, val detail: String = "") :
    Exception(if (detail.isEmpty()) reason else "$reason: $detail")

/**
 * Synced file attachments, format 1 (desktop `sync/attachment_sync.py`; docs/SYNC.md
 * "Documents and files"). Byte for byte with `tests/vectors/sync/attachments/`.
 *
 * Blob: `"LGKABLB1" || nonce || AES-256-GCM(k, nonce, u64be(len) || data || zero pad to 64 KiB, "lgk-sync-attachment-v1|" || id)`,
 * `nonce = HMAC-SHA256(k, "lgk-sync-attachment-nonce-v1|" || id || "|" || sha256(data))[0:12]`, blob id = hex sha256(blob).
 */
object AttachmentSync {
    const val FORMAT = 1
    val BLOB_MAGIC: ByteArray = "LGKABLB1".toByteArray(Charsets.US_ASCII)
    const val BLOB_AAD = "lgk-sync-attachment-v1|"
    const val NONCE_LABEL = "lgk-sync-attachment-nonce-v1|"
    const val PAD_BLOCK = 64 * 1024
    const val MAX_FILE_BYTES = 25 * 1024 * 1024
    const val MAX_ATTACHMENTS = 500
    const val CHUNK_BYTES = 512 * 1024
    const val SWEEP_MIN_AGE_SECONDS: Long = 7 * 86400
    const val BLOBS_DIR_NAME = "attachments"
    const val BLOB_SUFFIX = ".lgkblob"
    const val CAP_SUFFIX = ".lgkcap"
    const val CAP_SIG_SUFFIX = ".lgkcap.lgksig"
    const val MAX_CAP_BYTES = 4096
    const val MAX_NAME = 255
    const val MAX_MIME = 255
    private const val KEY_LEN = 32
    private const val NONCE_LEN = 12
    private const val TAG_LEN = 16
    private const val LEN_PREFIX = 8
    private val HEADER = BLOB_MAGIC.size + NONCE_LEN

    val MAX_BLOB_BYTES: Int = HEADER + paddedLength(MAX_FILE_BYTES.toLong()).toInt() + TAG_LEN
    val MIN_BLOB_BYTES: Int = HEADER + PAD_BLOCK + TAG_LEN
    val MAX_CHUNKS: Int = (MAX_BLOB_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES

    /** The blob id of the `0` x 64 probe (`blob-get` asked only to learn whether the peer knows the message). */
    val PROBE_ID: String = "0".repeat(64)

    // ---- small checks ------------------------------------------------------------------------

    fun isBlobId(v: String?): Boolean = v != null && v.length == 64 && v.all { it in '0'..'9' || it in 'a'..'f' }

    private val uuidRe = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    /** Canonical lowercase 8-4-4-4-12 (what Python's `str(uuid.UUID(v)) == v` accepts). */
    fun isCanonicalUuid(v: String?): Boolean = v != null && uuidRe.matches(v)

    fun paddedLength(size: Long): Long = (LEN_PREFIX + size + PAD_BLOCK - 1) / PAD_BLOCK * PAD_BLOCK

    fun blobSizeFor(size: Long): Long = HEADER + paddedLength(size) + TAG_LEN

    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    fun blobId(blob: ByteArray): String = Hex.lower(sha256(blob))

    private fun ctEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    private fun ctEquals(a: String, b: String): Boolean =
        MessageDigest.isEqual(a.toByteArray(Charsets.US_ASCII), b.toByteArray(Charsets.US_ASCII))

    private fun checkKey(key: ByteArray): ByteArray {
        if (key.size != KEY_LEN) throw AttachmentSyncException("bad-key")
        return key
    }

    // ---- blob --------------------------------------------------------------------------------

    fun blobNonce(key: ByteArray, attachmentId: String, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(checkKey(key), "HmacSHA256"))
        mac.update((NONCE_LABEL + attachmentId + "|").toByteArray(Charsets.US_ASCII))
        mac.update(sha256(data))
        return mac.doFinal().copyOf(NONCE_LEN)
    }

    fun sealBlob(key: ByteArray, attachmentId: String, data: ByteArray): ByteArray {
        checkKey(key)
        if (!isCanonicalUuid(attachmentId)) throw AttachmentSyncException("bad-ref", "attachment id")
        if (data.size > MAX_FILE_BYTES) throw AttachmentSyncException("too-large")
        val frame = ByteArray(paddedLength(data.size.toLong()).toInt())
        val n = data.size.toLong()
        for (i in 0 until LEN_PREFIX) frame[i] = (n ushr (8 * (LEN_PREFIX - 1 - i))).toByte()
        data.copyInto(frame, LEN_PREFIX)
        val nonce = blobNonce(key, attachmentId, data)
        val sealed = CryptoBox.sealGcm(key, nonce, frame, (BLOB_AAD + attachmentId).toByteArray(Charsets.US_ASCII))
        frame.fill(0)
        return BLOB_MAGIC + nonce + sealed
    }

    /** Size, magic and (when given) content address; no key needed. */
    fun checkBlobShape(blob: ByteArray, expectedId: String? = null): ByteArray {
        if (blob.size < MIN_BLOB_BYTES || blob.size > MAX_BLOB_BYTES) throw AttachmentSyncException("bad-blob", "size")
        if ((blob.size - HEADER - TAG_LEN) % PAD_BLOCK != 0) throw AttachmentSyncException("bad-blob", "size")
        if (!ctEquals(blob.copyOf(BLOB_MAGIC.size), BLOB_MAGIC)) throw AttachmentSyncException("bad-blob", "magic")
        if (expectedId != null) {
            if (!isBlobId(expectedId)) throw AttachmentSyncException("bad-blob-id")
            if (!ctEquals(blobId(blob), expectedId)) throw AttachmentSyncException("tampered", "content address")
        }
        return blob
    }

    /** Verifies [blob] against [ref] (the seven steps of the plan, in order) and returns the file bytes. */
    fun openBlob(blob: ByteArray, ref: AttachmentRef): ByteArray {
        checkBlobShape(blob, ref.blob)
        if (blob.size.toLong() != ref.blobSize || blob.size.toLong() != blobSizeFor(ref.size)) {
            throw AttachmentSyncException("tampered", "length")
        }
        val nonce = blob.copyOfRange(BLOB_MAGIC.size, HEADER)
        val key = ref.key
        val frame = try {
            CryptoBox.openGcm(key, nonce, blob.copyOfRange(HEADER, blob.size), (BLOB_AAD + ref.attachmentId).toByteArray(Charsets.US_ASCII))
        } catch (e: CryptoBoxException) {
            throw AttachmentSyncException("tampered", "authentication")
        }
        var size = 0L
        for (i in 0 until LEN_PREFIX) size = (size shl 8) or (frame[i].toLong() and 0xFF)
        if (size != ref.size) throw AttachmentSyncException("tampered", "frame")
        for (i in (LEN_PREFIX + size.toInt()) until frame.size) if (frame[i].toInt() != 0) throw AttachmentSyncException("tampered", "frame")
        val data = frame.copyOfRange(LEN_PREFIX, LEN_PREFIX + size.toInt())
        frame.fill(0)
        if (!ctEquals(Hex.lower(sha256(data)), ref.sha256)) throw AttachmentSyncException("tampered", "digest")
        if (!ctEquals(nonce, blobNonce(key, ref.attachmentId, data))) throw AttachmentSyncException("tampered", "nonce")
        return data
    }

    // ---- references --------------------------------------------------------------------------

    /** One reference per attachment id (a conflicting second is an issue), at most [MAX_ATTACHMENTS]. */
    fun uniqueRefs(refs: Iterable<AttachmentRef>): Pair<List<AttachmentRef>, List<SyncIssue>> {
        val seen = LinkedHashMap<String, AttachmentRef>()
        val issues = ArrayList<SyncIssue>()
        for (ref in refs) {
            val known = seen[ref.attachmentId]
            if (known == null) {
                if (seen.size >= MAX_ATTACHMENTS) {
                    issues.add(SyncIssue("too-many-attachments", "$MAX_ATTACHMENTS"))
                    break
                }
                seen[ref.attachmentId] = ref
            } else if (known != ref) {
                issues.add(SyncIssue("attachment-refused", "${ref.attachmentId}: two different files"))
            }
        }
        return seen.values.toList() to issues
    }

    // ---- Wi-Fi messages ----------------------------------------------------------------------

    fun encodeMessage(o: Map<String, JsonValue>): ByteArray = CanonicalJson.encode(JsonValue.Obj(o), Dialect.ASCII)

    fun blobGet(blob: String, seq: Int = 0): ByteArray {
        if (!isBlobId(blob)) throw AttachmentSyncException("bad-blob-id")
        return encodeMessage(mapOf("type" to JsonValue.Str("blob-get"), "blob" to JsonValue.Str(blob), "seq" to JsonValue.Int(seq.toLong())))
    }

    fun blobChunk(blob: ByteArray, seq: Int): ByteArray {
        checkBlobShape(blob)
        val total = (blob.size + CHUNK_BYTES - 1) / CHUNK_BYTES
        if (seq !in 0 until total) throw AttachmentSyncException("bad-chunk")
        val part = blob.copyOfRange(seq * CHUNK_BYTES, minOf(blob.size, (seq + 1) * CHUNK_BYTES))
        return encodeMessage(
            mapOf(
                "type" to JsonValue.Str("blob"), "blob" to JsonValue.Str(blobId(blob)), "seq" to JsonValue.Int(seq.toLong()),
                "total" to JsonValue.Int(total.toLong()), "size" to JsonValue.Int(blob.size.toLong()),
                "data" to JsonValue.Str(Base64Std.encode(part)),
            ),
        )
    }

    private val msgFields = mapOf(
        "blob-get" to setOf("type", "blob", "seq"),
        "blob" to setOf("type", "blob", "seq", "total", "size", "data"),
    )

    /** One parsed `blob` message. */
    class Chunk(val blob: String, val seq: Int, val total: Int, val size: Int, val data: String)

    /** Shape-checks a parsed `blob-get` (returns null) or `blob` message; throws `bad-message` / `too-large`. */
    fun parseMessage(o: Map<String, JsonValue>): Chunk? {
        val type = (o["type"] as? JsonValue.Str)?.v
        val want = msgFields[type] ?: throw AttachmentSyncException("bad-message")
        if (o.keys != want) throw AttachmentSyncException("bad-message")
        val blob = (o["blob"] as? JsonValue.Str)?.v
        val seq = (o["seq"] as? JsonValue.Int)?.v
        if (!isBlobId(blob) || seq == null || seq !in 0 until MAX_CHUNKS) throw AttachmentSyncException("bad-message")
        if (type == "blob-get") return null
        val size = (o["size"] as? JsonValue.Int)?.v
        if (size == null || size !in MIN_BLOB_BYTES..MAX_BLOB_BYTES) throw AttachmentSyncException("too-large")
        val total = (o["total"] as? JsonValue.Int)?.v
        if (total != (size + CHUNK_BYTES - 1) / CHUNK_BYTES || seq >= total) throw AttachmentSyncException("bad-message")
        val data = (o["data"] as? JsonValue.Str)?.v
        if (data == null || data.length > 4 * ((CHUNK_BYTES + 2) / 3)) throw AttachmentSyncException("too-large")
        return Chunk(blob!!, seq.toInt(), total.toInt(), size.toInt(), data)
    }

    /** Collects the chunks of one blob in order and verifies the content address at the end (desktop `BlobDownload`). */
    class BlobDownload(val ref: AttachmentRef) {
        private val parts = java.io.ByteArrayOutputStream()
        var nextSeq = 0
            private set
        private var total: Int? = null

        /** The whole blob after the last chunk, else null. */
        fun add(message: Map<String, JsonValue>): ByteArray? {
            val c = parseMessage(message) ?: throw AttachmentSyncException("bad-chunk")
            if (c.blob != ref.blob || c.size.toLong() != ref.blobSize) throw AttachmentSyncException("bad-chunk")
            if (c.seq != nextSeq || (total != null && c.total != total)) throw AttachmentSyncException("bad-chunk")
            val part = try {
                Base64Std.decodeStrict(c.data)
            } catch (e: Base64Exception) {
                throw AttachmentSyncException("bad-ref", "chunk")
            }
            if (part.size != minOf(CHUNK_BYTES, c.size - c.seq * CHUNK_BYTES)) throw AttachmentSyncException("bad-chunk")
            total = c.total
            parts.write(part)
            nextSeq++
            if (nextSeq < c.total) return null
            return checkBlobShape(parts.toByteArray(), ref.blob)
        }
    }
}

/**
 * The reference a synced `document` wrapper carries under `"attachment"` (exactly these keys). [key] is copied in and
 * out; [toString] never shows it.
 */
class AttachmentRef(
    val attachmentId: String,
    val blob: String,
    val blobSize: Long,
    val name: String,
    val mimeType: String,
    val size: Long,
    val sha256: String,
    key: ByteArray,
) {
    private val keyBytes = key.copyOf()
    val key: ByteArray get() = keyBytes.copyOf()

    init {
        if (!AttachmentSync.isCanonicalUuid(attachmentId)) throw AttachmentSyncException("bad-ref", "attachment id")
        if (!AttachmentSync.isBlobId(blob)) throw AttachmentSyncException("bad-blob-id")
        text(name, "name", AttachmentSync.MAX_NAME)
        if (name == "." || name == ".." || name.contains('/') || name.contains('\\')) throw AttachmentSyncException("bad-ref", "name")
        text(mimeType, "mime type", AttachmentSync.MAX_MIME)
        if (size !in 0..AttachmentSync.MAX_FILE_BYTES.toLong()) throw AttachmentSyncException("bad-ref", "size")
        if (blobSize != AttachmentSync.blobSizeFor(size)) throw AttachmentSyncException("bad-ref", "blob size")
        if (!AttachmentSync.isBlobId(sha256)) throw AttachmentSyncException("bad-ref", "sha256")
        if (keyBytes.size != 32) throw AttachmentSyncException("bad-key")
    }

    fun toJson(): JsonValue = JsonValue.Obj(
        mapOf(
            "blob" to JsonValue.Str(blob), "blob_size" to JsonValue.Int(blobSize), "id" to JsonValue.Str(attachmentId),
            "key" to JsonValue.Str(Base64Std.encode(keyBytes)), "mime_type" to JsonValue.Str(mimeType),
            "name" to JsonValue.Str(name), "sha256" to JsonValue.Str(sha256), "size" to JsonValue.Int(size),
        ),
    )

    override fun equals(other: Any?): Boolean =
        other is AttachmentRef && attachmentId == other.attachmentId && blob == other.blob && blobSize == other.blobSize &&
            name == other.name && mimeType == other.mimeType && size == other.size && sha256 == other.sha256 &&
            keyBytes.contentEquals(other.keyBytes)

    override fun hashCode(): Int = attachmentId.hashCode() * 31 + blob.hashCode()

    /** Never shows the key or the name. */
    override fun toString(): String = "AttachmentRef(id=$attachmentId, blob=$blob, size=$size)"

    companion object {
        val FIELDS = setOf("id", "blob", "blob_size", "name", "mime_type", "size", "sha256", "key")

        private fun text(v: String, what: String, limit: Int) {
            if (v.isEmpty() || v.codePointCount(0, v.length) > limit || v.any { it.code < 32 || it.code == 127 }) {
                throw AttachmentSyncException("bad-ref", what)
            }
        }

        /** Strict parse; throws `bad-ref` (or `bad-blob-id`) for anything else. */
        fun fromJson(v: JsonValue?): AttachmentRef {
            val o = (v as? JsonValue.Obj)?.fields
            if (o == null || o.keys != FIELDS) throw AttachmentSyncException("bad-ref", "fields")
            fun s(k: String): String = (o[k] as? JsonValue.Str)?.v ?: throw AttachmentSyncException("bad-ref", k)
            fun i(k: String): Long = (o[k] as? JsonValue.Int)?.v ?: throw AttachmentSyncException("bad-ref", k)
            val key = try {
                Base64Std.decodeStrict(s("key"))
            } catch (e: Base64Exception) {
                throw AttachmentSyncException("bad-ref", "key")
            }
            if (key.size != 32 || Base64Std.encode(key) != s("key")) throw AttachmentSyncException("bad-ref", "key")
            val blob = s("blob")
            if (!AttachmentSync.isBlobId(blob)) throw AttachmentSyncException("bad-ref", "blob")
            return AttachmentRef(s("id"), blob, i("blob_size"), s("name"), s("mime_type"), i("size"), s("sha256"), key)
        }

        /** The reference for [data] sealed under [key] (the sealed blob is returned too). */
        fun seal(attachmentId: String, name: String, mimeType: String, key: ByteArray, data: ByteArray): Pair<AttachmentRef, ByteArray> {
            val blob = AttachmentSync.sealBlob(key, attachmentId, data)
            val ref = AttachmentRef(
                attachmentId, AttachmentSync.blobId(blob), blob.size.toLong(), name, mimeType, data.size.toLong(),
                Hex.lower(AttachmentSync.sha256(data)), key,
            )
            return ref to blob
        }
    }
}
