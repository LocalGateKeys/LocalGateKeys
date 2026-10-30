package app.localgatekeys.android.attachments

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.AttachmentRef
import app.localgatekeys.core.sync.AttachmentSync
import app.localgatekeys.core.sync.AttachmentSyncException
import app.localgatekeys.core.sync.DirectoryAttachmentVault
import app.localgatekeys.core.sync.Documents
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import java.io.File
import java.util.UUID

/** What a document's file is, for the detail screen (never the key). */
data class DocumentInfo(val name: String, val mimeType: String, val size: Long, val stored: Boolean) {
    fun sizeText(t: Txt): String = DocumentText.size(size, t)
}

/**
 * Document items with an encrypted file (Task 12, desktop `DocumentService`): add, read, rename (title only, the stored
 * file name stays: owner decision 2026-10-29) and delete. The file is sealed under a fresh random key per attachment
 * ([AttachmentSync.sealBlob]); that key lives only inside the encrypted record's `attachment` reference, so the file on
 * disk is never readable without the unlocked vault. Blocking: call off the main thread.
 */
class DocumentStore(
    private val store: ItemStore,
    val vault: DirectoryAttachmentVault,
    private val random: RandomSource,
    private val clock: UnixClock,
) {
    enum class AddResult { ADDED, PRO_REQUIRED, TOO_LARGE, FAILED }

    /** The reference a stored document wrapper carries, or null. */
    fun ref(itemId: String): AttachmentRef? = try {
        Documents.refOf(store.load().records[itemId])
    } catch (e: Exception) {
        null
    }

    fun info(item: VaultItem): DocumentInfo? {
        val ref = ref(item.id) ?: return null
        return DocumentInfo(ref.name, ref.mimeType, ref.size, vault.has(ref))
    }

    /**
     * Adds [data] as a new document titled [title] (the file name when blank). Pro only, 25 MB per file. The file is
     * written before the record, so a committed record always has its file; a file whose record never committed is
     * removed by [collectGarbage] later.
     */
    fun add(data: ByteArray, fileName: String, mimeType: String?, title: String, isPro: Boolean): Pair<AddResult, String?> {
        if (!isPro) return AddResult.PRO_REQUIRED to null
        if (data.size > AttachmentSync.MAX_FILE_BYTES) return AddResult.TOO_LARGE to null
        return try {
            val name = DocumentText.safeName(fileName)
            val mime = DocumentText.safeMime(mimeType, name)
            val key = random.bytes(32)
            val attachmentId = uuid4()
            val (ref, blob) = AttachmentRef.seal(attachmentId, name, mime, key, data)
            key.fill(0)
            vault.store(ref, blob)
            val id = uuid4()
            val now = clock.now
            val record = JsonValue.Obj(
                mapOf(
                    "id" to JsonValue.Str(id), "kind" to JsonValue.Str(Documents.KIND),
                    "title" to JsonValue.Str(DocumentText.title(title, name)),
                    "created_at" to JsonValue.Int(now), "updated_at" to JsonValue.Int(now), "favorite" to JsonValue.Bool(false),
                    "tags" to JsonValue.Arr(emptyList()),
                    "payload" to JsonValue.Obj(
                        mapOf(
                            "attachment_id" to JsonValue.Str(attachmentId), "description" to JsonValue.Str(""),
                            "template_id" to JsonValue.Null,
                        ),
                    ),
                ),
            )
            val snap = store.load()
            val records = LinkedHashMap(snap.records)
            records[id] = wrap(record, ref)
            store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
            AddResult.ADDED to id
        } catch (e: Exception) {
            AddResult.FAILED to null
        }
    }

    /** The verified file bytes of [itemId]; throws [AttachmentSyncException] (`missing` while it waits for sync). */
    fun read(itemId: String): ByteArray {
        val ref = ref(itemId) ?: throw AttachmentSyncException("missing", "no document")
        return vault.open(ref)
    }

    /** Changes the title only (and the stamp); the stored file and its name stay. */
    fun rename(itemId: String, title: String): SaveResult {
        val t = title.trim()
        if (t.isEmpty() || t.codePointCount(0, t.length) > 512) return SaveResult.INVALID
        return try {
            val snap = store.load()
            val w = (snap.records[itemId] as? JsonValue.Obj)?.fields ?: return SaveResult.FAILED
            val r = (w["record"] as? JsonValue.Obj)?.fields ?: return SaveResult.FAILED
            val ref = Documents.refOf(snap.records[itemId]) ?: return SaveResult.FAILED
            if (r["title"] == JsonValue.Str(t)) return SaveResult.UNCHANGED
            val changed = LinkedHashMap(r)
            changed["title"] = JsonValue.Str(t)
            changed["updated_at"] = JsonValue.Int(maxOf(clock.now, (r["updated_at"] as? JsonValue.Int)?.v ?: 0L))
            val records = LinkedHashMap(snap.records)
            records[itemId] = wrap(JsonValue.Obj(changed), ref)
            store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
            SaveResult.SAVED
        } catch (e: Exception) {
            SaveResult.FAILED
        }
    }

    /** Deletes the item (a tombstone, like every delete) and then its file. */
    fun delete(itemId: String): SaveResult {
        val ref = ref(itemId)
        val r = EditorModel.delete(itemId, store, clock)
        if (r == SaveResult.SAVED && ref != null) vault.remove(ref)
        return r
    }

    /** Removes files no live record names (files from a delete that arrived by sync, or an add that never committed). */
    fun collectGarbage(nowMillis: Long = System.currentTimeMillis()): Int = try {
        vault.collectGarbage(store.load().records, nowMillis)
    } catch (e: Exception) {
        0
    }

    override fun toString(): String = "DocumentStore"

    private fun uuid4(): String {
        val b = random.bytes(16)
        b[6] = ((b[6].toInt() and 0x0F) or 0x40).toByte()
        b[8] = ((b[8].toInt() and 0x3F) or 0x80).toByte()
        val h = b.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        return UUID.fromString("${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}").toString()
    }

    companion object {
        /** The synced wrapper of a document record: the item wrapper plus its `attachment` reference. */
        fun wrap(record: JsonValue, ref: AttachmentRef): JsonValue =
            JsonValue.Obj((Wrapper.make(Namespace.ITEM, record) as JsonValue.Obj).fields + ("attachment" to ref.toJson()))
    }
}

/**
 * Plain copies made to preview, save or share a file. They live only in `cacheDir/open-documents` (never backed up),
 * each in its own random folder, and are deleted when the preview closes, after the share or save returns, when the
 * vault locks and when the app starts.
 */
class DocumentTemp(private val cacheDir: File) {
    val root: File get() = File(cacheDir, DIR)

    fun write(name: String, data: ByteArray): File {
        val dir = File(root, UUID.randomUUID().toString())
        if (!dir.mkdirs() && !dir.isDirectory) throw java.io.IOException("temp folder")
        val f = File(dir, DocumentText.safeName(name))
        f.writeBytes(data)
        return f
    }

    fun delete(file: File) {
        file.parentFile?.takeIf { it.parentFile == root }?.deleteRecursively() ?: file.delete()
    }

    fun clear() {
        root.deleteRecursively()
    }

    companion object {
        const val DIR = "open-documents"
    }
}

/** The documents' copy and the name rules (desktop `_open_copy_name`). */
object DocumentText {
    @StringRes val ADD = R.string.doc_add
    @StringRes val PRO_TITLE = R.string.doc_pro_title
    @StringRes val PRO_MESSAGE = R.string.doc_pro_message
    @StringRes val TOO_LARGE = R.string.doc_too_large
    @StringRes val ADD_FAILED = R.string.doc_add_failed
    @StringRes val READ_FAILED = R.string.doc_read_failed
    @StringRes val MISSING = R.string.doc_missing
    @StringRes val REFUSED = R.string.doc_refused
    @StringRes val OPEN_REASON = R.string.doc_open_reason
    @StringRes val NO_PREVIEW = R.string.doc_no_preview

    private val reserved = setOf("", ".", "..")

    /** A file name without path separators, control or format characters; at most 255 code points; never empty. */
    fun safeName(name: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < name.length) {
            val cp = name.codePointAt(i)
            i += Character.charCount(cp)
            val t = Character.getType(cp).toByte()
            val bad = cp < 0x20 || cp == 0x7F || cp == '/'.code || cp == '\\'.code || cp == ':'.code ||
                t == Character.FORMAT || t == Character.CONTROL || t == Character.SURROGATE
            sb.appendCodePoint(if (bad) '_'.code else cp)
        }
        var out = sb.toString().trim()
        if (out.codePointCount(0, out.length) > 255) out = out.substring(0, out.offsetByCodePoints(0, 255))
        return if (out in reserved || out.all { it == '.' }) "document" else out
    }

    /** The picker's type when it is a plain `type/subtype`, else one from the extension, else octet-stream. */
    fun safeMime(mime: String?, name: String): String {
        val m = mime?.trim()?.lowercase()
        if (m != null && m.length in 3..255 && Regex("^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$").matches(m)) return m
        return when (name.substringAfterLast('.', "").lowercase()) {
            "pdf" -> "application/pdf"
            "jpg", "jpeg" -> "image/jpeg"
            "png" -> "image/png"
            "gif" -> "image/gif"
            "webp" -> "image/webp"
            "heic" -> "image/heic"
            "txt" -> "text/plain"
            else -> "application/octet-stream"
        }
    }

    fun title(title: String, fileName: String): String {
        val t = title.trim().ifEmpty { fileName.substringBeforeLast('.').trim().ifEmpty { fileName } }
        return if (t.codePointCount(0, t.length) > 512) t.substring(0, t.offsetByCodePoints(0, 512)) else t
    }

    /** "812 bytes", "34 KB", "1.5 MB": the units and the decimal mark follow the person's language. */
    fun size(bytes: Long, t: Txt): String = when {
        bytes < 1024 -> t.plural(R.plurals.doc_size_bytes, bytes.toInt(), bytes)
        bytes < 1024 * 1024 -> t.s(R.string.doc_size_kb, bytes / 1024.0)
        else -> t.s(R.string.doc_size_mb, bytes / (1024.0 * 1024.0))
    }

    enum class Preview { IMAGE, PDF, TEXT, NONE }

    fun preview(mime: String): Preview = when {
        mime in setOf("image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp", "image/heic", "image/heif") -> Preview.IMAGE
        mime == "application/pdf" -> Preview.PDF
        mime.startsWith("text/") -> Preview.TEXT
        else -> Preview.NONE
    }
}
