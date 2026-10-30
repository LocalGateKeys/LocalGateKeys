package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.json.JsonValue
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.util.UUID

/**
 * This device's encrypted attachment files, as sync needs them (desktop `AttachmentStore` sync half).
 *
 * The phone keeps the sync blob itself as its sidecar: the file is sealed under the attachment's own random key,
 * which lives only inside the encrypted vault record (the wrapper's `attachment` reference), so the file is never
 * readable without the unlocked vault. A blob is verified ([AttachmentSync.openBlob]) before it is stored and again
 * whenever it is read.
 */
interface AttachmentVault {
    /** True when the file named by [ref] (same id and blob) is stored. */
    fun has(ref: AttachmentRef): Boolean

    /** Verifies [blob] against [ref] and stores it; throws [AttachmentSyncException] when refused. */
    fun store(ref: AttachmentRef, blob: ByteArray)

    /** The stored blob of [ref] when present and intact, else null. */
    fun blob(ref: AttachmentRef): ByteArray?
}

/** Document helpers shared by the transports (desktop `vault_bridge.document_refs` / `publishable`). */
object Documents {
    const val KIND = "document"

    private fun isDocumentWrapper(item: JsonValue?): Boolean {
        val w = (item as? JsonValue.Obj)?.fields ?: return false
        val r = (w["record"] as? JsonValue.Obj)?.fields ?: return false
        return w["ns"] == JsonValue.Str("item") && r["kind"] == JsonValue.Str(KIND)
    }

    fun isDocumentState(s: ItemState): Boolean = !s.deleted && isDocumentWrapper(s.item)

    /** [states] to publish; without [documents] the document items are left out (readers that do not support them). */
    fun publishable(states: List<ItemState>, documents: Boolean): List<ItemState> =
        if (documents) states else states.filter { !isDocumentState(it) }

    /** The reference of a stored or received document wrapper, or null when it has none or it is malformed. */
    fun refOf(item: JsonValue?): AttachmentRef? {
        if (!isDocumentWrapper(item)) return null
        return try {
            AttachmentRef.fromJson((item as JsonValue.Obj).fields["attachment"])
        } catch (e: AttachmentSyncException) {
            null
        }
    }

    /** The well-formed references of the live document states in [states]. */
    fun refs(states: Iterable<ItemState>): List<AttachmentRef> = states.filter { isDocumentState(it) }.mapNotNull { refOf(it.item) }

    /**
     * Fetches and stores every file the live documents of [states] name that [vault] lacks ([fetch] returns the blob
     * or null). Missing files are left for the apply step (`attachment-missing`); a refused blob is an
     * `attachment-refused` issue and stores nothing.
     */
    fun importMissing(vault: AttachmentVault, states: Iterable<ItemState>, fetch: (AttachmentRef) -> ByteArray?): List<SyncIssue> {
        val (refs, issues) = AttachmentSync.uniqueRefs(refs(states))
        val out = ArrayList(issues)
        for (ref in refs.sortedBy { it.blob }) {
            if (vault.has(ref)) continue
            val blob = try {
                fetch(ref)
            } catch (e: InterruptedException) {
                throw e
            } catch (e: Exception) {
                null
            } ?: continue
            try {
                vault.store(ref, blob)
            } catch (e: AttachmentSyncException) {
                out.add(SyncIssue("attachment-refused", "${ref.attachmentId}: ${e.reason}"))
            } catch (e: IOException) {
                out.add(SyncIssue("write-failed", "attachment: ${e.message ?: e}"))
            }
        }
        return out
    }
}

/**
 * [AttachmentVault] over one private directory: `<dir>/<attachment id>.<blob id>.lgkblob`, written through a temp file,
 * fsync and an atomic rename. Names are only a canonical UUID and a hex blob id; symlinks are never followed.
 */
class DirectoryAttachmentVault(val dir: File) : AttachmentVault {
    private fun file(ref: AttachmentRef): File = file(ref.attachmentId, ref.blob)

    private fun file(attachmentId: String, blob: String): File {
        if (!AttachmentSync.isCanonicalUuid(attachmentId) || !AttachmentSync.isBlobId(blob)) {
            throw AttachmentSyncException("bad-ref", "file name")
        }
        return File(dir, "$attachmentId.$blob${AttachmentSync.BLOB_SUFFIX}")
    }

    private fun regular(f: File): Boolean = Files.isRegularFile(f.toPath(), LinkOption.NOFOLLOW_LINKS)

    override fun has(ref: AttachmentRef): Boolean = regular(file(ref))

    override fun store(ref: AttachmentRef, blob: ByteArray) {
        val data = AttachmentSync.openBlob(blob, ref)
        data.fill(0)
        val target = file(ref)
        if (regular(target)) return
        if (!dir.isDirectory && !dir.mkdirs() && !dir.isDirectory) throw IOException("create attachments directory")
        val tmp = File(dir, ".${target.name}.${UUID.randomUUID()}.tmp")
        try {
            FileOutputStream(tmp).use { out ->
                out.write(blob)
                out.flush()
                out.fd.sync()
            }
            try {
                Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE)
            } catch (e: AtomicMoveNotSupportedException) {
                throw IOException("atomic rename not supported")
            }
        } finally {
            tmp.delete()
        }
    }

    override fun blob(ref: AttachmentRef): ByteArray? {
        val f = file(ref)
        return try {
            if (!regular(f) || f.length() != ref.blobSize) return null
            val raw = Files.readAllBytes(f.toPath())
            AttachmentSync.checkBlobShape(raw, ref.blob)
        } catch (e: IOException) {
            null
        } catch (e: AttachmentSyncException) {
            null
        }
    }

    /** The plaintext of [ref]'s file, verified; throws [AttachmentSyncException] (`missing` when absent). */
    fun open(ref: AttachmentRef): ByteArray {
        val raw = blob(ref) ?: throw AttachmentSyncException("missing", ref.attachmentId)
        return AttachmentSync.openBlob(raw, ref)
    }

    /**
     * Removes files no live record references (by id and blob), and leftover temp files, when older than
     * [minAgeMillis] (a file being added has no committed record yet). Returns the number removed.
     */
    fun collectGarbage(records: Map<String, JsonValue>, nowMillis: Long, minAgeMillis: Long = 10 * 60 * 1000L): Int {
        val keep = records.values.mapNotNull { Documents.refOf(it) }.map { "${it.attachmentId}.${it.blob}${AttachmentSync.BLOB_SUFFIX}" }.toSet()
        var removed = 0
        for (name in dir.list() ?: return 0) {
            if (name in keep) continue
            val f = File(dir, name)
            if (nowMillis - f.lastModified() < minAgeMillis) continue
            if (f.delete()) removed++
        }
        return removed
    }

    /** Deletes [ref]'s file (the document was deleted here). */
    fun remove(ref: AttachmentRef) {
        file(ref).delete()
    }

    /** Deletes every file (Start fresh / erase). */
    fun clear() {
        dir.deleteRecursively()
    }

    override fun toString(): String = "DirectoryAttachmentVault"
}
