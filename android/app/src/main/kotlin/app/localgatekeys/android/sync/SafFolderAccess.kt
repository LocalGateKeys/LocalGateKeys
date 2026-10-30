package app.localgatekeys.android.sync

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.FolderAccess
import app.localgatekeys.core.sync.FolderAccessException
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.SyncFailedException

/**
 * [FolderAccess] over a folder picked with the Storage Access Framework (`ACTION_OPEN_DOCUMENT_TREE`; the app holds a
 * persisted read and write permission to [treeUri]). Port of the iPhone's `CoordinatedFolder`; blocking: call it off
 * the main thread (the coordinator runs it on its IO dispatcher). The provider (OneDrive, Dropbox, Nextcloud, a local
 * folder...) fetches a file when it is opened.
 *
 * Paths are resolved one name at a time from the tree's root document. A provider may hold two documents with one
 * name; the first it lists is used.
 *
 * **Writes** (the spec's rename-replace-or-rewrite-and-verify rule): the data goes to a new temp document in the same
 * folder, named by the core rule `.<final name>.<random hex>.tmp` (so `FolderSync` skips it while in flight and sweeps
 * this device's leftovers), and is then renamed to the final name:
 * - no file of that name yet: the rename puts it in place (done);
 * - a file of that name exists: SAF has no atomic replace. When the provider's rename keeps the exact name (it replaced
 *   the old file, or holds both: the old one is then deleted), the write is done. Most providers refuse the name or
 *   pick another one (`name (1)`, as Android's own storage does): that copy is deleted, and the existing file is
 *   rewritten in place (`"wt"`) and read back to check every byte. That rewrite is NOT atomic: a device reading the
 *   file at that moment can see it partly written, reports it unreadable for that run and reads it again at its next
 *   sync. Once a provider has refused, this folder instance (one sync run) rewrites existing files in place directly,
 *   without uploading a temp first (still read back).
 * - a provider that cannot rename at all: the final file is created (or rewritten) directly, then read back.
 * The temp document is always removed afterwards (best effort; a leftover is swept by `FolderSync`), never when it is
 * the document that ended up holding the data (a provider that answers no name after a rename).
 *
 * Errors: a missing path is [FolderAccessException.Kind.NOT_FOUND]; everything else (permission revoked, provider
 * failure, bad path) is IO. [exists] never throws.
 */
class SafFolderAccess(
    context: Context,
    private val treeUri: Uri,
    private val random: RandomSource = SystemRandomSource(),
) : FolderAccess {
    private val resolver: ContentResolver = context.contentResolver
    private val rootId: String = try {
        DocumentsContract.getTreeDocumentId(treeUri)
    } catch (e: IllegalArgumentException) {
        throw FolderAccessException(FolderAccessException.Kind.IO, "the chosen folder is no longer available")
    }

    /** null until a replace was tried; false once the provider would not rename over an existing file. */
    @Volatile private var renameReplaces: Boolean? = null

    private class Doc(val id: String, val name: String, val isDir: Boolean)

    // MARK: FolderAccess

    override fun list(dir: String): List<String> = guarded(dir) {
        val d = resolve(parts(dir)) ?: throw notFound(dir)
        if (!d.isDir) throw io("$dir: not a folder")
        children(d.id).map { it.name }.distinct()
    }

    override fun read(path: String, limit: Int): ByteArray = guarded(path) {
        val d = resolve(parts(path)) ?: throw notFound(path)
        if (d.isDir) throw io("$path: is a folder")
        readUpTo(d.id, path, maxOf(0, limit))
    }

    override fun writeAtomic(path: String, data: ByteArray) = guarded(path) {
        val p = parts(path)
        val name = p.last()
        val parent = ensureFolders(p.dropLast(1))
        val existing = child(parent, name)
        if (existing?.isDir == true) throw io("$path: is a folder")
        if (existing != null && renameReplaces == false) {
            // This provider is known not to replace by renaming: rewrite in place, no temp upload.
            rewriteAndCheck(existing, data, name)
            return@guarded
        }
        var temp: Doc? = create(parent, ".$name.${hex(random.bytes(8))}.tmp")
        var target: Doc? = null
        try {
            writeAll(temp!!.id, data, name)
            when (val placed = renameOver(temp!!, name, parent, existing)) {
                is Placed.Done -> {
                    temp = null
                    return@guarded
                }
                is Placed.Moved -> temp = placed.left // a copy under another name, or the temp as it was
            }
            // Rewrite and verify: the provider cannot replace by renaming.
            val t = existing ?: child(parent, name) ?: create(parent, name)
            target = t
            rewriteAndCheck(t, data, name)
        } finally {
            // Never the file that now holds the data, whatever the provider reported about the rename.
            temp?.takeIf { it.id != target?.id }?.let { t -> runCatching { DocumentsContract.deleteDocument(resolver, docUri(t.id)) } }
        }
    }

    private fun rewriteAndCheck(target: Doc, data: ByteArray, name: String) {
        writeAll(target.id, data, name)
        val back = readUpTo(target.id, name, data.size + 1)
        if (!back.contentEquals(data)) throw io("$name: the written file could not be checked")
    }

    override fun remove(path: String) = guarded(path) {
        val d = resolve(parts(path)) ?: throw notFound(path)
        if (!DocumentsContract.deleteDocument(resolver, docUri(d.id))) throw io("$path: could not be deleted")
    }

    override fun exists(path: String): Boolean = try {
        resolve(parts(path)) != null
    } catch (e: Exception) {
        false
    }

    /** `COLUMN_LAST_MODIFIED` in Unix seconds; null when the provider does not report it (the blob is then kept). */
    override fun modifiedAt(path: String): Long? = try {
        val d = resolve(parts(path))
        if (d == null || d.isDir) {
            null
        } else {
            resolver.query(docUri(d.id), arrayOf(Document.COLUMN_LAST_MODIFIED), null, null, null)?.use { c ->
                if (c.moveToFirst() && !c.isNull(0)) c.getLong(0).takeIf { it > 0 }?.div(1000) else null
            }
        }
    } catch (e: Exception) {
        null
    }

    /** `COLUMN_SIZE`; null when the provider does not report it. */
    override fun size(path: String): Long? = try {
        val d = resolve(parts(path))
        if (d == null || d.isDir) {
            null
        } else {
            resolver.query(docUri(d.id), arrayOf(Document.COLUMN_SIZE), null, null, null)?.use { c ->
                if (c.moveToFirst() && !c.isNull(0)) c.getLong(0) else null
            }
        }
    } catch (e: Exception) {
        null
    }

    // MARK: writing

    private sealed interface Placed {
        /** The data now sits under the final name. */
        data object Done : Placed
        /** Not placed; [left] is what is left of the temp document to delete (null: nothing). */
        class Moved(val left: Doc?) : Placed
    }

    /** Renames [temp] to [name]; see the class comment. */
    private fun renameOver(temp: Doc, name: String, parent: String, existing: Doc?): Placed {
        val renamed: Uri = try {
            DocumentsContract.renameDocument(resolver, docUri(temp.id), name)
        } catch (e: SecurityException) {
            throw e
        } catch (e: Exception) {
            null // rename not supported, or refused (e.g. the name is taken)
        } ?: run {
            if (existing != null) renameReplaces = false
            // The temp may or may not still be there under its own name: delete whatever is.
            return Placed.Moved(stillThere(temp, parent))
        }
        val id = DocumentsContract.getDocumentId(renamed)
        // Some providers answer no name for the renamed document itself; its folder listing still names it.
        val now = displayName(id) ?: children(parent).firstOrNull { it.id == id }?.name
        if (now == null && (existing == null || id == existing.id)) {
            // Renamed, name unknown: nothing else held the name (or the provider replaced that document in place).
            if (existing != null) renameReplaces = true
            return Placed.Done
        }
        if (now != name) {
            // The provider chose another name ("name (1)"): that copy is deleted; the old file is rewritten instead.
            if (existing != null) renameReplaces = false
            return Placed.Moved(Doc(id, now ?: name, false))
        }
        if (existing != null) {
            // Kept the exact name: an old document still listed under it (a provider that allows two) goes.
            for (old in children(parent)) {
                if (old.name == name && old.id != id) DocumentsContract.deleteDocument(resolver, docUri(old.id))
            }
            renameReplaces = true
        }
        return Placed.Done
    }

    /** [temp] if it is still listed in [parent] (a failed rename leaves it, or a partial one may have moved it). */
    private fun stillThere(temp: Doc, parent: String): Doc? = children(parent).firstOrNull { it.id == temp.id || it.name == temp.name }

    /** A new file [name] in [parent]; refused when the provider stored it under another name. */
    private fun create(parent: String, name: String): Doc {
        val uri = DocumentsContract.createDocument(resolver, docUri(parent), MIME, name) ?: throw io("$name: could not be created")
        val id = DocumentsContract.getDocumentId(uri)
        val stored = displayName(id)
        if (stored != name) {
            runCatching { DocumentsContract.deleteDocument(resolver, uri) }
            throw io("$name: the folder stored the new file under another name")
        }
        return Doc(id, name, false)
    }

    /** The folder for [path] parts, creating missing ones. */
    private fun ensureFolders(path: List<String>): String {
        var id = rootId
        for (part in path) {
            val c = child(id, part)
            id = when {
                c == null -> {
                    val uri = DocumentsContract.createDocument(resolver, docUri(id), Document.MIME_TYPE_DIR, part)
                        ?: throw io("$part: the folder could not be created")
                    val newId = DocumentsContract.getDocumentId(uri)
                    if (displayName(newId) != part) throw io("$part: the folder was created under another name")
                    newId
                }
                c.isDir -> c.id
                else -> throw io("$part: not a folder")
            }
        }
        return id
    }

    private fun writeAll(id: String, data: ByteArray, name: String) {
        val pfd = resolver.openFileDescriptor(docUri(id), "wt") ?: throw io("$name: could not be opened for writing")
        pfd.use {
            val out = FileOutputStream(it.fileDescriptor)
            out.write(data)
            out.flush()
            try {
                it.fileDescriptor.sync()
            } catch (e: SyncFailedException) {
                // a pipe to a cloud provider: it stores the file when the descriptor closes
            }
        }
    }

    // MARK: reading

    private fun readUpTo(id: String, name: String, limit: Int): ByteArray {
        val input = resolver.openInputStream(docUri(id)) ?: throw io("$name: could not be opened")
        input.use { s ->
            val out = java.io.ByteArrayOutputStream(minOf(limit, 64 * 1024))
            val buf = ByteArray(16 * 1024)
            while (out.size() < limit) {
                val n = s.read(buf, 0, minOf(buf.size, limit - out.size()))
                if (n < 0) break
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }
    }

    // MARK: resolving

    private fun resolve(path: List<String>): Doc? {
        var current = rootDoc() ?: return null
        for (part in path) {
            if (!current.isDir) return null
            current = child(current.id, part) ?: return null
        }
        return current
    }

    private fun rootDoc(): Doc? = query(docUri(rootId)).firstOrNull()

    private fun child(parent: String, name: String): Doc? = children(parent).firstOrNull { it.name == name }

    private fun children(parent: String): List<Doc> =
        query(DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parent), listing = true)

    private fun displayName(id: String): String? = query(docUri(id)).firstOrNull()?.name

    /**
     * Rows of a document query (a document that is gone gives none: providers answer no cursor) or, with [listing], of
     * a children query (no cursor there is a provider failure, never an empty folder).
     */
    private fun query(uri: Uri, listing: Boolean = false): List<Doc> {
        val cursor = try {
            resolver.query(uri, PROJECTION, null, null, null)
        } catch (e: FileNotFoundException) {
            return emptyList()
        } catch (e: IllegalArgumentException) {
            return emptyList() // some providers report a missing document this way
        } ?: if (listing) throw io("the folder did not list its files") else return emptyList()
        return cursor.use { c ->
            val out = ArrayList<Doc>(c.count)
            while (c.moveToNext()) {
                val id = c.getString(0) ?: continue
                val name = c.getString(1) ?: continue
                out.add(Doc(id, name, c.getString(2) == Document.MIME_TYPE_DIR))
            }
            out
        }
    }

    private fun docUri(id: String): Uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, id)

    // MARK: errors

    private inline fun <T> guarded(path: String, body: () -> T): T = try {
        body()
    } catch (e: FolderAccessException) {
        throw e
    } catch (e: SecurityException) {
        throw io("$path: the chosen folder is no longer available")
    } catch (e: FileNotFoundException) {
        throw notFound(path)
    } catch (e: Exception) {
        throw io("$path: ${e.message ?: e.javaClass.simpleName}")
    }

    override fun toString(): String = "SafFolderAccess"

    companion object {
        private const val MIME = "application/octet-stream"
        private val PROJECTION = arrayOf(Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME, Document.COLUMN_MIME_TYPE)

        /** The Swift `CoordinatedFolder.url` rule: `/`-separated, no empty, `.` or `..` part. */
        internal fun parts(path: String): List<String> {
            val p = path.split("/")
            if (p.isEmpty() || p.any { it.isEmpty() || it == "." || it == ".." }) {
                throw FolderAccessException(FolderAccessException.Kind.IO, "bad path $path")
            }
            return p
        }

        private fun notFound(path: String) = FolderAccessException(FolderAccessException.Kind.NOT_FOUND, path)

        private fun io(detail: String) = FolderAccessException(FolderAccessException.Kind.IO, detail)

        private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}
