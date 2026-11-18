package app.localgatekeys.android.sync

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import app.localgatekeys.core.sync.FolderAccess
import app.localgatekeys.core.sync.FolderAccessException

/**
 * The app's [FolderOpening] (the iPhone's `SecurityScopedFolderOpener`): a picked folder is kept as its tree URI with a
 * persisted read and write permission ([persist]); [open] gives a [SafFolderAccess] over it. A folder whose permission
 * is gone (revoked in system settings, the provider app removed or cleared) does not open: the coordinator reports
 * `folder-missing`, and the Sync tab asks to choose the folder again ([isAvailable] false).
 */
class SafFolderOpener(context: Context, private val keepAlso: () -> Set<String> = { emptySet() }) : FolderOpening {
    private val app = context.applicationContext
    private val resolver: ContentResolver = app.contentResolver

    /**
     * Keeps the read and write permission the picker granted for [treeUri] across restarts and returns the URI string
     * to store. Throws [FolderAccessException] (IO) when the provider granted no persistable permission.
     */
    fun persist(treeUri: Uri): String {
        try {
            resolver.takePersistableUriPermission(treeUri, FLAGS)
        } catch (e: SecurityException) {
            throw FolderAccessException(FolderAccessException.Kind.IO, "the folder's permission could not be kept")
        }
        return treeUri.toString()
    }

    override fun open(uri: String): FolderAccess {
        if (!isAvailable(uri)) throw FolderAccessException(FolderAccessException.Kind.IO, UNAVAILABLE)
        return SafFolderAccess(app, Uri.parse(uri))
    }

    override fun isAvailable(uri: String): Boolean = try {
        val u = Uri.parse(uri)
        resolver.persistedUriPermissions.any { it.uri == u && it.isReadPermission && it.isWritePermission }
    } catch (e: Exception) {
        false
    }

    override fun keepOnly(uri: String?) = keepOnlyAll(setOfNotNull(uri))

    /** Releases every persisted folder permission but [uris]' and the emergency access folders' ([keepAlso]). */
    override fun keepOnlyAll(uris: Set<String>) {
        val keep = uris.map { Uri.parse(it) }.toSet()
        val also = try {
            keepAlso().map { Uri.parse(it) }.toSet()
        } catch (e: Exception) {
            emptySet()
        }
        val held = try {
            resolver.persistedUriPermissions
        } catch (e: Exception) {
            return
        }
        for (p in held) {
            if (p.uri in keep || p.uri in also) continue
            try {
                resolver.releasePersistableUriPermission(p.uri, FLAGS)
            } catch (e: SecurityException) {
                // already gone
            }
        }
    }

    /**
     * The picked folder's name as the provider shows it (the share sheet's folder row), or null when it cannot be read.
     * Blocking (a provider query); never throws.
     */
    fun displayName(uri: String): String? = try {
        val tree = Uri.parse(uri)
        val doc = DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))
        resolver.query(doc, arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    } catch (e: Exception) {
        null
    }

    override fun toString(): String = "SafFolderOpener"

    companion object {
        const val FLAGS = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        const val UNAVAILABLE = "the chosen folder is no longer available"
    }
}
