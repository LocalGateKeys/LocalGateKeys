package app.localgatekeys.android.sync

import app.localgatekeys.core.sync.FolderAccess
import app.localgatekeys.core.sync.FolderAccessException

/**
 * Opens the cloud folder the person picked (Swift `FolderOpening`). On Android the "bookmark" is the persisted tree
 * URI string (kept in the sealed `folder-uri` slot); it is never refreshed. A folder that cannot be opened (permission
 * revoked, provider gone) throws, and the coordinator reports `folder-missing`. [SafFolderOpener] is the app's.
 */
fun interface FolderOpening {
    fun open(uri: String): FolderAccess

    /** Whether [uri] can still be opened (Android: the app still holds its persisted permission). Never throws. */
    fun isAvailable(uri: String): Boolean = true

    /**
     * Gives up every folder permission except [uri]'s (null: all of them), so the app holds access only to the folder
     * it syncs through. Never throws.
     */
    fun keepOnly(uri: String?) {}

    companion object {
        /** No folder can be opened: every open fails as "folder-missing". */
        val UNAVAILABLE = FolderOpening { throw FolderAccessException(FolderAccessException.Kind.IO, "the chosen folder is no longer available") }
    }
}
