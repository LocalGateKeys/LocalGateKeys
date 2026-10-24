package app.localgatekeys.android.unlock

import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.sync.FolderOpening
import app.localgatekeys.android.vault.LocalStore
import app.localgatekeys.android.vault.VaultKey
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Erases this phone's vault. Fakes stand in for it in [AppLockModel] tests. */
interface VaultErasing {
    suspend fun erase()
}

/** The steps that failed, by name only (never a value). */
class VaultEraseFailure(val steps: List<String>) : Exception() {
    override val message: String
        get() = "The vault was not fully erased (could not delete: ${steps.joinToString(", ")}). " +
            "Tap Unlock to try erasing again, or Start fresh anyway."

    override fun equals(other: Any?): Boolean = other is VaultEraseFailure && other.steps == steps
    override fun hashCode(): Int = steps.hashCode()
}

/**
 * "Erase this phone's vault" (a port of `ios/App/Settings/VaultEraser.swift`): deletes the store directory (and its
 * set-aside copies), `vault-key.bin`, the sealed slots file, the Keystore key and every preference except the
 * erase-pending flag, which [AppLockModel] sets before and clears after. Every step is attempted even when an
 * earlier one fails; the failures are thrown together ([VaultEraseFailure]). Missing items are not errors, so
 * erasing again is safe. The next unlock is a first run. Never touches the desktop or the sync folder.
 *
 * Steps (failure names): "store files" (a directory that cannot be deleted is set aside instead, so the next unlock
 * starts empty), "local-key" (`vault-key.bin`), "secrets" ([slotsFile]), "vault-key" (the Keystore key), "settings" (a preference not removed durably).
 * Last, best effort (never a failure): every persisted folder permission is released ([folders] `keepOnly(null)`).
 */
class VaultEraser(
    private val dirs: VaultDirs,
    private val vaultKey: VaultKey,
    private val settings: AppSettings,
    private val slotsFile: File = dirs.secrets,
    /** The cloud folder's permissions (the app: SafFolderOpener). */
    private val folders: FolderOpening? = null,
) : VaultErasing {
    /** Deletes the store directory; true when it is gone (a seam: tests make it fail). */
    internal var removeDirectory: (File) -> Boolean = { it.deleteRecursively() }
    /** Renames an undeletable store directory out of the way (seam). */
    internal var setAside: (File, Long) -> Unit = { dir, now -> LocalStore.setAside(dir, now) }
    /** Deletes one file; true when it is gone (seam). */
    internal var deleteFile: (File) -> Boolean = { it.delete() }
    internal var now: () -> Long = { System.currentTimeMillis() / 1000L }

    override suspend fun erase() = withContext(Dispatchers.IO) {
        val failed = mutableListOf<String>()
        try {
            val dir = dirs.vault
            LocalStore.removeSetAside(dir) // earlier leftovers, best effort
            if (dir.exists() && !removeDirectory(dir)) {
                // Not deletable now: move it out of the way so the next unlock starts empty (no vault-without-key
                // loop). The set-aside copy is deleted later, best effort.
                setAside(dir, now())
            }
        } catch (e: Exception) {
            failed += "store files"
        }
        if (!removeFile(dirs.wrappedKey)) failed += "local-key"
        if (!removeFile(slotsFile)) failed += "secrets"
        try {
            vaultKey.delete()
        } catch (e: Exception) {
            failed += "vault-key"
        }
        try {
            settings.eraseAllExceptPending()
        } catch (e: Exception) {
            failed += "settings"
        }
        try {
            folders?.keepOnly(null)
        } catch (e: Exception) {
            // a permission that stays opens nothing: the folder URI went with the slots
        }
        if (failed.isNotEmpty()) throw VaultEraseFailure(failed)
    }

    private fun removeFile(f: File): Boolean = try {
        !f.exists() || deleteFile(f) || !f.exists()
    } catch (e: SecurityException) {
        false
    }

    companion object {
        /** Two confirmations, in the style of Leave and Reset sync. */
        const val CONFIRM_TEXT_1 =
            "Erase this phone's vault?\n\nThis deletes every item, the vault's keys and its sync settings from this phone. " +
                "Your PC and the sync folder are not changed. If this phone was your only copy, the items are gone."
        const val CONFIRM_TEXT_2 = "Are you sure? This cannot be undone. Erase this phone's vault now?"
    }
}
