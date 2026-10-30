package app.localgatekeys.android.unlock

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.sync.FolderOpening
import app.localgatekeys.android.vault.AppPasswordLock
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
    /** What the unlock screen says; the step names are technical ids and stay as they are. */
    fun text(t: Txt): String = t.s(R.string.erase_failed_steps, steps.joinToString(", "))

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
    /** The unsaved editor draft (Task 6), in noBackupFilesDir; failure name "draft". */
    private val draftFile: File? = null,
    /** Task 7: the app password file and the biometric shortcut; failure name "app-password". */
    private val appPassword: AppPasswordLock? = null,
    /** Part C: the sealed fill index (titles, usernames, app pairings) and its key; false = not gone. Failure name "fill-index". */
    private val fillIndex: (() -> Boolean)? = null,
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
        if (draftFile != null) {
            File(draftFile.parentFile, draftFile.name + ".tmp").let { if (!removeFile(it)) failed += "draft" }
            if (!removeFile(draftFile) && "draft" !in failed) failed += "draft"
        }
        if (appPassword != null && !appPassword.deleteAll()) failed += "app-password"
        if (fillIndex != null && !(try { fillIndex.invoke() } catch (e: Exception) { false })) failed += "fill-index"
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
        @StringRes val CONFIRM_TEXT_1 = R.string.erase_confirm_1
        @StringRes val CONFIRM_TEXT_2 = R.string.erase_confirm_2
    }
}
