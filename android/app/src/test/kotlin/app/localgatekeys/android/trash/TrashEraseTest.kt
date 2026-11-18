package app.localgatekeys.android.trash

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.unlock.AppLockModel
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.ManualScheduler
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.unlock.UnlockedVault
import app.localgatekeys.android.unlock.Unlocker
import app.localgatekeys.android.unlock.VaultDirs
import app.localgatekeys.android.unlock.VaultEraser
import app.localgatekeys.android.unlock.VaultOpener
import app.localgatekeys.android.unlock.tempDir
import app.localgatekeys.android.vault.FakeVaultKey
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.DirectoryAttachmentVault
import app.localgatekeys.core.sync.StoreChange
import java.io.File
import javax.crypto.Cipher
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The local trash store goes with the vault on every erase path. Erase vault (Settings), Start fresh (unlock screen) and
 * the device-removal erase (`RemovalGuard` -> `LgkApp.eraseVault` -> `AppLockModel.eraseAndLock`) all end in
 * [VaultEraser.erase], which deletes `filesDir/Vault`: `local-data.bin` and `attachments-deleted/` live inside it.
 */
class TrashEraseTest {
    private val approve: suspend (Cipher?) -> Cipher? = { it }

    private fun unlockedWithTrash(dirs: VaultDirs, settings: AppSettings): UnlockedVault {
        val v = runBlocking { VaultOpener(dirs, FakeVaultKey(), SystemRandomSource(), settings, cryptoBound = true).open(approve) }
        val record = JsonValue.Obj(
            mapOf(
                "id" to JsonValue.Str("00000000-0000-4000-8000-000000000001"), "kind" to JsonValue.Str("note"), "title" to JsonValue.Str("Kept"),
                "created_at" to JsonValue.Int(1), "updated_at" to JsonValue.Int(1), "favorite" to JsonValue.Bool(false),
                "tags" to JsonValue.Arr(emptyList()), "payload" to JsonValue.Obj(mapOf("body" to JsonValue.Str("x"))),
            ),
        )
        v.store.commit(StoreChange(0, mapOf("00000000-0000-4000-8000-000000000001" to Wrapper.make(Namespace.ITEM, record)), emptyMap(), null))
        val local = PhoneLocalData(dirs.vault, v.localKey, SystemRandomSource(), dirSync = {})
        val trash = PhoneTrash(local, v.store, { true }, TestClock(1_800_000_000), EnglishTxt(), DirectoryAttachmentVault(File(dirs.vault, "attachments")))
        trash.moveToTrash("00000000-0000-4000-8000-000000000001")
        assertTrue(File(dirs.vault, PhoneLocalData.FILE_NAME).exists())
        File(dirs.vault, PhoneTrash.KEPT_DIR).mkdirs()
        File(dirs.vault, PhoneTrash.KEPT_DIR + "/x.lgkblob").writeBytes(ByteArray(4))
        return v
    }

    @Test fun erase_vault_removes_the_trash_store_and_kept_files() = runBlocking {
        val base = tempDir("trash-erase")
        val dirs = VaultDirs.under(base)
        val settings = AppSettings(MemoryStore())
        val key = FakeVaultKey()
        unlockedWithTrash(dirs, settings).close()
        VaultEraser(dirs, key, settings).erase()
        assertFalse(File(dirs.vault, PhoneLocalData.FILE_NAME).exists())
        assertFalse(File(dirs.vault, PhoneTrash.KEPT_DIR).exists())
        assertFalse(dirs.vault.exists())
    }

    @Test fun an_undeletable_vault_is_set_aside_and_the_next_vault_starts_with_an_empty_trash() = runBlocking {
        val base = tempDir("trash-erase")
        val dirs = VaultDirs.under(base)
        val settings = AppSettings(MemoryStore())
        unlockedWithTrash(dirs, settings).close()
        val eraser = VaultEraser(dirs, FakeVaultKey(), settings)
        eraser.removeDirectory = { false }
        eraser.erase()
        assertFalse(dirs.vault.exists())
        // A fresh vault (new local key): nothing of the old trash is there, and nothing old can be read.
        val v = runBlocking { VaultOpener(dirs, FakeVaultKey(), SystemRandomSource(), settings, cryptoBound = true).open(approve) }
        val local = PhoneLocalData(dirs.vault, v.localKey, SystemRandomSource(), dirSync = {})
        assertEquals(LocalData.EMPTY, local.localData)
        assertFalse(local.wasReset)
        v.close()
    }

    @Test fun start_fresh_and_the_removal_erase_use_the_same_eraser() = runBlocking {
        val base = tempDir("trash-erase")
        val dirs = VaultDirs.under(base)
        val settings = AppSettings(MemoryStore())
        unlockedWithTrash(dirs, settings).close()
        val clock = TestClock(1_800_000_000)
        val unlocker = object : Unlocker {
            override suspend fun unlock(reason: String): UnlockedVault = throw IllegalStateException("not used")
            override fun lock() {}
            override fun discard(vault: UnlockedVault) {}
        }
        val lock = AppLockModel(
            unlocker = unlocker, clock = clock, scheduler = ManualScheduler(clock), settings = settings, clipboard = null,
            eraser = VaultEraser(dirs, FakeVaultKey(), settings), t = EnglishTxt(),
        )
        assertTrue(lock.eraseAndLock { })
        assertFalse(File(dirs.vault, PhoneLocalData.FILE_NAME).exists())
        // Start fresh after an erase that was interrupted (the pending flag is still set).
        unlockedWithTrash(dirs, settings).close()
        settings.erasePending = true
        lock.startFreshAnyway()
        assertFalse(File(dirs.vault, PhoneLocalData.FILE_NAME).exists())
        assertFalse(File(dirs.vault, PhoneTrash.KEPT_DIR).exists())
    }
}
