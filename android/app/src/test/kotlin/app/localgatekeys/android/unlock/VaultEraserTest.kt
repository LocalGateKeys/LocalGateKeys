package app.localgatekeys.android.unlock

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.IdleLock
import app.localgatekeys.android.settings.KeyValueStore
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.settings.SettingsWriteException
import app.localgatekeys.android.unlock.AppLockModel.State
import app.localgatekeys.android.vault.FakeVaultKey
import app.localgatekeys.android.vault.LocalStore
import app.localgatekeys.android.vault.LocalStoreException
import app.localgatekeys.android.vault.Slot
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.StoreChange
import java.io.File
import java.io.IOException
import javax.crypto.Cipher
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/** Port of ios/LocalGateKeysTests/VaultEraserTests.swift (Keychain slots become vault-key.bin, secrets.bin and the Keystore key). */
class VaultEraserTest {
    private lateinit var base: File
    private lateinit var dirs: VaultDirs
    private lateinit var key: RecordingVaultKey
    private lateinit var prefs: MemoryStore
    private lateinit var settings: AppSettings

    @Before fun setUp() {
        base = tempDir("erase")
        dirs = VaultDirs.under(base)
        key = RecordingVaultKey()
        prefs = MemoryStore()
        settings = AppSettings(prefs)
    }

    private val approve: suspend (Cipher?) -> Cipher? = { it }
    private fun opener() = VaultOpener(dirs, key, SystemRandomSource(), settings, cryptoBound = true)
    private fun firstRun(): UnlockedVault = runBlocking { opener().open(approve) }
    private fun eraser() = VaultEraser(dirs, key, settings)
    private fun failure(e: VaultEraser): VaultEraseFailure {
        try { runBlocking { e.erase() } } catch (f: VaultEraseFailure) { return f }
        fail("must report the failures"); throw AssertionError()
    }

    @Test fun erase_removes_store_keys_secrets_and_settings() = runBlocking {
        val v = firstRun()
        v.store.commit(StoreChange(0, emptyMap(), emptyMap(), null))
        v.slots.write(Slot.INSTALL_ID, byteArrayOf(1, 2, 3))
        v.slots.write(Slot.PAIRED_PEER, byteArrayOf(4))
        v.close()
        settings.idleLock = IdleLock.NEVER
        settings.initials = "Ann Lee"
        settings.planFullRevision = 7
        settings.erasePending = true
        val sibling = File(base, "unrelated.txt").apply { writeText("keep") }

        eraser().erase()

        assertFalse(dirs.vault.exists())
        assertFalse(dirs.wrappedKey.exists())
        assertFalse(dirs.secrets.exists())
        assertFalse(key.exists())
        for (k in AppSettings.Key.all - AppSettings.Key.ERASE_PENDING) {
            assertNull(k, prefs.getLong(k) ?: prefs.getString(k) ?: prefs.getBoolean(k))
        }
        assertTrue("the pending flag belongs to the lock model", settings.erasePending)
        assertTrue("never touches anything else", sibling.exists())
        // First run again: a new store with a new local key.
        val again = firstRun()
        assertTrue(again.store.load().records.isEmpty())
        assertEquals(0L, again.store.load().revision)
        assertNull(again.slots.read(Slot.INSTALL_ID))
    }

    @Test fun erase_removes_the_fill_index_and_reports_a_failure() = runBlocking {
        var calls = 0
        VaultEraser(dirs, key, settings, fillIndex = { calls++; true }).erase()
        assertEquals(1, calls)
        val e = try {
            VaultEraser(dirs, key, settings, fillIndex = { false }).erase()
            null
        } catch (x: VaultEraseFailure) {
            x
        }
        assertEquals(listOf("fill-index"), e?.steps)
    }

    @Test fun erase_releases_every_persisted_folder_permission() = runBlocking {
        val folders = app.localgatekeys.android.sync.FakeFolders(app.localgatekeys.android.sync.MemoryFolder())
        VaultEraser(dirs, key, settings, folders = folders).erase()
        assertEquals(listOf<String?>(null), folders.kept)
        // Best effort: a provider that refuses never fails the erase.
        val refusing = object : app.localgatekeys.android.sync.FolderOpening by folders {
            override fun keepOnly(uri: String?) = throw SecurityException("no")
        }
        VaultEraser(dirs, key, settings, folders = refusing).erase()
    }

    @Test fun undeletable_vault_directory_is_set_aside_so_the_next_unlock_starts_empty() = runBlocking {
        val v = firstRun()
        v.store.commit(StoreChange(0, emptyMap(), emptyMap(), null))
        v.close()
        val e = eraser()
        e.removeDirectory = { false }
        e.now = { 1_790_000_000 }

        e.erase() // not a failure: the files are out of the way

        assertFalse(dirs.vault.exists())
        val aside = File(base, "Vault-unreadable-1790000000")
        assertNotNull("set aside, not lost mid-erase", LocalStore.committedRevision(aside))
        // The next unlock is a first run (no vault-without-key loop), and it clears the set-aside copy.
        val fresh = firstRun()
        assertEquals(0L, fresh.store.load().revision)
        assertFalse(aside.exists())
    }

    @Test fun vault_without_key_start_fresh_with_undeletable_files_unlocks_empty() = runBlocking {
        val old = LocalStore.open(dirs.vault, ByteArray(32) { 5 }, SystemRandomSource(), null)
        old.commit(StoreChange(0, emptyMap(), emptyMap(), null))
        old.close()
        try {
            firstRun(); fail()
        } catch (x: LocalStoreException) {
            assertEquals(LocalStoreException.Kind.VAULT_WITHOUT_KEY, x.kind)
        }
        val e = eraser()
        e.removeDirectory = { false }
        e.erase()
        assertEquals(0L, firstRun().store.load().revision)
    }

    @Test fun erase_of_an_empty_install_succeeds() = runBlocking {
        eraser().erase()
        assertFalse(dirs.vault.exists())
    }

    @Test fun failed_steps_do_not_stop_the_others_and_a_retry_finishes() = runBlocking {
        firstRun().close()
        key.failDelete = true
        val e = eraser()

        assertEquals(listOf("vault-key"), failure(e).steps)
        assertFalse("later steps still ran", dirs.vault.exists())
        assertFalse(dirs.wrappedKey.exists())
        assertTrue(key.exists())

        key.failDelete = false
        e.erase() // missing items are not errors
        assertFalse(key.exists())
    }

    @Test fun store_directory_failure_is_reported() {
        firstRun().close()
        val e = eraser()
        e.removeDirectory = { false }
        e.setAside = { _, _ -> throw IOException("refused") }
        assertEquals(listOf("store files"), failure(e).steps)
        assertFalse("the other steps ran", key.exists())
    }

    @Test fun undeletable_key_files_are_reported_by_name() {
        val v = firstRun()
        v.slots.write(Slot.INSTALL_ID, byteArrayOf(1)) // secrets.bin exists once a slot is written
        v.close()
        val e = eraser()
        e.deleteFile = { false }
        assertEquals(listOf("local-key", "secrets"), failure(e).steps)
        assertFalse("the store and the Keystore key still went", dirs.vault.exists() || key.exists())
    }

    @Test fun settings_that_cannot_be_removed_are_reported() {
        firstRun().close()
        val failing = object : KeyValueStore by prefs {
            override fun remove(key: String, durable: Boolean) {
                if (durable) throw SettingsWriteException()
                prefs.remove(key, durable)
            }
        }
        val e = VaultEraser(dirs, key, AppSettings(failing))
        assertEquals(listOf("settings"), failure(e).steps)
        assertFalse("the files still went", dirs.vault.exists() || dirs.wrappedKey.exists() || key.exists())
    }

    @Test fun wording_matches_the_two_step_style() {
        assertEquals(
            "Erase this phone's vault?\n\nThis deletes every item, the vault's keys and its sync settings from this phone. " +
                "Your PC and the sync folder are not changed. If this phone was your only copy, the items are gone.",
            EnglishTxt().s(VaultEraser.CONFIRM_TEXT_1),
        )
        assertEquals("Are you sure? This cannot be undone. Erase this phone's vault now?", EnglishTxt().s(VaultEraser.CONFIRM_TEXT_2))
        assertTrue(EnglishTxt().s(VaultEraser.CONFIRM_TEXT_1).startsWith("Erase this phone's vault?"))
        assertTrue(EnglishTxt().s(VaultEraser.CONFIRM_TEXT_2).startsWith("Are you sure? This cannot be undone."))
    }

    /** Port of the BootstrappingUnlocker test: a flag left set by an earlier failure recovers on the next launch. */
    @Test fun stuck_flag_recovers_on_next_unlock_into_an_empty_vault() = runBlocking {
        val old = firstRun()
        old.store.commit(StoreChange(0, emptyMap(), emptyMap(), null))
        assertEquals(1L, old.store.load().revision)
        val oldKey = old.localKey.copyOf()
        old.close()
        settings.erasePending = true
        val clock = TestClock(1_790_000_000)
        val unlocker = VaultUnlocker(opener(), object : Authenticator {
            override suspend fun authenticate(reason: String, cipher: Cipher?): Cipher? = cipher
            override fun cancel() {}
        })
        val m = AppLockModel(unlocker, clock, ManualScheduler(clock), settings, null, eraser(), t = EnglishTxt())

        m.sceneBecameActive() // launch

        assertFalse(settings.erasePending); assertNull(m.errorMessage.value)
        assertEquals(State.UNLOCKED, m.state.value)
        val snap = m.store!!.load()
        assertEquals(0L, snap.revision); assertTrue(snap.records.isEmpty())
        assertFalse("a new local key: a first run", oldKey.contentEquals(m.vault.value!!.localKey))
        val open = m.vault.value!!
        m.lock()
        assertTrue("lock closes the vault and zeroes its key", open.localKey.all { it == 0.toByte() })
    }
}
