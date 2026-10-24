package app.localgatekeys.android.unlock

import app.localgatekeys.android.vault.FakeVaultKey
import app.localgatekeys.android.vault.LocalStore
import app.localgatekeys.android.vault.LocalStoreException
import app.localgatekeys.android.vault.Slot
import app.localgatekeys.android.vault.VaultKey
import app.localgatekeys.android.vault.VaultKeyException
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.StoreChange
import java.io.File
import javax.crypto.Cipher
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/** Records the order of key operations, so the API 29 / API 30+ prompt order can be checked. */
class RecordingVaultKey(val inner: VaultKey = FakeVaultKey()) : VaultKey by inner {
    val events = mutableListOf<String>()
    var failDelete = false
    override fun create() { events += "create"; inner.create() }
    override fun cipherForWrap(): Cipher { events += "cipherForWrap"; return inner.cipherForWrap() }
    override fun cipherForUnwrap(wrapped: ByteArray): Cipher { events += "cipherForUnwrap"; return inner.cipherForUnwrap(wrapped) }
    override fun delete() {
        events += "delete"
        if (failDelete) throw VaultKeyException(VaultKeyException.Kind.FAILED, "delete refused")
        inner.delete()
    }
}

/** First run, second run and the vault-without-key rules of the unlock layer (the prompt replaced by a lambda). */
class VaultOpenerTest {
    private lateinit var base: File
    private lateinit var dirs: VaultDirs
    private lateinit var key: RecordingVaultKey
    private var prompts = 0

    @Before fun setUp() {
        base = tempDir("opener")
        dirs = VaultDirs.under(base)
        key = RecordingVaultKey()
        prompts = 0
    }

    private fun opener(cryptoBound: Boolean = true) = VaultOpener(dirs, key, SystemRandomSource(), null, cryptoBound)

    /** Approves the prompt; on the crypto-bound path hands back the same cipher, as BiometricPrompt does. */
    private val approve: suspend (Cipher?) -> Cipher? = { c -> prompts++; key.events += "prompt"; c }

    private fun open(cryptoBound: Boolean = true, auth: suspend (Cipher?) -> Cipher? = approve) =
        runBlocking { opener(cryptoBound).open(auth) }

    private fun thrown(block: () -> Unit): Exception {
        try { block() } catch (e: Exception) { return e }
        fail("expected an exception"); throw AssertionError()
    }

    @Test fun first_run_creates_the_keystore_key_the_local_key_and_an_empty_store() {
        val v = open()
        assertTrue(key.exists())
        assertTrue(dirs.wrappedKey.isFile)
        assertEquals(32, v.localKey.size)
        assertEquals(0L, v.store.load().revision)
        assertTrue(v.store.load().records.isEmpty())
        v.slots.write(Slot.INSTALL_ID, byteArrayOf(1, 2))
        assertArrayEquals(byteArrayOf(1, 2), v.slots.read(Slot.INSTALL_ID))
        assertEquals(1, prompts)
        assertTrue("no temp file left", base.list()!!.none { it.endsWith(".tmp") })
        v.close()
    }

    @Test fun second_run_unwraps_the_same_local_key_and_opens_the_same_store() {
        val first = open()
        val k1 = first.localKey.copyOf()
        first.store.commit(StoreChange(0, emptyMap(), emptyMap(), null))
        first.close()
        key.events.clear()
        val second = open()
        assertArrayEquals(k1, second.localKey)
        assertEquals(1L, second.store.load().revision)
        assertEquals(listOf("cipherForUnwrap", "prompt"), key.events)
        assertEquals(2, prompts)
    }

    @Test fun api30_prompts_with_the_cipher_and_api29_prompts_before_making_it() {
        open(cryptoBound = true).close()
        assertEquals(listOf("create", "cipherForWrap", "prompt"), key.events)
        // API 29: a time-bound key; the cipher is made (and used) after the prompt, inside the 30 s window.
        setUp()
        var seen: Cipher? = Cipher.getInstance("AES/GCM/NoPadding")
        open(cryptoBound = false, auth = { c -> seen = c; key.events += "prompt"; null }).close()
        assertNull("no CryptoObject below API 30", seen)
        assertEquals(listOf("create", "prompt", "cipherForWrap"), key.events)
        key.events.clear()
        open(cryptoBound = false, auth = { c -> key.events += "prompt"; c }).close()
        assertEquals(listOf("prompt", "cipherForUnwrap"), key.events)
    }

    @Test fun store_files_without_the_wrapped_key_are_a_vault_without_key_and_nothing_is_created() {
        val other = LocalStore.open(dirs.vault, ByteArray(32) { 9 }, SystemRandomSource(), null)
        other.commit(StoreChange(0, emptyMap(), emptyMap(), null))
        other.close()
        val before = dirs.vault.list()!!.sorted()
        val e = thrown { open() }
        assertEquals(LocalStoreException.Kind.VAULT_WITHOUT_KEY, (e as LocalStoreException).kind)
        assertFalse("no Keystore key made over existing files", key.exists())
        assertFalse(dirs.wrappedKey.exists())
        assertEquals(before, dirs.vault.list()!!.sorted())
        assertEquals("no prompt for a vault that cannot open", 0, prompts)
        assertEquals(1L, LocalStore.committedRevision(dirs.vault))
    }

    @Test fun invalidated_keystore_key_surfaces_as_invalidated_and_changes_nothing() {
        open().close()
        val wrapped = dirs.wrappedKey.readBytes()
        (key.inner as FakeVaultKey).invalidate()
        val e = thrown { open() }
        assertEquals(VaultKeyException.Kind.INVALIDATED, (e as VaultKeyException).kind)
        assertArrayEquals(wrapped, dirs.wrappedKey.readBytes())
        assertTrue(LocalStore.hasStoreFiles(dirs.vault) || dirs.vault.isDirectory)
        assertFalse("never replaced silently", key.events.contains("delete"))
    }

    @Test fun keystore_key_gone_with_a_wrapped_key_is_a_vault_without_key() {
        open().close()
        key.inner.delete()
        key.events.clear()
        val e = thrown { open() }
        assertEquals(LocalStoreException.Kind.VAULT_WITHOUT_KEY, (e as LocalStoreException).kind)
        assertFalse(key.exists())
        assertTrue(dirs.wrappedKey.exists())
        assertEquals(emptyList<String>(), key.events)
    }

    @Test fun first_run_replaces_a_stale_keystore_key_and_stale_secrets() {
        key.inner.create() // left by a first run cancelled at the prompt
        dirs.secrets.writeBytes(ByteArray(40) { 3 }) // sealed with a key that no longer exists
        val v = open()
        assertTrue(key.events.containsAll(listOf("delete", "create")))
        assertNull("stale secrets are gone", v.slots.read(Slot.INSTALL_ID))
        v.close()
    }

    @Test fun a_cancelled_first_run_leaves_no_wrapped_key_and_the_next_run_works() {
        val e = thrown { open(auth = { throw AuthenticationException(10) }) }
        assertTrue(e is AuthenticationException)
        assertFalse(dirs.wrappedKey.exists())
        assertFalse(LocalStore.hasStoreFiles(dirs.vault))
        val v = open()
        assertNotNull(v.store.load())
        v.close()
    }

    @Test fun close_zeroes_the_key_and_closes_the_store() {
        val v = open()
        v.close()
        assertTrue(v.localKey.all { it == 0.toByte() })
        val e = thrown { v.store.load() }
        assertTrue(e is LocalStoreException)
        assertFalse("no key bytes in toString", v.toString().contains(v.localKey.joinToString()))
    }
}
