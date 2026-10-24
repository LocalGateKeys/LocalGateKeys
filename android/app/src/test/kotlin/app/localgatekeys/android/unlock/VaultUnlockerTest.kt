package app.localgatekeys.android.unlock

import app.localgatekeys.android.vault.FakeVaultKey
import app.localgatekeys.android.vault.LocalStore
import app.localgatekeys.android.vault.LocalStoreException
import app.localgatekeys.android.vault.Slot
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.StoreChange
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import kotlin.concurrent.thread
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/** Ruling 11: a lock never blocks the calling (main) thread, and nothing is written after it. */
class VaultUnlockerTest {
    private lateinit var dirs: VaultDirs
    private val key = FakeVaultKey()
    private val closer = Executors.newSingleThreadExecutor()
    private var cancels = 0

    private val approve = object : Authenticator {
        override suspend fun authenticate(reason: String, cipher: Cipher?): Cipher? = cipher
        override fun cancel() { cancels++ }
    }

    @Before fun setUp() {
        dirs = VaultDirs.under(tempDir("unlocker"))
    }

    private fun unlocker() =
        VaultUnlocker(VaultOpener(dirs, key, SystemRandomSource(), null, cryptoBound = true), approve, closer.asCoroutineDispatcher())

    private fun note(id: String): JsonValue =
        JsonValue.Obj(mapOf("ns" to JsonValue.Str("item"), "record" to JsonValue.Obj(mapOf("id" to JsonValue.Str(id)))))

    private fun drainCloser() {
        closer.submit {}.get(10, TimeUnit.SECONDS)
    }

    @Test fun lock_while_a_commit_holds_the_store_lock_returns_at_once_and_nothing_is_written() {
        val u = unlocker()
        val v = runBlocking { u.unlock("r") }
        v.store.commit(StoreChange(0, mapOf("a" to note("a")), emptyMap(), null)) // revision 1
        val store = v.store as LocalStore
        val inside = CountDownLatch(1)
        val release = CountDownLatch(1)
        store.beforeCurrentWrite = { inside.countDown(); release.await() }
        var outcome: Any? = null
        val committer = thread {
            outcome = try {
                store.commit(StoreChange(1, mapOf("a" to note("a"), "b" to note("b")), emptyMap(), null)); "committed"
            } catch (e: LocalStoreException) {
                e
            }
        }
        assertTrue(inside.await(10, TimeUnit.SECONDS)) // the commit holds the store lock, generation 2 written

        val t0 = System.nanoTime()
        u.lock()
        val ms = (System.nanoTime() - t0) / 1_000_000
        assertTrue("lock() returned in $ms ms while the commit held the lock", ms < 500)
        assertTrue("the vault's key copy is zeroed at once", v.localKey.all { it == 0.toByte() })
        assertEquals(1, cancels)

        release.countDown()
        committer.join(10_000)
        assertTrue("the in-flight commit stops before CURRENT: $outcome", outcome is LocalStoreException)
        try {
            store.commit(StoreChange(1, emptyMap(), emptyMap(), null))
            fail("no write after lock")
        } catch (e: LocalStoreException) {
            assertEquals(LocalStoreException.Kind.BAD_LOCAL_KEY, e.kind)
        }
        try {
            v.slots.write(Slot.INSTALL_ID, byteArrayOf(1))
            fail("no slot write after lock")
        } catch (e: IllegalStateException) {
            // expected
        }
        drainCloser()
        assertEquals("CURRENT still names the last committed revision", 1L, LocalStore.committedRevision(dirs.vault))

        // A fresh open sees revision 1 exactly, and commits on top of the stray generation 2.
        val again = runBlocking { unlocker().unlock("r") }
        val snap = again.store.load()
        assertEquals(1L, snap.revision)
        assertEquals(setOf("a"), snap.records.keys)
        again.store.commit(StoreChange(1, mapOf("c" to note("c")), emptyMap(), null))
        assertEquals(2L, again.store.load().revision)
        assertEquals(setOf("c"), again.store.load().records.keys)
    }

    @Test fun discard_shuts_only_that_vault() {
        val u = unlocker()
        val first = runBlocking { u.unlock("r") }
        val second = runBlocking { u.unlock("r") }
        u.discard(first)
        drainCloser()
        assertTrue(first.localKey.all { it == 0.toByte() })
        assertFalse("the other vault is untouched", second.localKey.all { it == 0.toByte() })
        second.store.load()
        assertEquals("no prompt dismissed", 0, cancels)
        u.discard(first) // twice: nothing happens
        u.lock()
        drainCloser()
        assertTrue(second.localKey.all { it == 0.toByte() })
        try {
            second.store.load(); fail()
        } catch (e: LocalStoreException) {
            // closed
        }
    }

    @Test fun unlocked_vault_has_no_structural_helpers_that_show_the_key() {
        val v = runBlocking { unlocker().unlock("r") }
        val methods = v.javaClass.methods.map { it.name }
        assertFalse(methods.any { it == "copy" || it.startsWith("component") })
        assertFalse(v.toString().contains(v.localKey.joinToString()))
        assertTrue(File(dirs.vault.path).isDirectory)
    }
}
