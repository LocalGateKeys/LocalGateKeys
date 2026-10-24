package app.localgatekeys.android.vault

import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.SecureRandom
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/** The Keystore adapter on a real device, with a key made WITHOUT user authentication (tests only). */
class KeystoreVaultKeyTest {
    private val alias = "lgk.vault.test"
    private lateinit var key: KeystoreVaultKey

    @Before fun setUp() {
        key = KeystoreVaultKey.forTestingWithoutUserAuth(InstrumentationRegistry.getInstrumentation().targetContext, alias)
        key.delete()
    }

    @After fun tearDown() = key.delete()

    private fun localKey() = ByteArray(32).also { SecureRandom().nextBytes(it) }

    @Test fun production_alias_is_off_limits_to_the_test_factory() {
        try {
            KeystoreVaultKey.forTestingWithoutUserAuth(InstrumentationRegistry.getInstrumentation().targetContext, KeystoreVaultKey.ALIAS)
            fail()
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test fun create_wraps_and_unwraps_a_local_key() {
        assertFalse(key.exists())
        key.create()
        assertTrue(key.exists())
        val local = localKey()
        val wrapped = key.wrap(local, key.cipherForWrap())
        assertEquals(12 + 32 + 16, wrapped.size)
        assertFalse(wrapped.copyOfRange(12, 44).contentEquals(local))
        val back = key.unwrap(wrapped, key.cipherForUnwrap(wrapped))
        assertArrayEquals(local, back)
        back.fill(0)
    }

    @Test fun each_wrap_uses_a_new_iv() {
        key.create()
        val local = localKey()
        val a = key.wrap(local, key.cipherForWrap())
        val b = key.wrap(local, key.cipherForWrap())
        assertNotEquals(a.copyOfRange(0, 12).toList(), b.copyOfRange(0, 12).toList())
    }

    @Test fun create_twice_is_refused() {
        key.create()
        try {
            key.create()
            fail()
        } catch (e: VaultKeyException) {
            assertEquals(VaultKeyException.Kind.FAILED, e.kind)
        }
    }

    @Test fun tampered_wrapped_bytes_fail_to_unwrap() {
        key.create()
        val wrapped = key.wrap(localKey(), key.cipherForWrap())
        val t = wrapped.copyOf().also { it[30] = (it[30].toInt() xor 1).toByte() }
        try {
            key.unwrap(t, key.cipherForUnwrap(t))
            fail()
        } catch (e: VaultKeyException) {
            assertEquals(VaultKeyException.Kind.FAILED, e.kind)
        }
        try {
            key.cipherForUnwrap(ByteArray(5))
            fail()
        } catch (e: VaultKeyException) {
            assertEquals(VaultKeyException.Kind.FAILED, e.kind)
        }
    }

    @Test fun deleting_the_key_makes_unwrap_fail_with_a_clear_error() {
        key.create()
        val wrapped = key.wrap(localKey(), key.cipherForWrap())
        key.delete()
        assertFalse(key.exists())
        try {
            key.cipherForUnwrap(wrapped)
            fail()
        } catch (e: VaultKeyException) {
            assertTrue(e.kind == VaultKeyException.Kind.MISSING || e.kind == VaultKeyException.Kind.INVALIDATED)
        }
        // A key recreated under the same alias is a different key: the old wrapped bytes do not open.
        key.create()
        try {
            key.unwrap(wrapped, key.cipherForUnwrap(wrapped))
            fail()
        } catch (e: VaultKeyException) {
            assertEquals(VaultKeyException.Kind.FAILED, e.kind)
        }
    }

    @Test fun delete_without_a_key_is_fine() {
        key.delete()
        assertFalse(key.exists())
    }

    @Test fun keystore_wrapped_local_key_opens_the_sealed_slots() {
        key.create()
        val local = localKey()
        val file = File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir, "slots-test-${System.nanoTime()}.bin")
        try {
            val rnd = app.localgatekeys.core.primitives.SystemRandomSource()
            SecretSlots(file, local, rnd).use { it.write(Slot.FOLDER_URI, "content://x".toByteArray()) }
            val wrapped = key.wrap(local, key.cipherForWrap())
            val unwrapped = key.unwrap(wrapped, key.cipherForUnwrap(wrapped))
            SecretSlots(file, unwrapped, rnd).use {
                assertArrayEquals("content://x".toByteArray(), it.read(Slot.FOLDER_URI))
            }
            unwrapped.fill(0)
        } finally {
            file.delete()
        }
    }

    @Test fun production_key_without_a_secure_lock_screen_reports_no_screen_lock() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val km = ctx.getSystemService(android.content.Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
        org.junit.Assume.assumeFalse("device has a secure lock screen", km.isDeviceSecure)
        val prod = KeystoreVaultKey.production(ctx)
        org.junit.Assume.assumeFalse("a production key already exists", prod.exists())
        try {
            prod.create()
            prod.delete()
            fail("expected NO_SCREEN_LOCK")
        } catch (e: VaultKeyException) {
            assertEquals(VaultKeyException.Kind.NO_SCREEN_LOCK, e.kind)
            assertFalse(prod.exists())
        }
    }

    @Test fun wrapping_a_local_key_of_the_wrong_length_is_refused() {
        key.create()
        try {
            key.wrap(ByteArray(16), key.cipherForWrap())
            fail()
        } catch (e: VaultKeyException) {
            assertEquals(VaultKeyException.Kind.FAILED, e.kind)
        }
    }
}
