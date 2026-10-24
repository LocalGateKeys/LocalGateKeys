package app.localgatekeys.android.crypto

import android.util.Base64
import app.localgatekeys.core.crypto.Argon2
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** argon2kt on the device against the shared desktop vectors, at production parameters (128 MiB, 4 passes, 4 lanes). */
class Argon2KtVectorTest {
    private val adapter = Argon2KtAdapter()

    private fun asset(name: String): JSONObject {
        val ctx = InstrumentationRegistry.getInstrumentation().context
        return JSONObject(ctx.assets.open("vectors/sync/$name").bufferedReader(Charsets.UTF_8).use { it.readText() })
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    private fun derive(pw: ByteArray, salt: ByteArray) = hex(adapter.derive(pw, salt, 131072, 4, 4, 32))

    /** Salt of a keyring; the cost parameters are read from its kdf block and must be the production ones. */
    private fun kdfOf(file: String): Pair<ByteArray, Triple<Int, Int, Int>> {
        val kdf = asset(file).getJSONObject("kdf")
        val params = Triple(kdf.getInt("memory_kib"), kdf.getInt("iterations"), kdf.getInt("parallelism"))
        assertEquals(Triple(131072, 4, 4), params)
        return Base64.decode(kdf.getString("salt"), Base64.DEFAULT) to params
    }

    private fun deriveWithKeyringParams(file: String, pw: ByteArray): String {
        val (salt, p) = kdfOf(file)
        return hex(adapter.derive(pw, salt, p.first, p.second, p.third, 32))
    }

    @Test fun argon2_default_is_the_argon2kt_adapter_after_app_start() {
        val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        assertTrue(app is app.localgatekeys.android.LgkApp)
        assertTrue(Argon2.default is Argon2KtAdapter)
    }

    @Test fun epoch1_password_matches_desktop() {
        val exp = asset("expected.json")
        val want = exp.getJSONObject("epochs").getJSONObject("1").getString("password_wrap_key_hex")
        assertEquals(want, deriveWithKeyringParams("keyring_epoch1.json", exp.getString("password_epoch1").toByteArray(Charsets.UTF_8)))
    }

    @Test fun epoch2_password_matches_desktop() {
        val exp = asset("expected.json")
        val want = exp.getJSONObject("epochs").getJSONObject("2").getString("password_wrap_key_hex")
        assertEquals(want, deriveWithKeyringParams("keyring_epoch2.json", exp.getString("password_epoch2").toByteArray(Charsets.UTF_8)))
    }

    @Test fun nfc_and_nfd_passwords_differ() {
        val u = asset("expected.json").getJSONObject("unicode_password")
        val salt = unhex(u.getString("salt_hex"))
        val nfc = unhex(u.getString("password_nfc_utf8_hex"))
        val nfd = unhex(u.getString("password_nfd_utf8_hex"))
        val a = derive(nfc, salt)
        val b = derive(nfd, salt)
        assertNotEquals(a, b)
        assertEquals(u.getString("argon2id_nfc_hex"), a)
        assertEquals(u.getString("argon2id_nfd_hex"), b)
    }
}
