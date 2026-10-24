package app.localgatekeys.core.crypto

import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class Argon2Test {
    private fun derive(pw: ByteArray, salt: ByteArray): String =
        Vectors.hexString(Argon2.default.derive(pw, salt, 131072, 4, 4, 32))

    @Test fun argon2_matches_desktop_outputs() {
        val exp = Vectors.json(Vectors.sync("expected.json")).obj().fields
        val epochs = exp.getValue("epochs").obj().fields
        val existing = exp.getValue("existing_group").obj().fields.getValue("epochs").obj().fields
        val cases = mutableListOf<Triple<String, String, String>>()
        cases += Triple(
            "keyring_epoch1.json", exp.getValue("password_epoch1").str(),
            epochs.getValue("1").obj().fields.getValue("password_wrap_key_hex").str(),
        )
        cases += Triple(
            "keyring_epoch2.json", exp.getValue("password_epoch2").str(),
            epochs.getValue("2").obj().fields.getValue("password_wrap_key_hex").str(),
        )
        for ((file, ep) in listOf("keyring_existing_epoch1.json" to "1", "keyring_existing_epoch3.json" to "3")) {
            val e = existing.getValue(ep).obj().fields
            cases += Triple(file, e.getValue("password").str(), e.getValue("password_wrap_key_hex").str())
        }
        for ((file, password, want) in cases) {
            val kdf = Vectors.json(Vectors.sync(file)).obj().fields.getValue("kdf").obj().fields
            assertEquals(131072L, kdf.getValue("memory_kib").long())
            val salt = Base64Std.decodeStrict(kdf.getValue("salt").str())
            assertEquals(want, derive(password.toByteArray(Charsets.UTF_8), salt), file)
        }
    }

    @Test fun nfc_and_nfd_passwords_differ() {
        val u = Vectors.json(Vectors.sync("expected.json")).obj().fields.getValue("unicode_password").obj().fields
        val salt = Vectors.hex(u.getValue("salt_hex").str())
        val nfc = Vectors.hex(u.getValue("password_nfc_utf8_hex").str())
        val nfd = Vectors.hex(u.getValue("password_nfd_utf8_hex").str())
        assertNotEquals(Vectors.hexString(nfc), Vectors.hexString(nfd))
        assertEquals(Vectors.hexString(nfc), Vectors.hexString(u.getValue("password_nfc").str().toByteArray(Charsets.UTF_8)))
        assertEquals(Vectors.hexString(nfd), Vectors.hexString(u.getValue("password_nfd").str().toByteArray(Charsets.UTF_8)))
        val a = derive(nfc, salt)
        val b = derive(nfd, salt)
        assertNotEquals(a, b)
        assertEquals(u.getValue("argon2id_nfc_hex").str(), a)
        assertEquals(u.getValue("argon2id_nfd_hex").str(), b)
    }

    @Test fun invalid_parameters_are_rejected() {
        val salt = ByteArray(16)
        val pw = ByteArray(4)
        assertFailsWith<IllegalArgumentException> { Argon2.default.derive(pw, ByteArray(7), 64, 1, 1, 32) }
        assertFailsWith<IllegalArgumentException> { Argon2.default.derive(pw, salt, 64, 1, 0, 32) }
        assertFailsWith<IllegalArgumentException> { Argon2.default.derive(pw, salt, 64, 1, 1, 0) }
        assertFailsWith<IllegalArgumentException> { Argon2.default.derive(pw, salt, 64, 0, 1, 32) }
    }
}
