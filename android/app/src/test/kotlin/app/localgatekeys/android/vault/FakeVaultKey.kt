package app.localgatekeys.android.vault

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** JVM stand-in for [KeystoreVaultKey]: a software AES-256-GCM key with the same wrap format and error kinds. */
class FakeVaultKey : VaultKey {
    private var key: SecretKeySpec? = null
    private var invalidated = false

    /** Simulates the screen lock being removed: every use fails with INVALIDATED. */
    fun invalidate() {
        invalidated = true
    }

    override fun exists(): Boolean = key != null

    override fun create() {
        if (key != null) throw VaultKeyException(VaultKeyException.Kind.FAILED, "vault key already exists")
        key = SecretKeySpec(ByteArray(32).also { SecureRandom().nextBytes(it) }, "AES")
        invalidated = false
    }

    private fun usable(): SecretKeySpec {
        if (invalidated) throw VaultKeyException(VaultKeyException.Kind.INVALIDATED)
        return key ?: throw VaultKeyException(VaultKeyException.Kind.MISSING)
    }

    override fun cipherForWrap(): Cipher {
        val k = usable()
        val iv = ByteArray(WRAP_IV_BYTES).also { SecureRandom().nextBytes(it) }
        return Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, k, GCMParameterSpec(WRAP_TAG_BITS, iv)) }
    }

    override fun cipherForUnwrap(wrapped: ByteArray): Cipher {
        val k = usable()
        val (iv, _) = WrapFormat.split(wrapped)
        return Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(WRAP_TAG_BITS, iv)) }
    }

    override fun wrap(localKey: ByteArray, cipher: Cipher): ByteArray = WrapFormat.wrap(localKey, cipher)

    override fun unwrap(wrapped: ByteArray, cipher: Cipher): ByteArray = WrapFormat.unwrap(wrapped, cipher)

    override fun delete() {
        key = null
        invalidated = false
    }
}
