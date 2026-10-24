package app.localgatekeys.core.primitives

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class CryptoBoxException(val kind: Kind) : Exception(kind.name) {
    enum class Kind { BAD_KEY_OR_NONCE, AUTHENTICATION_FAILED }
}

object CryptoBox {
    /** HKDF-SHA256 (RFC 5869). An empty salt means a zero-filled salt of hash length. */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 0..(255 * 32)) { "bad hkdf length" }
        val prk = hmac(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        val out = java.io.ByteArrayOutputStream(length)
        var t = ByteArray(0)
        var counter = 1
        while (out.size() < length) {
            t = hmac(prk, t + info + byteArrayOf(counter.toByte()))
            out.write(t)
            counter++
        }
        return out.toByteArray().copyOf(length)
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** Returns ciphertext || 16-byte tag. */
    fun sealGcm(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        if (key.size != 32 || nonce.size != 12) throw CryptoBoxException(CryptoBoxException.Kind.BAD_KEY_OR_NONCE)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad)
        return c.doFinal(plaintext)
    }

    /** Input is ciphertext || tag. */
    fun openGcm(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray {
        if (key.size != 32 || nonce.size != 12) throw CryptoBoxException(CryptoBoxException.Kind.BAD_KEY_OR_NONCE)
        if (ciphertext.size < 16) throw CryptoBoxException(CryptoBoxException.Kind.AUTHENTICATION_FAILED)
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            c.updateAAD(aad)
            return c.doFinal(ciphertext)
        } catch (e: java.security.GeneralSecurityException) {
            throw CryptoBoxException(CryptoBoxException.Kind.AUTHENTICATION_FAILED)
        }
    }
}
