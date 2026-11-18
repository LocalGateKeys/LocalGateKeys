package app.localgatekeys.core.primitives

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/** Ed25519 over raw 32-byte seeds and public keys (Swift `Curve25519.Signing`). Signatures are RFC 8032 deterministic. */
object Ed25519 {
    fun publicKey(seed: ByteArray): ByteArray {
        require(seed.size == 32) { "bad seed" }
        return Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
    }

    fun sign(seed: ByteArray, msg: ByteArray): ByteArray {
        require(seed.size == 32) { "bad seed" }
        val s = Ed25519Signer()
        s.init(true, Ed25519PrivateKeyParameters(seed, 0))
        s.update(msg, 0, msg.size)
        return s.generateSignature()
    }

    /** False for any malformed input, as the Swift `verify`. */
    fun verify(sig: ByteArray, msg: ByteArray, pub: ByteArray): Boolean {
        if (pub.size != 32 || sig.size != 64) return false
        return try {
            val s = Ed25519Signer()
            s.init(false, Ed25519PublicKeyParameters(pub, 0))
            s.update(msg, 0, msg.size)
            s.verifySignature(sig)
        } catch (e: RuntimeException) {
            false
        }
    }

    private val P = java.math.BigInteger.ONE.shiftLeft(255) - java.math.BigInteger.valueOf(19)
    private val L = java.math.BigInteger.ONE.shiftLeft(252) + java.math.BigInteger("27742317777372353535851937790883648493")
    private val SMALL_ORDER_Y: Set<java.math.BigInteger> = setOf(
        java.math.BigInteger.ZERO, java.math.BigInteger.ONE, P - java.math.BigInteger.ONE,
        le(Hex.decode("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")),
        le(Hex.decode("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")),
    )

    private fun le(b: ByteArray): java.math.BigInteger = java.math.BigInteger(1, b.reversedArray())

    /** Canonical (`y < p`, `x = 0` only with the sign bit clear) and not one of the 8 torsion points. */
    private fun strictPoint(enc: ByteArray): Boolean {
        val raw = enc.copyOf()
        val signBit = raw[31].toInt() and 0x80 != 0
        raw[31] = (raw[31].toInt() and 0x7f).toByte()
        val y = le(raw)
        if (y >= P) return false
        if (signBit && (y == java.math.BigInteger.ONE || y == P - java.math.BigInteger.ONE)) return false
        return y !in SMALL_ORDER_Y
    }

    /**
     * libsodium `crypto_sign_verify_detached` rules (feature pack contract §5.2): `S < L`, canonical non-small-order
     * `A` and `R`, then the cofactorless equation (Bouncy Castle).
     */
    fun verifyStrict(sig: ByteArray, msg: ByteArray, pub: ByteArray): Boolean {
        if (pub.size != 32 || sig.size != 64) return false
        if (le(sig.copyOfRange(32, 64)) >= L) return false
        if (!strictPoint(pub) || !strictPoint(sig.copyOfRange(0, 32))) return false
        return verify(sig, msg, pub)
    }
}

object X25519 {
    fun publicKey(priv: ByteArray): ByteArray {
        require(priv.size == 32) { "bad private key" }
        return X25519PrivateKeyParameters(priv, 0).generatePublicKey().encoded
    }

    /**
     * Raw shared secret. Throws [IllegalArgumentException] on a malformed key or an all-zero result
     * (low-order peer key), where the Swift code throws `malformed`.
     */
    fun agree(priv: ByteArray, pub: ByteArray): ByteArray {
        require(priv.size == 32 && pub.size == 32) { "bad key length" }
        val out = ByteArray(32)
        try {
            val a = X25519Agreement()
            a.init(X25519PrivateKeyParameters(priv, 0))
            a.calculateAgreement(X25519PublicKeyParameters(pub, 0), out, 0)
        } catch (e: IllegalStateException) {
            // Bouncy Castle itself refuses an all-zero agreement.
            throw IllegalArgumentException("low-order peer key")
        }
        require(out.any { it.toInt() != 0 }) { "all-zero shared secret" }
        return out
    }
}
