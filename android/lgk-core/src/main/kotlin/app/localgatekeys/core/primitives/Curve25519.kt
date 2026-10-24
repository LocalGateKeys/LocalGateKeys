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
