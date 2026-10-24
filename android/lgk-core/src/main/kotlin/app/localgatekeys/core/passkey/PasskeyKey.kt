package app.localgatekeys.core.passkey

import app.localgatekeys.core.primitives.Base64Url
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec

class PasskeyKeyException(val kind: Kind) : Exception(kind.name) {
    enum class Kind { BAD_CLIENT_DATA_HASH }
}

/**
 * An ES256 passkey private key, stored as unpadded base64url PKCS#8 DER (desktop `create_credential`).
 * Port of Swift `PasskeyKey`. The base64url string is key material: keep its lifetime short and never log it.
 */
class PasskeyKey private constructor(private val d: BigInteger) {
    private val privateKey: PrivateKey = factory().generatePrivate(ECPrivateKeySpec(d, params))

    private val point: ECPoint by lazy {
        val p = curve.g.multiply(d).normalize()
        ECPoint(p.affineXCoord.toBigInteger(), p.affineYCoord.toBigInteger())
    }

    /** The public key, derived from the private scalar. */
    val publicKey: ECPublicKey
        get() = factory().generatePublic(ECPublicKeySpec(point, params)) as ECPublicKey

    /**
     * The PKCS#8 encoding the desktop's `cryptography` (and CryptoKit) write: version 0, id-ecPublicKey with
     * prime256v1, and an ECPrivateKey carrying the 32-byte scalar and the uncompressed public point.
     */
    val pkcs8B64Url: String
        get() {
            val pub = byteArrayOf(0x04) + Passkey.coordinate(point.affineX) + Passkey.coordinate(point.affineY)
            val der = PKCS8_PREFIX + Passkey.coordinate(d) + PKCS8_MIDDLE + pub
            return Base64Url.encodeNoPad(der)
        }

    /**
     * DER ECDSA-SHA256 over `authData || clientDataHash`. Throws [PasskeyKeyException] unless the hash is
     * 32 bytes (SHA-256 of clientDataJSON).
     */
    fun sign(authData: ByteArray, clientDataHash: ByteArray): ByteArray {
        if (clientDataHash.size != 32) throw PasskeyKeyException(PasskeyKeyException.Kind.BAD_CLIENT_DATA_HASH)
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(privateKey)
        sig.update(authData + clientDataHash)
        return sig.sign()
    }

    /** Equal when the private scalar is equal (compared in constant time). */
    override fun equals(other: Any?): Boolean =
        other is PasskeyKey && java.security.MessageDigest.isEqual(Passkey.coordinate(d), Passkey.coordinate(other.d))

    override fun hashCode(): Int = point.affineX.hashCode() xor point.affineY.hashCode()

    /** No key material. */
    override fun toString(): String = "PasskeyKey"

    companion object {
        private val PKCS8_PREFIX = byteArrayOf(
            0x30, 0x81.toByte(), 0x87.toByte(), 0x02, 0x01, 0x00,
            0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07,
            0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
        )
        private val PKCS8_MIDDLE = byteArrayOf(0xa1.toByte(), 0x44, 0x03, 0x42, 0x00)

        private val params: ECParameterSpec by lazy {
            val ap = AlgorithmParameters.getInstance("EC")
            ap.init(ECGenParameterSpec("secp256r1"))
            ap.getParameterSpec(ECParameterSpec::class.java)
        }

        private val curve = org.bouncycastle.crypto.ec.CustomNamedCurves.getByName("secp256r1")

        private fun factory(): KeyFactory = KeyFactory.getInstance("EC")

        /** True only for the P-256 curve (same field, coefficients, generator and order). */
        private fun isP256(p: ECParameterSpec): Boolean =
            p.curve == params.curve && p.generator == params.generator && p.order == params.order && p.cofactor == params.cofactor

        /**
         * null where desktop `_load_private_key` returns None: bad base64url, not a P-256 key (RSA, Ed25519,
         * other curves and garbage included).
         */
        fun fromPkcs8B64Url(s: String): PasskeyKey? {
            val der = Base64Url.decodeLenient(s, 4096) ?: return null
            try {
                val key = factory().generatePrivate(PKCS8EncodedKeySpec(der)) as? ECPrivateKey ?: return null
                if (!isP256(key.params)) return null
                val d = key.s
                if (d.signum() <= 0 || d >= params.order) return null
                return PasskeyKey(d)
            } catch (e: Exception) {
                return null
            } finally {
                der.fill(0)
            }
        }

        fun generate(): PasskeyKey {
            val gen = KeyPairGenerator.getInstance("EC")
            gen.initialize(ECGenParameterSpec("secp256r1"))
            return PasskeyKey((gen.generateKeyPair().private as ECPrivateKey).s)
        }
    }
}
