package app.localgatekeys.core.lan

import app.localgatekeys.core.primitives.Ed25519
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.X25519
import java.security.MessageDigest

/** Swift `DeviceIdentity.Error.malformed`. */
class DeviceIdentityException : Exception("malformed")

/**
 * Long-lived device keys (desktop `sync.pairing.DeviceIdentity`): an Ed25519 signing key and an
 * X25519 exchange key, held as raw 32-byte private keys.
 */
class DeviceIdentity(val deviceId: String, signingPrivate: ByteArray, exchangePrivate: ByteArray) {
    private val signingPriv: ByteArray = signingPrivate.copyOf()
    private val exchangePriv: ByteArray = exchangePrivate.copyOf()
    private val signingPub: ByteArray
    private val exchangePub: ByteArray

    init {
        if (!Identifier.isValid(deviceId) || signingPrivate.size != 32 || exchangePrivate.size != 32) {
            throw DeviceIdentityException()
        }
        try {
            signingPub = Ed25519.publicKey(signingPriv)
            exchangePub = X25519.publicKey(exchangePriv)
        } catch (e: RuntimeException) {
            throw DeviceIdentityException()
        }
    }

    val signingPrivateKey: ByteArray get() = signingPriv.copyOf()
    val exchangePrivateKey: ByteArray get() = exchangePriv.copyOf()
    val signingPublicKey: ByteArray get() = signingPub.copyOf()
    val exchangePublicKey: ByteArray get() = exchangePub.copyOf()

    /** Lowercase hex SHA-256 of the raw Ed25519 public key. */
    val fingerprint: String get() = Hex.lower(MessageDigest.getInstance("SHA-256").digest(signingPub))

    /** Raw X25519 shared secret with [peerPublic]; throws [DeviceIdentityException] on a malformed or low-order peer key. */
    internal fun exchange(peerPublic: ByteArray): ByteArray {
        if (peerPublic.size != 32) throw DeviceIdentityException()
        val raw = try {
            X25519.agree(exchangePriv, peerPublic)
        } catch (e: RuntimeException) {
            throw DeviceIdentityException()
        }
        if (raw.none { it.toInt() != 0 }) throw DeviceIdentityException()
        return raw
    }

    /** Ed25519 signature of [msg] (RFC 8032 deterministic). */
    fun sign(msg: ByteArray): ByteArray = try {
        Ed25519.sign(signingPriv, msg)
    } catch (e: RuntimeException) {
        throw DeviceIdentityException()
    }

    override fun equals(other: Any?): Boolean =
        other is DeviceIdentity && deviceId == other.deviceId &&
            signingPriv.contentEquals(other.signingPriv) && exchangePriv.contentEquals(other.exchangePriv)

    override fun hashCode(): Int = (deviceId.hashCode() * 31 + signingPub.contentHashCode()) * 31 + exchangePub.contentHashCode()

    /** Never shows key material. */
    override fun toString(): String = "DeviceIdentity(deviceId=$deviceId, fingerprint=$fingerprint)"

    companion object {
        /** A new identity; the device id defaults to a random UUID4 (lowercase, hyphenated). */
        fun generate(deviceId: String? = null, random: RandomSource): DeviceIdentity {
            val id = if (deviceId != null) deviceId else {
                val u = random.bytes(16)
                if (u.size != 16) throw DeviceIdentityException()
                u[6] = ((u[6].toInt() and 0x0F) or 0x40).toByte()
                u[8] = ((u[8].toInt() and 0x3F) or 0x80).toByte()
                val h = Hex.lower(u)
                h.substring(0, 8) + "-" + h.substring(8, 12) + "-" + h.substring(12, 16) + "-" + h.substring(16, 20) + "-" + h.substring(20, 32)
            }
            return DeviceIdentity(id, random.bytes(32), random.bytes(32))
        }

        /** True when [signature] is a valid Ed25519 signature of [message] by the raw [publicKey]. */
        fun verify(signature: ByteArray, message: ByteArray, publicKey: ByteArray): Boolean =
            Ed25519.verify(signature, message, publicKey)
    }
}
