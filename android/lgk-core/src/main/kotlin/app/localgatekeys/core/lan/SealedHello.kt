package app.localgatekeys.core.lan

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.CryptoBoxException
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.X25519

private fun authentication(detail: String) = LanTransportException(LanTransportException.Kind.AUTHENTICATION, detail)

private fun malformed(detail: String) = LanTransportException(LanTransportException.Kind.MALFORMED, detail)

/**
 * The sealing secret of one sealed-hello exchange (desktop `transport.SealContext`): `es = X25519(x_i, S_R)`,
 * `X_i` and `S_R`. Kept only for the length of one handshake; [wipe] zeroes the secret.
 */
class SealContext internal constructor(shared: ByteArray, initiatorEphemeral: ByteArray, responderStatic: ByteArray) {
    private var shared: ByteArray? = shared.copyOf()
    private val eph: ByteArray = initiatorEphemeral.copyOf()
    private val static: ByteArray = responderStatic.copyOf()

    val initiatorEphemeral: ByteArray get() = eph.copyOf()
    val responderStatic: ByteArray get() = static.copyOf()

    /** `HKDF-SHA256(ikm = es, salt = X_i ‖ S_R, info = label ‖ role, 32)`. */
    @Synchronized
    fun key(role: SecureChannel.Role): ByteArray {
        val es = shared ?: throw authentication("Sealed hello secret was already wiped")
        return CryptoBox.hkdf(es, eph + static, SealedHello.LABEL + role.wire.toByteArray(Charsets.US_ASCII), 32)
    }

    fun aad(): ByteArray = SealedHello.LABEL + eph

    @Synchronized
    fun wipe() {
        shared?.fill(0)
        shared = null
    }

    /** Never shows key material. */
    override fun toString(): String = "SealContext(<redacted>)"
}

/**
 * The sealed hello of LAN protocol version 3 (`docs/formats/LAN_SYNC_V3.md` section 2.2; desktop
 * `seal_initiator_hello` / `open_initiator_hello` / `seal_responder_hello` / `open_responder_hello`).
 * The initiator's first frame is `{"box","eph","signature":"","version":3}`, the responder's answer
 * `{"box","version":3}`; each box is AES-256-GCM (12 zero bytes nonce) over a 1024-byte padded version-3 hello.
 */
object SealedHello {
    /** u16be length + inner hello + zero bytes. */
    const val PLAINTEXT_BYTES: Int = 1024
    const val BOX_BYTES: Int = PLAINTEXT_BYTES + 16

    internal val LABEL: ByteArray = "localgatekeys|sync|sealed-hello|v3|".toByteArray(Charsets.US_ASCII)
    private val NONCE = ByteArray(12)
    internal val FIELDS = setOf("box", "eph", "signature", "version")
    internal val REPLY_FIELDS = setOf("box", "version")

    /** The padded plaintext of [hello]: `u16be(len) ‖ hello ‖ zero bytes`, exactly [PLAINTEXT_BYTES]. */
    fun pad(hello: SessionHello): ByteArray {
        val inner = hello.toBytes()
        val room = PLAINTEXT_BYTES - 2
        if (inner.size > room) {
            throw LanTransportException(LanTransportException.Kind.TOO_LARGE, "Session hello does not fit a sealed hello")
        }
        val out = ByteArray(PLAINTEXT_BYTES)
        out[0] = (inner.size ushr 8).toByte()
        out[1] = inner.size.toByte()
        inner.copyInto(out, 2)
        return out
    }

    /** The version-3 hello of a padded plaintext: length 1 ... 1022, every padding byte zero, strict parse. */
    fun unpad(plain: ByteArray): SessionHello {
        if (plain.size != PLAINTEXT_BYTES) throw malformed("Sealed hello is malformed")
        val length = ((plain[0].toInt() and 0xFF) shl 8) or (plain[1].toInt() and 0xFF)
        if (length !in 1..(PLAINTEXT_BYTES - 2)) throw malformed("Sealed hello padding is malformed")
        for (i in 2 + length until PLAINTEXT_BYTES) {
            if (plain[i].toInt() != 0) throw malformed("Sealed hello padding is malformed")
        }
        return SessionHello.parse(plain.copyOfRange(2, 2 + length), LanTransport.VERSION)
    }

    /**
     * The initiator's first frame payload (no length prefix) and its [SealContext]: [hello] (version 3)
     * sealed to [responderExchangePublic]. Draws the 32-byte one-connection X25519 private key from [random].
     */
    fun sealInitiator(hello: SessionHello, responderExchangePublic: ByteArray, random: RandomSource): Pair<ByteArray, SealContext> {
        val ephemeral = random.bytes(32)
        try {
            return sealInitiator(hello, responderExchangePublic, ephemeral)
        } finally {
            ephemeral.fill(0)
        }
    }

    /** [sealInitiator] with a given ephemeral private key (the vectors). */
    internal fun sealInitiator(
        hello: SessionHello,
        responderExchangePublic: ByteArray,
        ephemeralPrivate: ByteArray,
    ): Pair<ByteArray, SealContext> {
        if (hello.version != LanTransport.VERSION) throw authentication("A version-3 session hello is required")
        if (responderExchangePublic.size != 32) throw authentication("Peer exchange key is malformed")
        if (ephemeralPrivate.size != 32) throw authentication("Sealed hello ephemeral key is malformed")
        val ephPublic = try {
            X25519.publicKey(ephemeralPrivate)
        } catch (e: RuntimeException) {
            throw authentication("Sealed hello ephemeral key is malformed")
        }
        val es = try {
            X25519.agree(ephemeralPrivate, responderExchangePublic)
        } catch (e: RuntimeException) {
            throw authentication("Peer exchange key is malformed")
        }
        try {
            if (es.all { it.toInt() == 0 }) throw authentication("Peer exchange key is malformed")
            val context = SealContext(es, ephPublic, responderExchangePublic)
            val box = box(context, SecureChannel.Role.INITIATOR, pad(hello))
            val payload = LanTransport.canonical(
                JsonValue.Obj(
                    mapOf(
                        "box" to JsonValue.Str(Base64Std.encode(box)),
                        "eph" to JsonValue.Str(Base64Std.encode(ephPublic)),
                        "signature" to JsonValue.Str(""),
                        "version" to JsonValue.Int(LanTransport.VERSION),
                    ),
                ),
            )
            return payload to context
        } finally {
            es.fill(0)
        }
    }

    /**
     * Responder side: the hello inside a sealed first frame [payload] (no length prefix) to [identity], and
     * its [SealContext]. Throws [LanTransportException] for anything that is not exactly a sealed hello to
     * this device; the caller closes the connection without an answer.
     */
    fun openInitiator(payload: ByteArray, identity: DeviceIdentity): Pair<SessionHello, SealContext> {
        if (payload.size > LanTransport.MAX_FIRST_FRAME_BYTES) {
            throw LanTransportException(LanTransportException.Kind.TOO_LARGE, "Sealed hello exceeds the bound")
        }
        val raw = parse(payload)
        if (raw == null || raw.keys != FIELDS || raw["version"] != JsonValue.Int(LanTransport.VERSION) ||
            raw["signature"] != JsonValue.Str("")
        ) {
            throw malformed("Sealed hello is malformed")
        }
        val ephPublic = LanTransport.b64(raw["eph"], 32, "sealed hello key")
        val box = LanTransport.b64(raw["box"], BOX_BYTES, "sealed hello")
        val es = try {
            identity.exchange(ephPublic)
        } catch (e: DeviceIdentityException) {
            throw authentication("Peer sealed hello key is malformed")
        }
        val context = try {
            SealContext(es, ephPublic, identity.exchangePublicKey)
        } finally {
            es.fill(0)
        }
        val plain = try {
            open(context, SecureChannel.Role.INITIATOR, box)
        } catch (e: LanTransportException) {
            context.wipe()
            throw authentication("Sealed hello is not for this device")
        }
        try {
            return unpad(plain) to context
        } catch (e: LanTransportException) {
            context.wipe()
            throw e
        }
    }

    /** The responder's answer payload `{"box","version":3}`: its version-3 [hello] sealed under [context]. */
    fun sealResponder(hello: SessionHello, context: SealContext): ByteArray {
        if (hello.version != LanTransport.VERSION) throw authentication("A version-3 session hello is required")
        val box = box(context, SecureChannel.Role.RESPONDER, pad(hello))
        return LanTransport.canonical(
            JsonValue.Obj(mapOf("box" to JsonValue.Str(Base64Std.encode(box)), "version" to JsonValue.Int(LanTransport.VERSION))),
        )
    }

    /** Initiator side: the responder's version-3 hello from its sealed answer [payload] (no length prefix). */
    fun openResponder(payload: ByteArray, context: SealContext): SessionHello {
        if (payload.size > LanTransport.MAX_FIRST_FRAME_BYTES) {
            throw LanTransportException(LanTransportException.Kind.TOO_LARGE, "Sealed hello exceeds the bound")
        }
        val raw = parse(payload)
        if (raw == null || raw.keys != REPLY_FIELDS || raw["version"] != JsonValue.Int(LanTransport.VERSION)) {
            throw malformed("Sealed hello is malformed")
        }
        val box = LanTransport.b64(raw["box"], BOX_BYTES, "sealed hello")
        val plain = try {
            open(context, SecureChannel.Role.RESPONDER, box)
        } catch (e: LanTransportException) {
            throw authentication("Sealed hello answer is not from the expected peer")
        }
        return unpad(plain)
    }

    private fun parse(payload: ByteArray): Map<String, JsonValue>? = try {
        (CanonicalJson.parse(payload) as? JsonValue.Obj)?.fields
    } catch (e: JsonException) {
        null
    }

    private fun box(context: SealContext, role: SecureChannel.Role, plain: ByteArray): ByteArray {
        val key = context.key(role)
        try {
            return CryptoBox.sealGcm(key, NONCE, plain, context.aad())
        } finally {
            key.fill(0)
        }
    }

    private fun open(context: SealContext, role: SecureChannel.Role, box: ByteArray): ByteArray {
        val key = context.key(role)
        try {
            return CryptoBox.openGcm(key, NONCE, box, context.aad())
        } catch (e: CryptoBoxException) {
            throw authentication("Sealed hello authentication failed")
        } finally {
            key.fill(0)
        }
    }
}
