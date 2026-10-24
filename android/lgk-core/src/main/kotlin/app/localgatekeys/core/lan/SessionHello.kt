package app.localgatekeys.core.lan

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.X25519
import java.security.MessageDigest

private fun authentication(detail: String) = LanTransportException(LanTransportException.Kind.AUTHENTICATION, detail)

private fun malformed(detail: String) = LanTransportException(LanTransportException.Kind.MALFORMED, detail)

/**
 * The X25519 ephemeral private key of one local session hello (desktop `transport.EphemeralSecret`),
 * usable for exactly one derivation: [take] hands the bytes to the derivation and then fills them
 * with zeros; [wipe] zeroes them unused (a failed handshake). A second use throws.
 */
internal class EphemeralSecret(privateKey: ByteArray) {
    private var key: ByteArray? = privateKey.copyOf()

    val used: Boolean @Synchronized get() = key == null

    @Synchronized
    fun <T> take(block: (ByteArray) -> T): T {
        val k = key ?: throw authentication("Session ephemeral key was already used or wiped")
        key = null
        try {
            return block(k)
        } finally {
            k.fill(0)
        }
    }

    @Synchronized
    fun wipe() {
        key?.fill(0)
        key = null
    }

    /** Never shows key material. */
    override fun toString(): String = "EphemeralSecret(<redacted>)"
}

/**
 * The signed hello each side sends first on a LAN connection (desktop `transport.SessionHello`,
 * protocol version 2). [ephemeralPublic] is a fresh X25519 key per hello; a hello this device made
 * also holds the matching private key ([ephemeralSecret]: never serialised, never compared).
 */
class SessionHello internal constructor(
    sessionId: ByteArray,
    val groupId: String,
    val deviceId: String,
    signingPublic: ByteArray,
    exchangePublic: ByteArray,
    ephemeralPublic: ByteArray,
    nonce: ByteArray,
    val counter: Long,
    signature: ByteArray,
    internal val ephemeralSecret: EphemeralSecret?,
) {
    /** A hello without an ephemeral private key (a parsed or test hello: it can never derive a key). */
    constructor(
        sessionId: ByteArray,
        groupId: String,
        deviceId: String,
        signingPublic: ByteArray,
        exchangePublic: ByteArray,
        ephemeralPublic: ByteArray,
        nonce: ByteArray,
        counter: Long,
        signature: ByteArray,
    ) : this(sessionId, groupId, deviceId, signingPublic, exchangePublic, ephemeralPublic, nonce, counter, signature, null)

    private val sessionIdBytes: ByteArray = sessionId.copyOf()
    val sessionId: ByteArray get() = sessionIdBytes.copyOf()
    private val signingPublicBytes: ByteArray = signingPublic.copyOf()
    val signingPublic: ByteArray get() = signingPublicBytes.copyOf()
    private val exchangePublicBytes: ByteArray = exchangePublic.copyOf()
    val exchangePublic: ByteArray get() = exchangePublicBytes.copyOf()
    private val ephemeralPublicBytes: ByteArray = ephemeralPublic.copyOf()
    val ephemeralPublic: ByteArray get() = ephemeralPublicBytes.copyOf()
    private val nonceBytes: ByteArray = nonce.copyOf()
    val nonce: ByteArray get() = nonceBytes.copyOf()
    private val signatureBytes: ByteArray = signature.copyOf()
    val signature: ByteArray get() = signatureBytes.copyOf()

    internal val unsignedJson: Map<String, JsonValue>
        get() = mapOf(
            "version" to JsonValue.Int(LanTransport.VERSION),
            "session_id" to JsonValue.Str(Base64Std.encode(sessionId)),
            "group_id" to JsonValue.Str(groupId),
            "device_id" to JsonValue.Str(deviceId),
            "signing_public" to JsonValue.Str(Base64Std.encode(signingPublic)),
            "exchange_public" to JsonValue.Str(Base64Std.encode(exchangePublic)),
            "ephemeral_public" to JsonValue.Str(Base64Std.encode(ephemeralPublic)),
            "nonce" to JsonValue.Str(Base64Std.encode(nonce)),
            "counter" to JsonValue.Int(counter),
        )

    /** The signed text: label + canonical JSON of the hello without `signature`. */
    fun signingBytes(): ByteArray = LABEL + LanTransport.canonical(JsonValue.Obj(unsignedJson))

    /** Canonical JSON of the whole hello (the transcript uses this form). */
    fun toBytes(): ByteArray =
        LanTransport.canonical(JsonValue.Obj(unsignedJson + ("signature" to JsonValue.Str(Base64Std.encode(signature)))))

    override fun equals(other: Any?): Boolean =
        other is SessionHello && sessionId.contentEquals(other.sessionId) && groupId == other.groupId &&
            deviceId == other.deviceId && signingPublic.contentEquals(other.signingPublic) &&
            exchangePublic.contentEquals(other.exchangePublic) && ephemeralPublic.contentEquals(other.ephemeralPublic) &&
            nonce.contentEquals(other.nonce) && counter == other.counter && signature.contentEquals(other.signature)

    override fun hashCode(): Int {
        var h = sessionId.contentHashCode()
        h = 31 * h + groupId.hashCode()
        h = 31 * h + deviceId.hashCode()
        h = 31 * h + signingPublic.contentHashCode()
        h = 31 * h + exchangePublic.contentHashCode()
        h = 31 * h + ephemeralPublic.contentHashCode()
        h = 31 * h + nonce.contentHashCode()
        h = 31 * h + counter.hashCode()
        h = 31 * h + signature.contentHashCode()
        return h
    }

    companion object {
        internal val FIELDS = setOf(
            "counter", "device_id", "ephemeral_public", "exchange_public", "group_id", "nonce", "session_id",
            "signature", "signing_public", "version",
        )
        internal val LABEL: ByteArray = "localgatekeys|sync|session-hello|v2|".toByteArray(Charsets.UTF_8)

        /**
         * A signed hello of [identity]; draws the 32-byte hello nonce, then the 32-byte X25519
         * ephemeral private key, from [random]. The private key stays in the hello for one derivation.
         */
        fun make(identity: DeviceIdentity, groupId: String, sessionId: ByteArray, counter: Long, random: RandomSource): SessionHello {
            if (groupId.isEmpty() || sessionId.size != LanTransport.SESSION_ID_BYTES || counter < 0) {
                throw authentication("Session hello input is malformed")
            }
            val nonce = random.bytes(32)
            if (nonce.size != 32) throw malformed("session nonce is malformed")
            val ephemeral = random.bytes(32)
            try {
                if (ephemeral.size != 32) throw authentication("Session ephemeral key is malformed")
                val ephemeralPublic = try {
                    X25519.publicKey(ephemeral)
                } catch (e: RuntimeException) {
                    throw authentication("Session ephemeral key is malformed")
                }
                val unsigned = SessionHello(
                    sessionId, groupId, identity.deviceId, identity.signingPublicKey, identity.exchangePublicKey,
                    ephemeralPublic, nonce, counter, ByteArray(0),
                )
                return SessionHello(
                    sessionId, groupId, identity.deviceId, identity.signingPublicKey, identity.exchangePublicKey,
                    ephemeralPublic, nonce, counter, identity.sign(unsigned.signingBytes()), EphemeralSecret(ephemeral),
                )
            } finally {
                ephemeral.fill(0)
            }
        }

        /**
         * The version announced by a first frame that is a signed hello of ANOTHER version (a JSON
         * object with `signature` and an integer `version` != 2), else null. Such a hello is never
         * parsed further or used for a key; the caller reports "update needed".
         */
        fun otherVersion(bytes: ByteArray): Long? {
            if (bytes.size > LanTransport.MAX_MESSAGE_BYTES) return null
            val o = try {
                (CanonicalJson.parse(bytes) as? JsonValue.Obj)?.fields
            } catch (e: JsonException) {
                null
            } ?: return null
            val v = (o["version"] as? JsonValue.Int)?.v ?: return null
            return if (v != LanTransport.VERSION && "signature" in o) v else null
        }

        /**
         * Strict parse (`SessionHello.from_bytes`): exact field set, duplicate keys refused, `version`
         * the JSON integer 2 (a version-1 hello is refused), canonical base64 with exact lengths,
         * `counter` an integer 0 ... 2^63-1.
         */
        fun parse(bytes: ByteArray): SessionHello {
            if (bytes.size > LanTransport.MAX_MESSAGE_BYTES) {
                throw LanTransportException(LanTransportException.Kind.TOO_LARGE, "Session hello exceeds the bound")
            }
            val o = try {
                (CanonicalJson.parse(bytes) as? JsonValue.Obj)?.fields
            } catch (e: JsonException) {
                null
            }
            if (o == null || o.keys != FIELDS) throw malformed("Session hello is malformed")
            if (o["version"] != JsonValue.Int(LanTransport.VERSION)) throw malformed("Unsupported session hello")
            val counter = (o["counter"] as? JsonValue.Int)?.v
            if (counter == null || counter < 0) throw malformed("Session hello counter is malformed")
            val group = (o["group_id"] as? JsonValue.Str)?.v
            val device = (o["device_id"] as? JsonValue.Str)?.v
            if (group == null || device == null) throw malformed("Session hello is malformed")
            return SessionHello(
                LanTransport.b64(o["session_id"], LanTransport.SESSION_ID_BYTES, "session id"),
                group,
                device,
                LanTransport.b64(o["signing_public"], 32, "signing public key"),
                LanTransport.b64(o["exchange_public"], 32, "exchange public key"),
                LanTransport.b64(o["ephemeral_public"], 32, "ephemeral public key"),
                LanTransport.b64(o["nonce"], 32, "session nonce"),
                counter,
                LanTransport.b64(o["signature"], 64, "session signature"),
            )
        }

        /**
         * `verify_session_hello`: group, device id, signing key, fingerprint and exchange key must be
         * exactly the pinned ones; the ephemeral key must be neither all zero nor the exchange key;
         * then the Ed25519 signature.
         */
        fun verify(hello: SessionHello, pinned: PinnedPeer, groupId: String) {
            if (hello.groupId != groupId || hello.groupId != pinned.groupId) throw authentication("Session group mismatch")
            if (hello.deviceId != pinned.deviceId || !hello.signingPublic.contentEquals(pinned.signingPublic)) {
                throw authentication("Session device key is not pinned")
            }
            if (Hex.lower(MessageDigest.getInstance("SHA-256").digest(hello.signingPublic)) != pinned.fingerprint) {
                throw authentication("Session device fingerprint is not pinned")
            }
            if (!hello.exchangePublic.contentEquals(pinned.exchangePublic)) throw authentication("Session exchange key is not pinned")
            val eph = hello.ephemeralPublic
            if (eph.all { it.toInt() == 0 } || eph.contentEquals(hello.exchangePublic)) {
                throw authentication("Session ephemeral key is malformed")
            }
            if (!DeviceIdentity.verify(hello.signature, hello.signingBytes(), hello.signingPublic)) {
                throw authentication("Session hello signature is invalid")
            }
        }
    }
}
