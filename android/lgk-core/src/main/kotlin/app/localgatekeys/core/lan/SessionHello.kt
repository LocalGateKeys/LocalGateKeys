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
 * The signed hello each side sends first on a LAN connection (desktop `transport.SessionHello`).
 * [version] 2 is the clear-text hello of released builds; 3 is the same hello inside a sealed first
 * frame ([SealedHello], `docs/formats/LAN_SYNC_V3.md`), signed under the `v3` label. [ephemeralPublic]
 * is a fresh X25519 key per hello; a hello this device made also holds the matching private key
 * ([ephemeralSecret]: never serialised, never compared).
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
    val version: Long,
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
        version: Long = LanTransport.PLAIN_HELLO_VERSION,
    ) : this(sessionId, groupId, deviceId, signingPublic, exchangePublic, ephemeralPublic, nonce, counter, signature, version, null)

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
            "version" to JsonValue.Int(version),
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
    fun signingBytes(): ByteArray = label(version) + LanTransport.canonical(JsonValue.Obj(unsignedJson))

    /** Canonical JSON of the whole hello (the transcript uses this form). */
    fun toBytes(): ByteArray =
        LanTransport.canonical(JsonValue.Obj(unsignedJson + ("signature" to JsonValue.Str(Base64Std.encode(signature)))))

    override fun equals(other: Any?): Boolean =
        other is SessionHello && sessionId.contentEquals(other.sessionId) && groupId == other.groupId &&
            deviceId == other.deviceId && signingPublic.contentEquals(other.signingPublic) &&
            exchangePublic.contentEquals(other.exchangePublic) && ephemeralPublic.contentEquals(other.ephemeralPublic) &&
            nonce.contentEquals(other.nonce) && counter == other.counter && signature.contentEquals(other.signature) &&
            version == other.version

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
        internal val LABEL_V3: ByteArray = "localgatekeys|sync|session-hello|v3|".toByteArray(Charsets.UTF_8)

        /** The signature label of a hello [version] (2 or 3); any other version is refused. */
        internal fun label(version: Long): ByteArray = when (version) {
            LanTransport.PLAIN_HELLO_VERSION -> LABEL
            LanTransport.VERSION -> LABEL_V3
            else -> throw authentication("Session hello version is not supported")
        }

        /**
         * A signed hello of [identity]; draws the 32-byte hello nonce, then the 32-byte X25519
         * ephemeral private key, from [random]. The private key stays in the hello for one derivation.
         * [version] 3 is the hello sent inside a sealed frame ([SealedHello.sealInitiator]).
         */
        fun make(
            identity: DeviceIdentity,
            groupId: String,
            sessionId: ByteArray,
            counter: Long,
            random: RandomSource,
            version: Long = LanTransport.PLAIN_HELLO_VERSION,
        ): SessionHello {
            label(version)
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
                    ephemeralPublic, nonce, counter, ByteArray(0), version,
                )
                return SessionHello(
                    sessionId, groupId, identity.deviceId, identity.signingPublicKey, identity.exchangePublicKey,
                    ephemeralPublic, nonce, counter, identity.sign(unsigned.signingBytes()), version, EphemeralSecret(ephemeral),
                )
            } finally {
                ephemeral.fill(0)
            }
        }

        /**
         * The version announced by a first frame that is not a clear-text version-2 hello (a JSON
         * object with `signature` and an integer `version` != 2: a signed hello of another version, or
         * a sealed version-3 frame, whose `signature` is empty), else null (desktop `HelloVersionError`).
         * Such a frame is never parsed as a clear-text hello or used for a key.
         */
        fun otherVersion(bytes: ByteArray): Long? {
            if (bytes.size > LanTransport.MAX_MESSAGE_BYTES) return null
            val o = try {
                (CanonicalJson.parse(bytes) as? JsonValue.Obj)?.fields
            } catch (e: JsonException) {
                null
            } ?: return null
            val v = (o["version"] as? JsonValue.Int)?.v ?: return null
            return if (v != LanTransport.PLAIN_HELLO_VERSION && "signature" in o) v else null
        }

        /**
         * Strict parse (`SessionHello.from_bytes`): exact field set, duplicate keys refused, `version`
         * the JSON integer [version] (2: a clear-text first frame; 3: the inside of a sealed one; any
         * other hello is refused), canonical base64 with exact lengths, `counter` an integer 0 ... 2^63-1.
         */
        fun parse(bytes: ByteArray, version: Long = LanTransport.PLAIN_HELLO_VERSION): SessionHello {
            if (bytes.size > LanTransport.MAX_MESSAGE_BYTES) {
                throw LanTransportException(LanTransportException.Kind.TOO_LARGE, "Session hello exceeds the bound")
            }
            val o = try {
                (CanonicalJson.parse(bytes) as? JsonValue.Obj)?.fields
            } catch (e: JsonException) {
                null
            }
            if (o == null || o.keys != FIELDS) throw malformed("Session hello is malformed")
            if ((version != LanTransport.PLAIN_HELLO_VERSION && version != LanTransport.VERSION) ||
                o["version"] != JsonValue.Int(version)
            ) {
                throw malformed("Unsupported session hello")
            }
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
                version,
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
