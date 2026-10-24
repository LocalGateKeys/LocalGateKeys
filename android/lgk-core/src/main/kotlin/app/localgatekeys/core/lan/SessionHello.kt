package app.localgatekeys.core.lan

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.RandomSource
import java.security.MessageDigest

private fun authentication(detail: String) = LanTransportException(LanTransportException.Kind.AUTHENTICATION, detail)

private fun malformed(detail: String) = LanTransportException(LanTransportException.Kind.MALFORMED, detail)

/** The signed hello each side sends first on a LAN connection (desktop `transport.SessionHello`). */
class SessionHello(
    sessionId: ByteArray,
    val groupId: String,
    val deviceId: String,
    signingPublic: ByteArray,
    exchangePublic: ByteArray,
    nonce: ByteArray,
    val counter: Long,
    signature: ByteArray,
) {
    private val sessionIdBytes: ByteArray = sessionId.copyOf()
    val sessionId: ByteArray get() = sessionIdBytes.copyOf()
    private val signingPublicBytes: ByteArray = signingPublic.copyOf()
    val signingPublic: ByteArray get() = signingPublicBytes.copyOf()
    private val exchangePublicBytes: ByteArray = exchangePublic.copyOf()
    val exchangePublic: ByteArray get() = exchangePublicBytes.copyOf()
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
            exchangePublic.contentEquals(other.exchangePublic) && nonce.contentEquals(other.nonce) &&
            counter == other.counter && signature.contentEquals(other.signature)

    override fun hashCode(): Int {
        var h = sessionId.contentHashCode()
        h = 31 * h + groupId.hashCode()
        h = 31 * h + deviceId.hashCode()
        h = 31 * h + signingPublic.contentHashCode()
        h = 31 * h + exchangePublic.contentHashCode()
        h = 31 * h + nonce.contentHashCode()
        h = 31 * h + counter.hashCode()
        h = 31 * h + signature.contentHashCode()
        return h
    }

    companion object {
        internal val FIELDS = setOf(
            "counter", "device_id", "exchange_public", "group_id", "nonce", "session_id",
            "signature", "signing_public", "version",
        )
        internal val LABEL: ByteArray = "localgatekeys|sync|session-hello|v1|".toByteArray(Charsets.UTF_8)

        /** A signed hello of [identity]; draws the 32-byte hello nonce from [random]. */
        fun make(identity: DeviceIdentity, groupId: String, sessionId: ByteArray, counter: Long, random: RandomSource): SessionHello {
            if (groupId.isEmpty() || sessionId.size != LanTransport.SESSION_ID_BYTES || counter < 0) {
                throw authentication("Session hello input is malformed")
            }
            val nonce = random.bytes(32)
            if (nonce.size != 32) throw malformed("session nonce is malformed")
            val unsigned = SessionHello(
                sessionId, groupId, identity.deviceId, identity.signingPublicKey, identity.exchangePublicKey,
                nonce, counter, ByteArray(0),
            )
            return SessionHello(
                sessionId, groupId, identity.deviceId, identity.signingPublicKey, identity.exchangePublicKey,
                nonce, counter, identity.sign(unsigned.signingBytes()),
            )
        }

        /**
         * Strict parse (`SessionHello.from_bytes`): exact field set, duplicate keys refused, `version`
         * the JSON integer 1, canonical base64 with exact lengths, `counter` an integer 0 ... 2^63-1.
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
                LanTransport.b64(o["nonce"], 32, "session nonce"),
                counter,
                LanTransport.b64(o["signature"], 64, "session signature"),
            )
        }

        /**
         * `verify_session_hello`: group, device id, signing key, fingerprint and exchange key must be
         * exactly the pinned ones, then the Ed25519 signature.
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
            if (!DeviceIdentity.verify(hello.signature, hello.signingBytes(), hello.signingPublic)) {
                throw authentication("Session hello signature is invalid")
            }
        }
    }
}
