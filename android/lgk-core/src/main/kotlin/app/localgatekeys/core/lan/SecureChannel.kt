package app.localgatekeys.core.lan

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.CryptoBoxException
import app.localgatekeys.core.primitives.X25519
import java.security.MessageDigest

private fun authentication(detail: String) = LanTransportException(LanTransportException.Kind.AUTHENTICATION, detail)

private fun malformed(detail: String) = LanTransportException(LanTransportException.Kind.MALFORMED, detail)

private fun tooLarge(detail: String) = LanTransportException(LanTransportException.Kind.TOO_LARGE, detail)

private fun replay(detail: String) = LanTransportException(LanTransportException.Kind.REPLAY, detail)

/**
 * The AES-GCM channel of one LAN connection (desktop `transport.SecureChannel`).
 *
 * Key (protocol version 2) = HKDF-SHA256(ikm = X25519(own ephemeral, peer ephemeral) ||
 * X25519(own static, peer static), salt = SHA-256(`session-salt|v2|` + sorted hellos),
 * info = `session-key|v2|` + session id). The local hello's ephemeral private key is consumed
 * (zeroed) by the one derivation, so recorded traffic stays sealed after a static key leaks. Nonce = 4-byte direction prefix + 8-byte big-endian
 * counter; each direction starts at counter 1 and a receiver refuses a counter that does not
 * increase. The desktop sends one request and one response per connection.
 *
 * Not thread-safe: one connection, one thread.
 */
class SecureChannel(key: ByteArray, sessionId: ByteArray, val role: Role) {
    enum class Role(val wire: String) { INITIATOR("initiator"), RESPONDER("responder") }

    private val keyBytes: ByteArray
    private val sid: ByteArray
    private val sendPrefixBytes: ByteArray
    private val receivePrefixBytes: ByteArray
    private var sendCounter: Long = 0
    private var lastReceived: Long = 0

    init {
        if (key.size != 32) throw authentication("Session key must be 32 bytes")
        if (sessionId.size != LanTransport.SESSION_ID_BYTES) throw authentication("Session ID is malformed")
        keyBytes = key.copyOf()
        sid = sessionId.copyOf()
        sendPrefixBytes = prefix(key, role)
        receivePrefixBytes = prefix(key, if (role == Role.INITIATOR) Role.RESPONDER else Role.INITIATOR)
    }

    /**
     * `SecureChannel.from_paired_identities`: verifies the remote hello against [remote], both
     * session-id bindings and the local hello's signature, then derives the key. Consumes the
     * ephemeral private key of [localHello]: a second channel from the same hello throws.
     */
    constructor(
        local: DeviceIdentity,
        remote: PinnedPeer,
        groupId: String,
        sessionId: ByteArray,
        role: Role,
        localHello: SessionHello,
        remoteHello: SessionHello,
    ) : this(derive(local, remote, groupId, sessionId, localHello, remoteHello), sessionId, role)

    val sendPrefix: ByteArray get() = sendPrefixBytes.copyOf()
    val receivePrefix: ByteArray get() = receivePrefixBytes.copyOf()
    val key: ByteArray get() = keyBytes.copyOf()
    val sessionId: ByteArray get() = sid.copyOf()

    private fun metadata(counter: Long, nonce: ByteArray): MutableMap<String, JsonValue> = mutableMapOf(
        "version" to JsonValue.Int(LanTransport.VERSION),
        "session_id" to JsonValue.Str(Base64Std.encode(sid)),
        "counter" to JsonValue.Int(counter),
        "nonce" to JsonValue.Str(Base64Std.encode(nonce)),
    )

    /** Seals one message; returns the frame WITH its 4-byte length prefix. */
    fun seal(payload: ByteArray): ByteArray {
        if (payload.size !in 1..LanTransport.MAX_MESSAGE_BYTES) throw tooLarge("Encrypted message exceeds the bound")
        if (sendCounter >= Long.MAX_VALUE) throw replay("Session counter exhausted")
        sendCounter += 1
        val nonce = nonce(sendPrefixBytes, sendCounter)
        val meta = metadata(sendCounter, nonce)
        val ct = CryptoBox.sealGcm(keyBytes, nonce, payload, LanTransport.canonical(JsonValue.Obj(meta)))
        meta["ciphertext"] = JsonValue.Str(Base64Std.encode(ct))
        return LanTransport.encodeFrame(LanTransport.canonical(JsonValue.Obj(meta)))
    }

    /**
     * Opens one frame (with its length prefix). Strict: exact field set, `version` the JSON
     * integer 2, this session, an increasing counter bound to the peer's direction prefix.
     */
    fun open(frame: ByteArray): ByteArray {
        val payload = LanTransport.decodeFrame(frame)
        if (payload.size > LanTransport.MAX_MESSAGE_BYTES + 4096) throw tooLarge("Encrypted frame exceeds the bound")
        val raw = parseFrame(payload)
        if (raw["session_id"] != JsonValue.Str(Base64Std.encode(sid))) {
            throw authentication("Encrypted frame belongs to another session")
        }
        val counter = (raw["counter"] as? JsonValue.Int)?.v
        if (counter == null || counter < 1) throw malformed("Encrypted frame counter is malformed")
        if (counter <= lastReceived) throw replay("Duplicate or out-of-order encrypted frame")
        val nonce = LanTransport.b64(raw["nonce"], 12, "encrypted nonce")
        if (!nonce.contentEquals(nonce(receivePrefixBytes, counter))) {
            throw authentication("Encrypted nonce is not bound to the session direction")
        }
        val ct = LanTransport.b64(raw["ciphertext"], null, "encrypted payload")
        if (ct.size > LanTransport.MAX_MESSAGE_BYTES + 16) throw tooLarge("encrypted payload exceeds the size bound")
        val plain = try {
            CryptoBox.openGcm(keyBytes, nonce, ct, LanTransport.canonical(JsonValue.Obj(metadata(counter, nonce))))
        } catch (e: CryptoBoxException) {
            throw authentication("Encrypted frame authentication failed")
        }
        if (plain.size > LanTransport.MAX_MESSAGE_BYTES) throw tooLarge("Decrypted message exceeds the bound")
        lastReceived = counter
        return plain
    }

    companion object {
        internal val FRAME_FIELDS = setOf("ciphertext", "counter", "nonce", "session_id", "version")

        private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

        private fun derive(
            local: DeviceIdentity,
            remote: PinnedPeer,
            groupId: String,
            sessionId: ByteArray,
            localHello: SessionHello,
            remoteHello: SessionHello,
        ): ByteArray {
            SessionHello.verify(remoteHello, remote, groupId)
            if (localHello.groupId != groupId || localHello.deviceId != local.deviceId ||
                !localHello.sessionId.contentEquals(sessionId) || !remoteHello.sessionId.contentEquals(sessionId)
            ) {
                throw authentication("Session hello binding is invalid")
            }
            if (!DeviceIdentity.verify(localHello.signature, localHello.signingBytes(), local.signingPublicKey)) {
                throw authentication("Local session hello signature is invalid")
            }
            val transcript = transcript(localHello.toBytes(), remoteHello.toBytes())
            val secret = localHello.ephemeralSecret ?: throw authentication("Local session hello has no ephemeral key")
            val ephemeral = secret.take { eph ->
                val ownPublic = try {
                    X25519.publicKey(eph)
                } catch (e: RuntimeException) {
                    throw authentication("Local session hello does not carry its ephemeral key")
                }
                if (!ownPublic.contentEquals(localHello.ephemeralPublic)) {
                    throw authentication("Local session hello does not carry its ephemeral key")
                }
                agree(eph, remoteHello.ephemeralPublic, "ephemeral")
            }
            val static = try {
                local.exchange(remote.exchangePublic)
            } catch (e: DeviceIdentityException) {
                throw authentication("Peer exchange key is malformed")
            }
            val ikm = ephemeral + static
            try {
                return deriveKey(ikm, sessionId, transcript)
            } finally {
                ikm.fill(0)
                ephemeral.fill(0)
                static.fill(0)
            }
        }

        /** X25519; an all-zero result (a low-order peer key) is refused like a malformed key. */
        private fun agree(priv: ByteArray, pub: ByteArray, what: String): ByteArray {
            val raw = try {
                X25519.agree(priv, pub)
            } catch (e: RuntimeException) {
                throw authentication("Peer $what key is malformed")
            }
            if (raw.all { it.toInt() == 0 }) throw authentication("Peer $what key is malformed")
            return raw
        }

        private fun lexLess(a: ByteArray, b: ByteArray): Boolean {
            val n = minOf(a.size, b.size)
            for (i in 0 until n) {
                val x = a[i].toInt() and 0xFF
                val y = b[i].toInt() and 0xFF
                if (x != y) return x < y
            }
            return a.size < b.size
        }

        /** Both hello texts sorted bytewise and concatenated (never by role or counter). */
        fun transcript(a: ByteArray, b: ByteArray): ByteArray {
            val t = if (lexLess(a, b)) a + b else b + a
            if (t.size > LanTransport.MAX_MESSAGE_BYTES) throw authentication("Session transcript is malformed")
            return t
        }

        fun salt(transcript: ByteArray): ByteArray =
            sha256("localgatekeys|sync|session-salt|v2|".toByteArray(Charsets.UTF_8) + transcript)

        fun info(sessionId: ByteArray): ByteArray = "localgatekeys|sync|session-key|v2|".toByteArray(Charsets.UTF_8) + sessionId

        /** HKDF over [ikm] = ephemeral shared secret || static shared secret (64 bytes). */
        fun deriveKey(ikm: ByteArray, sessionId: ByteArray, transcript: ByteArray): ByteArray {
            if (sessionId.size != LanTransport.SESSION_ID_BYTES || ikm.size != 64) {
                throw authentication("Session transcript is malformed")
            }
            return CryptoBox.hkdf(ikm, salt(transcript), info(sessionId), 32)
        }

        /** First 4 bytes of SHA-256(key + `send|` + sender role). */
        fun prefix(key: ByteArray, role: Role): ByteArray =
            sha256(key + "send|".toByteArray(Charsets.UTF_8) + role.wire.toByteArray(Charsets.UTF_8)).copyOf(4)

        private fun nonce(prefix: ByteArray, counter: Long): ByteArray =
            prefix + ByteArray(8) { (counter ushr (56 - 8 * it)).toByte() }

        /** Strict frame payload shape check (without the length prefix). */
        fun parseFrame(payload: ByteArray): Map<String, JsonValue> {
            val o = try {
                (CanonicalJson.parse(payload) as? JsonValue.Obj)?.fields
            } catch (e: JsonException) {
                null
            }
            if (o == null || o.keys != FRAME_FIELDS) throw malformed("Encrypted frame is malformed")
            if (o["version"] != JsonValue.Int(LanTransport.VERSION)) throw malformed("Unsupported encrypted frame")
            return o
        }
    }
}
