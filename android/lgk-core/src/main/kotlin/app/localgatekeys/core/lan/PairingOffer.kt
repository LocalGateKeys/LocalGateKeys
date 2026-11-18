package app.localgatekeys.core.lan

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Base64Url
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.Scalars
import java.security.MessageDigest

private fun malformed(detail: String): PairingException = PairingException(PairingException.Kind.MALFORMED, detail)

/**
 * The scanned out-of-band enrollment bundle (desktop `PairingOffer`). Version 2 ([COMMIT_VERSION]) carries
 * [commit] = SHA-256(`enroll-commit|v3|` ‖ reveal) (`docs/formats/LAN_SYNC_V3.md` 3.1); [reveal] is only in
 * the inviter's own offer ([create], a phone host), never in the QR.
 */
class PairingOffer(
    val version: Long,
    val offerId: String,
    val groupId: String,
    val endpoint: LanEndpoint,
    val inviterDeviceId: String,
    inviterSigningPublic: ByteArray,
    inviterExchangePublic: ByteArray,
    val certificateFingerprint: String,
    val expiresAt: Long,
    transcriptNonce: ByteArray,
    pairingSecret: ByteArray,
    val code: String,
    commit: ByteArray? = null,
    reveal: ByteArray? = null,
) {
    private val signingPub = inviterSigningPublic.copyOf()
    private val exchangePub = inviterExchangePublic.copyOf()
    private val nonce = transcriptNonce.copyOf()
    private val secret = pairingSecret.copyOf()
    private val commitBytes = commit?.copyOf()
    private val revealBytes = reveal?.copyOf()

    init {
        // `__post_init__`: a version-2 offer needs a 32-byte commit (and a reveal, if any, that matches it);
        // a version-1 offer has neither.
        if (version >= COMMIT_VERSION) {
            if (commitBytes == null || commitBytes.size != 32) throw malformed("Pairing commitment is malformed")
            if (revealBytes != null &&
                (revealBytes.size != 32 || !MessageDigest.isEqual(Enrollment.commit(revealBytes), commitBytes))
            ) {
                throw malformed("Pairing reveal does not match its commitment")
            }
        } else if (commitBytes != null || revealBytes != null) {
            throw malformed("A version-1 pairing offer has no commitment")
        }
    }

    val inviterSigningPublic: ByteArray get() = signingPub.copyOf()
    val inviterExchangePublic: ByteArray get() = exchangePub.copyOf()
    val transcriptNonce: ByteArray get() = nonce.copyOf()
    val pairingSecret: ByteArray get() = secret.copyOf()

    /** The QR's commitment to the inviter's reveal (version 2), else null. */
    val commit: ByteArray? get() = commitBytes?.copyOf()

    /** The inviter's reveal (only in an inviter's own offer), else null. */
    val reveal: ByteArray? get() = revealBytes?.copyOf()

    /** The reviewable bundle without the two enrollment credentials. */
    val publicJson: JsonValue
        get() = JsonValue.Obj(
            mapOf(
                "version" to JsonValue.Int(version),
                "offer_id" to JsonValue.Str(offerId),
                "group_id" to JsonValue.Str(groupId),
                "endpoint" to endpoint.json,
                "inviter_device_id" to JsonValue.Str(inviterDeviceId),
                "inviter_signing_public" to JsonValue.Str(Base64Std.encode(signingPub)),
                "inviter_exchange_public" to JsonValue.Str(Base64Std.encode(exchangePub)),
                "certificate_fingerprint" to JsonValue.Str(certificateFingerprint),
                "expires_at" to JsonValue.Int(expiresAt),
                "transcript_nonce" to JsonValue.Str(Base64Std.encode(nonce)),
            ) + (commitBytes?.let { mapOf("commit" to JsonValue.Str(Base64Std.encode(it))) } ?: emptyMap()),
        )

    val bundleJson: JsonValue
        get() = JsonValue.Obj(
            (publicJson as JsonValue.Obj).fields +
                mapOf("pairing_secret" to JsonValue.Str(Base64Std.encode(secret)), "code" to JsonValue.Str(code)),
        )

    /** The inviter as the pinned LAN peer the new device stores after a successful enrollment. */
    val inviterPeer: PinnedPeer
        get() = PinnedPeer(inviterDeviceId, groupId, signingPub, exchangePub, endpoint)

    /** `_check_offer`: not expired at [now] and the fingerprint matches the pinned signing key. */
    internal fun check(now: Long) {
        if (now < 0) throw malformed("Pairing clock value is malformed")
        if (now >= expiresAt) throw PairingException(PairingException.Kind.EXPIRED)
        if (Hex.lower(MessageDigest.getInstance("SHA-256").digest(signingPub)) != certificateFingerprint) {
            throw PairingException(PairingException.Kind.AUTHENTICATION, "Pairing certificate fingerprint does not match the pinned key")
        }
    }

    override fun equals(other: Any?): Boolean =
        other is PairingOffer && version == other.version && offerId == other.offerId && groupId == other.groupId &&
            endpoint == other.endpoint && inviterDeviceId == other.inviterDeviceId &&
            signingPub.contentEquals(other.signingPub) && exchangePub.contentEquals(other.exchangePub) &&
            certificateFingerprint == other.certificateFingerprint && expiresAt == other.expiresAt &&
            nonce.contentEquals(other.nonce) && secret.contentEquals(other.secret) && code == other.code &&
            (commitBytes?.contentEquals(other.commitBytes ?: ByteArray(0)) ?: (other.commitBytes == null))

    override fun hashCode(): Int = (offerId.hashCode() * 31 + groupId.hashCode()) * 31 + expiresAt.hashCode()

    /** Never shows the pairing secret or code. */
    override fun toString(): String = "PairingOffer(offerId=$offerId, groupId=$groupId, inviter=$inviterDeviceId)"

    /** `offer_qr_payload`: `lgk-pair:` + unpadded base64url of the ASCII canonical bundle JSON (<= 1200 characters). */
    fun qrPayload(): String {
        val text = QR_PREFIX + Base64Url.encodeNoPad(Pairing.canonical(bundleJson))
        if (text.length > MAX_QR_PAYLOAD) throw malformed("Pairing QR payload is too large")
        return text
    }

    /** The secret part of a new offer the host keeps (the same values are inside the QR bundle). */
    class SecretState(val offerId: String, pairingSecret: ByteArray, val code: String) {
        private val secret = pairingSecret.copyOf()
        val pairingSecret: ByteArray get() = secret.copyOf()

        override fun equals(other: Any?): Boolean =
            other is SecretState && offerId == other.offerId && secret.contentEquals(other.secret) && code == other.code

        override fun hashCode(): Int = offerId.hashCode()

        /** Never shows the secret or the code. */
        override fun toString(): String = "SecretState(offerId=$offerId)"
    }

    companion object {
        /** Desktop `OFFER_COMMIT_VERSION`: the offer version that carries `commit`. */
        const val COMMIT_VERSION: Long = 2
        const val QR_PREFIX = "lgk-pair:"
        const val MAX_QR_PAYLOAD = 1200

        /** Offer lifetime (`PAIRING_TTL_SECONDS`). */
        const val TTL_SECONDS: Long = 120
        const val SECRET_BYTES = 32
        const val CODE_DIGITS = 8

        /** Largest multiple of 10^8 below 2^32: a 4-byte read at or above it is drawn again. */
        internal const val CODE_LIMIT: Long = (1L shl 32) / 100_000_000 * 100_000_000

        /**
         * A new version-2 offer ([COMMIT_VERSION]) for [group] from [identity], reachable at [endpoint], expiring
         * [TTL_SECONDS] after [now] (desktop `create_pairing_offer`). Randomness, in order: 16 bytes (uuid4 offer id),
         * 32 (transcript nonce), 32 (pairing secret), 4 bytes per draw for the code (big-endian, drawn again while
         * >= [CODE_LIMIT], then modulo 10^8), then 32 (the reveal: kept in the returned offer only, its commitment goes
         * in the QR).
         */
        fun create(
            group: String,
            identity: DeviceIdentity,
            endpoint: LanEndpoint,
            now: app.localgatekeys.core.primitives.UnixClock,
            random: app.localgatekeys.core.primitives.RandomSource,
        ): Pair<PairingOffer, SecretState> {
            if (!app.localgatekeys.core.primitives.Identifier.isValid(group)) throw malformed("group id is malformed")
            val ep = LanEndpoint(endpoint.host, endpoint.port)
            val created = now.now
            if (created < 0 || created > Pairing.MAX_INT53 - TTL_SECONDS) throw malformed("Pairing clock value is malformed")
            val u = random.bytes(16)
            if (u.size != 16) throw malformed("Pairing randomness is malformed")
            u[6] = ((u[6].toInt() and 0x0F) or 0x40).toByte()
            u[8] = ((u[8].toInt() and 0x3F) or 0x80).toByte()
            val h = Hex.lower(u)
            val offerId = h.substring(0, 8) + "-" + h.substring(8, 12) + "-" + h.substring(12, 16) + "-" +
                h.substring(16, 20) + "-" + h.substring(20, 32)
            val nonce = random.bytes(32)
            val secret = random.bytes(SECRET_BYTES)
            if (nonce.size != 32 || secret.size != SECRET_BYTES) throw malformed("Pairing randomness is malformed")
            var value: Long
            var draws = 0
            do {
                val b = random.bytes(4)
                if (b.size != 4 || draws >= 64) throw malformed("Pairing randomness is malformed")
                value = ((b[0].toLong() and 0xFF) shl 24) or ((b[1].toLong() and 0xFF) shl 16) or
                    ((b[2].toLong() and 0xFF) shl 8) or (b[3].toLong() and 0xFF)
                draws += 1
            } while (value >= CODE_LIMIT)
            val code = (value % 100_000_000).toString().padStart(CODE_DIGITS, '0')
            val reveal = random.bytes(32)
            if (reveal.size != 32) throw malformed("Pairing randomness is malformed")
            val offer = PairingOffer(
                COMMIT_VERSION, offerId, group, ep, identity.deviceId, identity.signingPublicKey, identity.exchangePublicKey,
                identity.fingerprint, created + TTL_SECONDS, nonce, secret, code, Enrollment.commit(reveal), reveal,
            )
            return offer to SecretState(offerId, secret, code)
        }

        /**
         * Strict QR text parse (desktop `parse_qr_payload` + `from_bundle_dict`): prefix, unpadded
         * canonical base64url, duplicate-free canonical JSON; unknown bundle keys are ignored.
         */
        fun parseQr(text: String): PairingOffer {
            if (Scalars.count(text) > MAX_QR_PAYLOAD || !text.startsWith(QR_PREFIX)) throw malformed("Not a LocalGateKeys pairing code")
            val body = text.substring(QR_PREFIX.length)
            val bodyBytes = body.toByteArray(Charsets.UTF_8).size
            if (body.isEmpty() || bodyBytes % 4 == 1) throw malformed("Pairing QR payload is malformed")
            val raw = try {
                Base64Url.decodeNoPadStrict(body)
            } catch (e: Base64Exception) {
                throw malformed("Pairing QR payload is malformed")
            }
            val value = try {
                CanonicalJson.parse(raw)
            } catch (e: JsonException) {
                throw malformed("Pairing QR payload is malformed")
            }
            if (value !is JsonValue.Obj) throw malformed("Pairing QR payload is malformed")
            if (!Pairing.canonical(value).contentEquals(raw)) throw malformed("Pairing QR payload is not canonical")
            return fromBundle(value)
        }

        /** `PairingOffer.from_bundle_dict` plus `__post_init__`. */
        fun fromBundle(v: JsonValue): PairingOffer {
            val o = (v as? JsonValue.Obj)?.fields ?: throw malformed("Pairing offer is malformed")
            val ep = (o["endpoint"] as? JsonValue.Obj)?.fields ?: throw malformed("Pairing endpoint is malformed")
            val e = Pairing.endpoint(ep["host"], ep["port"])
            val endpoint = LanEndpoint(e.host, e.port)
            val offerId = Pairing.ident(o["offer_id"], "offer id")
            val groupId = Pairing.ident(o["group_id"], "group id")
            val inviter = Pairing.ident(o["inviter_device_id"], "inviter device id")
            val signing = Pairing.b64(o["inviter_signing_public"], 32, "inviter signing key")
            val exchange = Pairing.b64(o["inviter_exchange_public"], 32, "inviter exchange key")
            val fingerprint = Pairing.text(o["certificate_fingerprint"], "certificate fingerprint", 64)
            val nonce = Pairing.b64(o["transcript_nonce"], 32, "transcript nonce")
            val secret = Pairing.b64(o["pairing_secret"], 32, "pairing secret")
            val code = Pairing.text(o["code"], "pairing code", 8)
            val fp = fingerprint.toByteArray(Charsets.UTF_8)
            if (fp.size != 64 || !fp.all { (it in 0x30..0x39) || (it in 0x61..0x66) }) {
                throw malformed("Pairing certificate fingerprint is malformed")
            }
            val expires = (o["expires_at"] as? JsonValue.Int)?.v
            if (expires == null || expires <= 0 || expires > Pairing.MAX_INT53) throw malformed("Pairing expiration is malformed")
            val cb = code.toByteArray(Charsets.UTF_8)
            if (cb.size != 8 || !cb.all { it in 0x30..0x39 }) throw malformed("Pairing code is malformed")
            // The desktop defaults a missing version to 1 and copies any other value into the transcript;
            // here it must be an integer (anything else could not be re-serialised identically).
            val version = when (val ver = o["version"]) {
                null -> 1L
                is JsonValue.Int -> ver.v
                else -> throw malformed("Pairing offer version is malformed")
            }
            // Version 2 reads `commit` (32 bytes); a version-1 bundle's `commit` key is ignored like any unknown key.
            val commit = if (version >= COMMIT_VERSION) Pairing.b64(o["commit"], 32, "pairing commitment") else null
            return PairingOffer(version, offerId, groupId, endpoint, inviter, signing, exchange, fingerprint, expires, nonce, secret, code, commit)
        }
    }
}
