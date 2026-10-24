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

/** The scanned out-of-band enrollment bundle (desktop `PairingOffer`). */
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
) {
    private val signingPub = inviterSigningPublic.copyOf()
    private val exchangePub = inviterExchangePublic.copyOf()
    private val nonce = transcriptNonce.copyOf()
    private val secret = pairingSecret.copyOf()

    val inviterSigningPublic: ByteArray get() = signingPub.copyOf()
    val inviterExchangePublic: ByteArray get() = exchangePub.copyOf()
    val transcriptNonce: ByteArray get() = nonce.copyOf()
    val pairingSecret: ByteArray get() = secret.copyOf()

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
            ),
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
            nonce.contentEquals(other.nonce) && secret.contentEquals(other.secret) && code == other.code

    override fun hashCode(): Int = (offerId.hashCode() * 31 + groupId.hashCode()) * 31 + expiresAt.hashCode()

    /** Never shows the pairing secret or code. */
    override fun toString(): String = "PairingOffer(offerId=$offerId, groupId=$groupId, inviter=$inviterDeviceId)"

    companion object {
        const val QR_PREFIX = "lgk-pair:"
        const val MAX_QR_PAYLOAD = 1200

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
            return PairingOffer(version, offerId, groupId, endpoint, inviter, signing, exchange, fingerprint, expires, nonce, secret, code)
        }
    }
}
