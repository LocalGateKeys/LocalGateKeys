package app.localgatekeys.core.lan

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.SyncFormatException
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.CryptoBoxException
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.primitives.X25519
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private fun malformed(detail: String): PairingException = PairingException(PairingException.Kind.MALFORMED, detail)

private fun authentication(detail: String): PairingException = PairingException(PairingException.Kind.AUTHENTICATION, detail)

private fun ascii(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

private fun ByteArray.startsWithBytes(prefix: ByteArray): Boolean =
    size >= prefix.size && (prefix.indices).all { this[it] == prefix[it] }

private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

/**
 * One-use network enrollment, new-device side (desktop `pairing.build_enrollment_request` /
 * `open_enrollment_reply`), plus the inviter-side request opener used to check the format.
 */
object Enrollment {
    private val REQUEST_MAGIC_BYTES = ascii("LGKENROLL1\n")
    private val REPLY_MAGIC_BYTES = ascii("LGKENROLLOK1\n")
    private val REFUSED_MAGIC_BYTES = ascii("LGKENROLLNO1\n")
    private val REVEAL_MAGIC_BYTES = ascii("LGKENROLLRV1\n")

    /** Copies of the request, reply, refusal and reveal magics. */
    val REQUEST_MAGIC: ByteArray get() = REQUEST_MAGIC_BYTES.copyOf()
    val REPLY_MAGIC: ByteArray get() = REPLY_MAGIC_BYTES.copyOf()
    val REFUSED_MAGIC: ByteArray get() = REFUSED_MAGIC_BYTES.copyOf()

    /** The interim frame of a version-2 offer: the inviter's reveal, before the reply (`LAN_SYNC_V3.md` 3.3). */
    val REVEAL_MAGIC: ByteArray get() = REVEAL_MAGIC_BYTES.copyOf()
    const val MAX_BYTES = 16 * 1024

    /** The largest reveal frame (desktop `open_enrollment_reveal`). */
    const val MAX_REVEAL_BYTES = 256

    /**
     * Enrollment version 3 (desktop `ENROLL_VERSION`), used for and required by a version-2 offer: the code also
     * covers the inviter's reveal. A version-1 offer keeps [LEGACY_VERSION].
     */
    const val VERSION: Long = 3

    /** Enrollment version 2: the request carries the device `name` and both screens show a verification code. */
    const val LEGACY_VERSION: Long = 2

    /** The enrollment version of the transcript and body for [offer] (desktop `enroll_version`). */
    fun version(offer: PairingOffer): Long = if (offer.commit != null) VERSION else LEGACY_VERSION

    /** The longest device name (UTF-8 bytes) a request may carry. */
    const val MAX_NAME_BYTES = 64

    /** How long the inviting device waits for its user to choose Accept (desktop `ACCEPT_TIMEOUT_SECONDS`). */
    const val ACCEPT_TIMEOUT_SECONDS = 60

    /**
     * How long the new device must wait for the reply frame after sending its request (desktop
     * `ENROLL_REPLY_SECONDS`): the Accept timeout plus a margin. The app's enrollment socket read
     * timeout is this, not the short LAN read timeout.
     */
    const val ENROLL_REPLY_SECONDS = ACCEPT_TIMEOUT_SECONDS + 15

    /**
     * Refusal reasons the inviter may state: generic, offer used up or expired, peer list full, declined
     * on the inviting device (or no answer in time), and a request of an older version.
     */
    val REFUSAL_REASONS: Set<String> = setOf("refused", "used-or-expired", "full", "declined", "update-needed")

    /** Desktop `lan_sync.USED_OR_EXPIRED_MESSAGE`. */
    const val USED_OR_EXPIRED_MESSAGE = "This pairing code was used up or expired. Show a new code."

    /** Desktop `lan_sync.DECLINED_MESSAGE`. */
    const val DECLINED_MESSAGE = "The other device declined, or nobody chose Accept there in time. " +
        "Show a new code and choose Accept when the codes match."

    private val REQUEST_INFO = ascii("localgatekeys|sync|enroll-request|v1|")
    private val REPLY_INFO = ascii("localgatekeys|sync|enroll-reply|v1|")
    private val MAC_LABEL = ascii("localgatekeys|sync|enroll-mac|v1|")
    private val SIG_LABEL = ascii("localgatekeys|sync|enroll-sig|v1|")
    private val REPLY_SIG_LABEL = ascii("localgatekeys|sync|enroll-reply-sig|v1|")
    private val VERIFY_LABEL = ascii("localgatekeys|sync|enroll-verify|v2|")
    private val VERIFY_LABEL_V3 = ascii("localgatekeys|sync|enroll-verify|v3|")
    private val COMMIT_LABEL = ascii("localgatekeys|sync|enroll-commit|v3|")
    private val REQUEST_FIELDS = setOf(
        "version", "offer_id", "device_id", "signing_public", "exchange_public", "endpoint", "name", "signature", "mac",
    )
    private val REPLY_FIELDS = setOf("group_id", "epoch", "key", "device_id", "signing_public")

    /**
     * `check_device_name`: the name shown on the inviter's Accept prompt, 1..64 UTF-8 bytes, no
     * character below U+0020 and no U+007F. Returns [name] unchanged.
     */
    fun checkDeviceName(name: String): String {
        if (name.any { it < ' ' || it == '\u007F' }) throw malformed("Device name is malformed")
        // A lone surrogate has no UTF-8 form (Python raises UnicodeEncodeError).
        for ((i, c) in name.withIndex()) {
            if (c.isHighSurrogate() && (i + 1 >= name.length || !name[i + 1].isLowSurrogate())) throw malformed("Device name is malformed")
            if (c.isLowSurrogate() && (i == 0 || !name[i - 1].isHighSurrogate())) throw malformed("Device name is malformed")
        }
        if (name.toByteArray(Charsets.UTF_8).size !in 1..MAX_NAME_BYTES) throw malformed("Device name must be 1..64 UTF-8 bytes")
        return name
    }

    /**
     * `verification_code`: the 6-digit code both screens show for one enrollment, first 4 bytes of
     * SHA-256(`enroll-verify|v2|` + transcript) as a big-endian unsigned integer mod 1 000 000; with
     * [reveal] (a version-2 offer) SHA-256(`enroll-verify|v3|` + transcript + reveal).
     */
    fun verificationCode(transcript: ByteArray, reveal: ByteArray? = null): String {
        val d = if (reveal == null) {
            sha256(VERIFY_LABEL + transcript)
        } else {
            if (reveal.size != 32) throw malformed("Pairing reveal is malformed")
            sha256(VERIFY_LABEL_V3 + transcript + reveal)
        }
        val n = ((d[0].toLong() and 0xFF) shl 24) or ((d[1].toLong() and 0xFF) shl 16) or
            ((d[2].toLong() and 0xFF) shl 8) or (d[3].toLong() and 0xFF)
        return (n % 1_000_000).toString().padStart(6, '0')
    }

    /**
     * The verification code of this device's request for [offer] (the same inputs as [buildRequest]). For a
     * version-1 offer the phone shows it while it waits for the reply; a version-2 offer needs the inviter's
     * [reveal] ([openReveal]), so the code is shown only once the reveal checked out.
     */
    fun verificationCode(
        offer: PairingOffer,
        identity: DeviceIdentity,
        endpoint: LanEndpoint?,
        name: String,
        reveal: ByteArray? = null,
    ): String {
        if (offer.commit != null) checkReveal(offer, reveal)
        val t = transcript(offer, identity.deviceId, identity.signingPublicKey, identity.exchangePublicKey, revalidated(endpoint), name)
        return verificationCode(t, if (offer.commit != null) reveal else null)
    }

    /** `enrollment_commit`: SHA-256(`enroll-commit|v3|` + [reveal]), the commitment a version-2 offer carries. */
    fun commit(reveal: ByteArray): ByteArray {
        if (reveal.size != 32) throw malformed("Pairing reveal is malformed")
        return sha256(COMMIT_LABEL + reveal)
    }

    /** A 32-byte [reveal] that matches [offer]'s commitment, else [PairingException.Kind.AUTHENTICATION]. */
    private fun checkReveal(offer: PairingOffer, reveal: ByteArray?) {
        val expected = offer.commit ?: return
        if (reveal == null || reveal.size != 32 || !MessageDigest.isEqual(commit(reveal), expected)) {
            throw authentication("The inviting device sent no valid reveal before its reply")
        }
    }

    /** Inviter side (`enrollment_reveal`): the interim reveal frame of a verified request; null for a version-1 offer. */
    fun revealFrame(offer: PairingOffer): ByteArray? {
        if (offer.commit == null) return null
        val reveal = offer.reveal ?: throw malformed("This offer has no reveal")
        return REVEAL_MAGIC_BYTES + Pairing.canonical(JsonValue.Obj(mapOf("reveal" to JsonValue.Str(Base64Std.encode(reveal)))))
    }

    /** Whether an enrollment frame from the inviter is a reveal frame (by its magic). */
    fun isReveal(raw: ByteArray): Boolean = raw.startsWithBytes(REVEAL_MAGIC_BYTES)

    /**
     * New-device side (`open_enrollment_reveal`): the reveal from the interim frame [raw] (at most 256 bytes,
     * `LGKENROLLRV1\n` + canonical `{"reveal"}`), checked against [offer]'s commitment. A malformed frame throws
     * [PairingException.Kind.MALFORMED], a mismatch [PairingException.Kind.AUTHENTICATION].
     */
    fun openReveal(offer: PairingOffer, raw: ByteArray): ByteArray {
        val expected = offer.commit ?: throw malformed("This offer has no commitment")
        if (raw.size > MAX_REVEAL_BYTES || !raw.startsWithBytes(REVEAL_MAGIC_BYTES)) throw malformed("Enrollment reveal is malformed")
        val value = (Pairing.strictJson(raw.copyOfRange(REVEAL_MAGIC_BYTES.size, raw.size)) as? JsonValue.Obj)?.fields
        if (value == null || value.keys != setOf("reveal")) throw malformed("Enrollment reveal is malformed")
        val reveal = Pairing.b64(value["reveal"], 32, "pairing reveal")
        if (!MessageDigest.isEqual(commit(reveal), expected)) throw authentication("Enrollment reveal does not match the QR code")
        return reveal
    }

    /** A code shown as "123 456". */
    fun displayCode(code: String): String = if (code.length == 6) code.substring(0, 3) + " " + code.substring(3) else code

    /**
     * Desktop `join_lan_group`'s refusal mapping: a [PairingException.Kind.REFUSED] reply as the
     * [LanSyncException] the app shows (`offer-used-or-expired`, `too-many-peers`, `declined`,
     * `update-needed`, else `refused`).
     */
    fun refusalIssue(e: PairingException): LanSyncException = when (if (e.kind == PairingException.Kind.REFUSED) e.detail else "") {
        "used-or-expired" -> LanSyncException("offer-used-or-expired", USED_OR_EXPIRED_MESSAGE)
        "full" -> LanSyncException("too-many-peers", "The other device already has the most paired devices.")
        "declined" -> LanSyncException("declined", DECLINED_MESSAGE)
        "update-needed" -> LanSyncException("update-needed", "Update LocalGateKeys on this device to pair with the other one.")
        else -> LanSyncException("refused", e.message ?: "")
    }

    /** The verified content of an enrollment request (inviter side). */
    class Request(
        val deviceId: String,
        signingPublic: ByteArray,
        exchangePublic: ByteArray,
        val endpoint: LanEndpoint?,
        val name: String,
        transcript: ByteArray,
        body: ByteArray,
        reveal: ByteArray? = null,
    ) {
        private val signing = signingPublic.copyOf()
        private val exchange = exchangePublic.copyOf()
        private val transcriptBytes = transcript.copyOf()
        private val bodyBytes = body.copyOf()
        private val revealBytes = reveal?.copyOf()

        val signingPublic: ByteArray get() = signing.copyOf()
        val exchangePublic: ByteArray get() = exchange.copyOf()
        val transcript: ByteArray get() = transcriptBytes.copyOf()

        /** The decrypted body as received. */
        val body: ByteArray get() = bodyBytes.copyOf()

        /** The request came for a version-2 offer (commit-then-reveal): the new device is pinned to the sealed hello. */
        val hasReveal: Boolean get() = revealBytes != null

        /** The verification code the new device shows (covering the inviter's reveal for a version-2 offer). */
        val code: String get() = verificationCode(transcriptBytes, revealBytes)

        override fun equals(other: Any?): Boolean =
            other is Request && deviceId == other.deviceId && signing.contentEquals(other.signing) &&
                exchange.contentEquals(other.exchange) && endpoint == other.endpoint && name == other.name &&
                transcriptBytes.contentEquals(other.transcriptBytes) && bodyBytes.contentEquals(other.bodyBytes)

        override fun hashCode(): Int = deviceId.hashCode() * 31 + signing.contentHashCode()
    }

    /** `enrollment_transcript` (with `invitee_name`; version 3 for a version-2 offer, else 2). */
    fun transcript(
        offer: PairingOffer,
        deviceId: String,
        signingPublic: ByteArray,
        exchangePublic: ByteArray,
        endpoint: LanEndpoint?,
        name: String,
    ): ByteArray {
        if (!Identifier.isValid(deviceId)) throw malformed("invitee device id is malformed")
        return Pairing.canonical(
            JsonValue.Obj(
                mapOf(
                    "protocol" to JsonValue.Str("localgatekeys-sync-enrollment"),
                    "version" to JsonValue.Int(version(offer)),
                    "offer" to offer.publicJson,
                    "code" to JsonValue.Str(offer.code),
                    "invitee_device_id" to JsonValue.Str(deviceId),
                    "invitee_signing_public" to JsonValue.Str(Base64Std.encode(signingPublic)),
                    "invitee_exchange_public" to JsonValue.Str(Base64Std.encode(exchangePublic)),
                    "invitee_endpoint" to (endpoint?.json ?: JsonValue.Null),
                    "invitee_name" to JsonValue.Str(checkDeviceName(name)),
                ),
            ),
        )
    }

    private fun mac(offer: PairingOffer, transcript: ByteArray): ByteArray {
        val m = Mac.getInstance("HmacSHA256")
        m.init(SecretKeySpec(offer.pairingSecret, "HmacSHA256"))
        return m.doFinal(MAC_LABEL + transcript)
    }

    private fun revalidated(endpoint: LanEndpoint?): LanEndpoint? = endpoint?.let { LanEndpoint(it.host, it.port) }

    /**
     * The new device's one request for a scanned offer: `LGKENROLL1\n` + canonical JSON.
     * [name] is this device's display name for the inviter's Accept prompt ([checkDeviceName]); show
     * [verificationCode] for the same inputs while waiting up to [ENROLL_REPLY_SECONDS] for the reply.
     * Randomness: the 32-byte ephemeral X25519 private key, then the 12-byte nonce.
     */
    fun buildRequest(
        offer: PairingOffer,
        identity: DeviceIdentity,
        name: String,
        endpoint: LanEndpoint? = null,
        random: RandomSource,
        now: UnixClock,
    ): ByteArray {
        offer.check(now.now)
        if (identity.deviceId == offer.inviterDeviceId) throw authentication("A distinct invitee device identity is required")
        val ep = revalidated(endpoint)
        val transcript = transcript(offer, identity.deviceId, identity.signingPublicKey, identity.exchangePublicKey, ep, name)
        val body = Pairing.canonical(
            JsonValue.Obj(
                mapOf(
                    "version" to JsonValue.Int(version(offer)),
                    "offer_id" to JsonValue.Str(offer.offerId),
                    "device_id" to JsonValue.Str(identity.deviceId),
                    "signing_public" to JsonValue.Str(Base64Std.encode(identity.signingPublicKey)),
                    "exchange_public" to JsonValue.Str(Base64Std.encode(identity.exchangePublicKey)),
                    "endpoint" to (ep?.json ?: JsonValue.Null),
                    "name" to JsonValue.Str(name),
                    "signature" to JsonValue.Str(Base64Std.encode(identity.sign(SIG_LABEL + transcript))),
                    "mac" to JsonValue.Str(Base64Std.encode(mac(offer, transcript))),
                ),
            ),
        )
        val ephPrivate = random.bytes(32)
        val nonce = random.bytes(12)
        if (nonce.size != 12) throw malformed("Enrollment nonce is malformed")
        val shared: ByteArray
        val ephPublic: ByteArray
        try {
            shared = X25519.agree(ephPrivate, offer.inviterExchangePublic)
            ephPublic = X25519.publicKey(ephPrivate)
        } catch (e: RuntimeException) {
            throw authentication("Inviter exchange key is unusable")
        }
        val key = CryptoBox.hkdf(shared, offer.transcriptNonce, REQUEST_INFO + ascii(offer.offerId), 32)
        val header = mapOf("offer_id" to JsonValue.Str(offer.offerId), "eph" to JsonValue.Str(Base64Std.encode(ephPublic)))
        val ct = try {
            CryptoBox.sealGcm(key, nonce, body, Pairing.canonical(JsonValue.Obj(header)))
        } catch (e: CryptoBoxException) {
            throw malformed("Enrollment request cannot be sealed")
        }
        val outer = header + mapOf("nonce" to JsonValue.Str(Base64Std.encode(nonce)), "ct" to JsonValue.Str(Base64Std.encode(ct)))
        val raw = REQUEST_MAGIC_BYTES + Pairing.canonical(JsonValue.Obj(outer))
        if (raw.size > MAX_BYTES) throw malformed("Enrollment request is too large")
        return raw
    }

    /**
     * Inviter side (`_decrypt_enrollment_request` + `_verify_enrollment_body`): decrypt with the
     * inviter's exchange key, then check the body, MAC and signature. A request of an older enrollment version
     * throws [PairingException.Kind.MALFORMED] here ([OfferSession] answers it with `update-needed`).
     */
    fun openRequest(offer: PairingOffer, inviter: DeviceIdentity, raw: ByteArray): Request = try {
        verifyRequestBody(offer, decryptRequest(offer, inviter, raw))
    } catch (e: PairingException) {
        if (e.kind == PairingException.Kind.REFUSED) throw malformed("The new device needs an update (older enrollment version)")
        throw e
    }

    /** `_decrypt_enrollment_request`: size, magic, JSON shape, offer id and AES-GCM (never an attempt). */
    internal fun decryptRequest(offer: PairingOffer, inviter: DeviceIdentity, raw: ByteArray): ByteArray {
        if (raw.size > MAX_BYTES || !raw.startsWithBytes(REQUEST_MAGIC_BYTES)) throw malformed("Enrollment request is malformed")
        val outer = (Pairing.strictJson(raw.copyOfRange(REQUEST_MAGIC_BYTES.size, raw.size)) as? JsonValue.Obj)?.fields
        if (outer == null || outer.keys != setOf("offer_id", "eph", "nonce", "ct")) throw malformed("Enrollment request is malformed")
        if (outer["offer_id"] != JsonValue.Str(offer.offerId)) throw authentication("Enrollment request is for another offer")
        val eph = Pairing.b64(outer["eph"], 32, "enrollment key")
        val nonce = Pairing.b64(outer["nonce"], 12, "enrollment nonce")
        val ct: ByteArray
        val shared: ByteArray
        try {
            ct = Base64Std.decodeStrict((outer["ct"] as? JsonValue.Str)?.v ?: throw authentication("Enrollment request cannot be opened"))
            shared = inviter.exchange(eph)
        } catch (e: Base64Exception) {
            throw authentication("Enrollment request cannot be opened")
        } catch (e: DeviceIdentityException) {
            throw authentication("Enrollment request cannot be opened")
        }
        val key = CryptoBox.hkdf(shared, offer.transcriptNonce, REQUEST_INFO + ascii(offer.offerId), 32)
        val aad = Pairing.canonical(JsonValue.Obj(mapOf("offer_id" to outer.getValue("offer_id"), "eph" to outer.getValue("eph"))))
        val plain = try {
            CryptoBox.openGcm(key, nonce, ct, aad)
        } catch (e: CryptoBoxException) {
            throw authentication("Enrollment request authentication failed")
        }
        return plain
    }

    /**
     * `_verify_enrollment_body`: the checks after a successful decrypt (they count as attempts). A body of an older
     * enrollment version throws [PairingException.Kind.REFUSED] `update-needed`.
     */
    internal fun verifyRequestBody(offer: PairingOffer, plain: ByteArray): Request {
        val body = (Pairing.strictJson(plain) as? JsonValue.Obj)?.fields
        val bodyVersion = (body?.get("version") as? JsonValue.Int)?.v
        val expected = version(offer)
        if (bodyVersion != null && bodyVersion < expected && body?.get("offer_id") == JsonValue.Str(offer.offerId)) {
            // Desktop `EnrollmentOutdated`: the inviter answers `update-needed` (also a version-2 body for a
            // version-2 offer: without the reveal its code could be ground) and sends no reveal.
            throw PairingException(PairingException.Kind.REFUSED, "update-needed")
        }
        if (body == null || body.keys != REQUEST_FIELDS || body["version"] != JsonValue.Int(expected) ||
            body["offer_id"] != JsonValue.Str(offer.offerId)
        ) {
            throw malformed("Enrollment request is malformed")
        }
        val deviceId = Pairing.ident(body["device_id"], "invitee device id")
        if (deviceId == offer.inviterDeviceId) throw authentication("This device id is already in use in the group")
        val signing = Pairing.b64(body["signing_public"], 32, "invitee signing key")
        val exchange = Pairing.b64(body["exchange_public"], 32, "invitee exchange key")
        val ep = body["endpoint"]
        val endpoint: LanEndpoint? = when {
            ep == JsonValue.Null -> null
            ep is JsonValue.Obj && ep.fields.keys == setOf("host", "port") -> {
                val f = Pairing.endpoint(ep.fields["host"], ep.fields["port"])
                LanEndpoint(f.host, f.port)
            }
            else -> throw malformed("Enrollment endpoint is malformed")
        }
        val name = checkDeviceName((body["name"] as? JsonValue.Str)?.v ?: throw malformed("Device name is malformed"))
        val transcript = transcript(offer, deviceId, signing, exchange, endpoint, name)
        val mac = Pairing.b64(body["mac"], 32, "enrollment mac")
        if (!MessageDigest.isEqual(mac, mac(offer, transcript))) throw authentication("Enrollment does not prove the pairing secret")
        val sig = Pairing.b64(body["signature"], 64, "enrollment signature")
        if (!DeviceIdentity.verify(sig, SIG_LABEL + transcript, signing)) throw authentication("Enrollment signature is invalid")
        return Request(deviceId, signing, exchange, endpoint, name, transcript, plain, offer.reveal)
    }

    /** The refusal frame the inviter sends for [reason] (`LGKENROLLNO1\n` + canonical `{"reason"}`). */
    fun refusal(reason: String): ByteArray {
        if (reason !in REFUSAL_REASONS) throw malformed("Unknown refusal reason")
        return REFUSED_MAGIC_BYTES + Pairing.canonical(JsonValue.Obj(mapOf("reason" to JsonValue.Str(reason))))
    }

    /**
     * Host side (`seal_enrollment_reply`): the group key for an accepted [request], sealed to the new device:
     * `LGKENROLLOK1\n` + canonical `{"ct","eph","nonce","sig"}`. Randomness: the 32-byte ephemeral X25519 private key,
     * then the 12-byte nonce.
     */
    fun sealReply(inviter: DeviceIdentity, offer: PairingOffer, request: Request, groupKey: GroupKey, random: RandomSource): ByteArray =
        sealReply(offer, request, groupKey, random) { inviter.sign(it) }

    /** [sign] is the inviter's Ed25519 signer; tests pass the desktop's signature to pin the bytes. */
    internal fun sealReply(
        offer: PairingOffer,
        request: Request,
        groupKey: GroupKey,
        random: RandomSource,
        sign: (ByteArray) -> ByteArray,
    ): ByteArray {
        if (groupKey.epoch < 1 || groupKey.key.size != 32) throw malformed("Group key is malformed")
        if (!Identifier.isValid(groupKey.groupId)) throw malformed("group id is malformed")
        val bound = sha256(request.transcript)
        val ephPrivate = random.bytes(32)
        val nonce = random.bytes(12)
        if (ephPrivate.size != 32 || nonce.size != 12) throw malformed("Enrollment nonce is malformed")
        val shared: ByteArray
        val ephPublic: ByteArray
        try {
            shared = X25519.agree(ephPrivate, request.exchangePublic)
            ephPublic = X25519.publicKey(ephPrivate)
        } catch (e: RuntimeException) {
            throw authentication("Invitee exchange key is unusable")
        }
        if (shared.none { it.toInt() != 0 }) throw authentication("Invitee exchange key is unusable")
        val secret = CryptoBox.hkdf(shared, bound, REPLY_INFO + ascii(offer.offerId), 32)
        val header = mapOf("eph" to JsonValue.Str(Base64Std.encode(ephPublic)), "nonce" to JsonValue.Str(Base64Std.encode(nonce)))
        val headerBytes = Pairing.canonical(JsonValue.Obj(header))
        val body = Pairing.canonical(
            JsonValue.Obj(
                mapOf(
                    "group_id" to JsonValue.Str(groupKey.groupId), "epoch" to JsonValue.Int(groupKey.epoch),
                    "key" to JsonValue.Str(Base64Std.encode(groupKey.key)), "device_id" to JsonValue.Str(request.deviceId),
                    "signing_public" to JsonValue.Str(Base64Std.encode(request.signingPublic)),
                ),
            ),
        )
        val ct = try {
            CryptoBox.sealGcm(secret, nonce, body, headerBytes + bound)
        } catch (e: CryptoBoxException) {
            throw malformed("Enrollment reply cannot be sealed")
        }
        val sig = try {
            sign(REPLY_SIG_LABEL + bound + headerBytes + ct)
        } catch (e: Exception) {
            throw malformed("Signed transcript is malformed")
        }
        val outer = header + mapOf("ct" to JsonValue.Str(Base64Std.encode(ct)), "sig" to JsonValue.Str(Base64Std.encode(sig)))
        return REPLY_MAGIC_BYTES + Pairing.canonical(JsonValue.Obj(outer))
    }

    /**
     * New-device side: verify the inviter's reply against the QR-pinned key and return the group key.
     * [endpoint] and [name] are the ones this device announced in its request. A refusal throws
     * [PairingException.Kind.REFUSED] with its reason ([refusalIssue] maps it for the app). For a version-2
     * offer [reveal] must be the one [openReveal] checked: a key reply without it is refused
     * ([PairingException.Kind.AUTHENTICATION]).
     */
    fun openReply(
        offer: PairingOffer,
        identity: DeviceIdentity,
        raw: ByteArray,
        name: String,
        endpoint: LanEndpoint? = null,
        reveal: ByteArray? = null,
    ): GroupKey {
        if (raw.startsWithBytes(REFUSED_MAGIC_BYTES)) {
            var reason = "refused"
            val parsed = try {
                CanonicalJson.parse(raw.copyOfRange(REFUSED_MAGIC_BYTES.size, raw.size))
            } catch (e: JsonException) {
                null
            }
            val r = ((parsed as? JsonValue.Obj)?.fields?.get("reason") as? JsonValue.Str)?.v
            if (r != null && r in REFUSAL_REASONS) reason = r
            throw PairingException(PairingException.Kind.REFUSED, reason)
        }
        if (raw.size > MAX_BYTES || !raw.startsWithBytes(REPLY_MAGIC_BYTES)) throw malformed("Enrollment reply is malformed")
        checkReveal(offer, reveal)
        val outer = (Pairing.strictJson(raw.copyOfRange(REPLY_MAGIC_BYTES.size, raw.size)) as? JsonValue.Obj)?.fields
        if (outer == null || outer.keys != setOf("eph", "nonce", "ct", "sig")) throw malformed("Enrollment reply is malformed")
        val ep = revalidated(endpoint)
        val transcript = transcript(offer, identity.deviceId, identity.signingPublicKey, identity.exchangePublicKey, ep, name)
        val bound = sha256(transcript)
        val header = Pairing.canonical(JsonValue.Obj(mapOf("eph" to outer.getValue("eph"), "nonce" to outer.getValue("nonce"))))
        val eph = Pairing.b64(outer["eph"], 32, "reply key")
        val nonce = Pairing.b64(outer["nonce"], 12, "reply nonce")
        val ct = try {
            Base64Std.decodeStrict((outer["ct"] as? JsonValue.Str)?.v ?: throw malformed("Enrollment reply is malformed"))
        } catch (e: Base64Exception) {
            throw malformed("Enrollment reply is malformed")
        }
        val sig = Pairing.b64(outer["sig"], 64, "reply signature")
        val notPinned = authentication("Enrollment reply is not from the pinned inviter")
        if (!DeviceIdentity.verify(sig, REPLY_SIG_LABEL + bound + header + ct, offer.inviterSigningPublic)) throw notPinned
        val shared = try {
            identity.exchange(eph)
        } catch (e: DeviceIdentityException) {
            throw notPinned
        }
        val plain = try {
            CryptoBox.openGcm(CryptoBox.hkdf(shared, bound, REPLY_INFO + ascii(offer.offerId), 32), nonce, ct, header + bound)
        } catch (e: CryptoBoxException) {
            throw notPinned
        }
        val body = (Pairing.strictJson(plain) as? JsonValue.Obj)?.fields
        if (body == null || body.keys != REPLY_FIELDS) throw malformed("Enrollment reply is malformed")
        if (body["device_id"] != JsonValue.Str(identity.deviceId) ||
            body["signing_public"] != JsonValue.Str(Base64Std.encode(identity.signingPublicKey))
        ) {
            throw authentication("Inviter pinned another device identity")
        }
        val epoch = (body["epoch"] as? JsonValue.Int)?.v
        if (body["group_id"] != JsonValue.Str(offer.groupId) || epoch == null || epoch < 1) {
            throw malformed("Enrollment reply group is malformed")
        }
        val key = Pairing.b64(body["key"], 32, "group key")
        try {
            return GroupKey(offer.groupId, epoch, key)
        } catch (e: SyncFormatException) {
            throw malformed("Enrollment reply group is malformed")
        }
    }
}
