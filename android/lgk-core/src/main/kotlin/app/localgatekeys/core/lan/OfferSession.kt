package app.localgatekeys.core.lan

import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.UnixClock

/** Monotonic seconds (never set back with the wall clock); tests inject fixed values. */
fun interface MonotonicClock {
    fun seconds(): Double
}

/** [System.nanoTime] in seconds. */
object SystemMonotonicClock : MonotonicClock {
    override fun seconds(): Double = System.nanoTime() / 1e9
}

/**
 * One armed pairing offer on the host (Swift `OfferSession`; desktop `PairingSession` plus the offer timing of
 * `lan_sync.LanResponder.start_enrollment` / `enroll_verify` / `expire_enrollment`).
 *
 * One success consumes the offer. A request that does not decrypt (size, magic, JSON shape, another offer id, AES-GCM)
 * is refused without counting, so a sender without the QR code cannot burn the offer; once it decrypts, any failure
 * counts, and after [MAX_ATTEMPTS] the offer is used up. The lifetime runs on both the wall clock and the monotonic
 * clock (setting the wall clock back cannot extend it). For [GRACE_SECONDS] after expiry a late request gets
 * `used-or-expired`; after that the session stops and requests get no answer ([Outcome.Close]). Thread-safe.
 */
class OfferSession(
    val offer: PairingOffer,
    private val inviter: DeviceIdentity,
    private val wall: UnixClock = SystemClock(),
    private val monotonic: MonotonicClock = SystemMonotonicClock,
) {
    sealed interface Outcome {
        /** Send this refusal frame (`LGKENROLLNO1\n...`). */
        class Refuse(frame: ByteArray) : Outcome {
            private val bytes = frame.copyOf()
            val frame: ByteArray get() = bytes.copyOf()

            override fun equals(other: Any?): Boolean = other is Refuse && bytes.contentEquals(other.bytes)

            override fun hashCode(): Int = bytes.contentHashCode()

            override fun toString(): String = "Refuse(${String(bytes, Charsets.US_ASCII).trim()})"
        }

        /** Close without an answer (no offer armed and the grace period is over). */
        object Close : Outcome {
            override fun toString(): String = "Close"
        }

        /** A verified request: show its name and code for Accept / Decline; nothing is pinned yet. */
        class Verified(val request: Enrollment.Request) : Outcome {
            override fun toString(): String = "Verified(${request.deviceId})"
        }
    }

    private val lock = Any()
    private var armed = true
    private var stopped = false
    private var consumed = false
    private var attemptCount = 0
    private val deadline: Double
    private val refuseUntil: Double

    init {
        if (inviter.deviceId != offer.inviterDeviceId || inviter.fingerprint != offer.certificateFingerprint ||
            !inviter.exchangePublicKey.contentEquals(offer.inviterExchangePublic)
        ) {
            throw PairingException(PairingException.Kind.AUTHENTICATION, "Inviter identity does not match the offer")
        }
        // A version-2 offer is armed only with its reveal (`PairingOffer.create` on this device).
        if (offer.commit != null && offer.reveal == null) {
            throw PairingException(PairingException.Kind.MALFORMED, "This offer was not created on this device")
        }
        deadline = monotonic.seconds() + maxOf(0.0, (offer.expiresAt - wall.now).toDouble())
        refuseUntil = deadline + GRACE_SECONDS
    }

    val attempts: Int get() = synchronized(lock) { attemptCount }

    /** Used once, or [MAX_ATTEMPTS] failures. */
    val isExhausted: Boolean get() = synchronized(lock) { consumed || attemptCount >= MAX_ATTEMPTS }

    /** True while requests still get an answer (armed, or within the grace period). */
    val isListening: Boolean get() = synchronized(lock) { !stopped && monotonic.seconds() < refuseUntil }

    /** Disarm (Cancel, or a lock): later requests get no answer. */
    fun stop(): Unit = synchronized(lock) {
        armed = false
        stopped = true
    }

    /** The timer tick: disarm an expired or used-up offer; stop after the grace period. */
    fun expire(): Unit = synchronized(lock) {
        if (monotonic.seconds() >= refuseUntil) {
            armed = false
            stopped = true
        } else if (consumed || attemptCount >= MAX_ATTEMPTS || expiredLocked()) {
            armed = false
        }
    }

    private fun expiredLocked(): Boolean = wall.now >= offer.expiresAt || monotonic.seconds() >= deadline

    /**
     * One enrollment request. [reservedIds] are device ids already in the group (they count as a failed attempt),
     * except a request [rejoin] accepts: a paired device asking again with the same keys (design 2026-11-17, rule 4).
     * [peerCount] >= [maxPeers] answers `full` before anything is consumed or counted, unless the request is such a
     * rejoin, which takes no new place.
     */
    fun handle(
        raw: ByteArray,
        reservedIds: Set<String> = emptySet(),
        peerCount: Int = 0,
        maxPeers: Int = 16,
        rejoin: (Enrollment.Request) -> Boolean = { false },
    ): Outcome {
        synchronized(lock) {
            if (stopped) return Outcome.Close
            val now = wall.now
            if (now >= offer.expiresAt + GRACE_SECONDS.toLong() || monotonic.seconds() >= refuseUntil) {
                armed = false
                stopped = true
                return Outcome.Close
            }
            if (!armed || consumed || attemptCount >= MAX_ATTEMPTS || expiredLocked()) return refusal("used-or-expired")
            if (peerCount >= maxPeers) {
                // Full: only a rejoin goes on; anything else gets `full` as before, nothing counted or consumed.
                val again = try {
                    Enrollment.verifyRequestBody(offer, Enrollment.decryptRequest(offer, inviter, raw)).takeIf(rejoin)
                } catch (e: Exception) {
                    null
                } ?: return refusal("full")
                consumed = true
                return Outcome.Verified(again)
            }
            val plain = try {
                Enrollment.decryptRequest(offer, inviter, raw)
            } catch (e: Exception) {
                return refusal("refused") // not counted
            }
            try {
                val request = Enrollment.verifyRequestBody(offer, plain)
                if (request.deviceId in reservedIds && !rejoin(request)) {
                    throw PairingException(PairingException.Kind.AUTHENTICATION, "This device id is already in use in the group")
                }
                consumed = true
                return Outcome.Verified(request)
            } catch (e: PairingException) {
                attemptCount += 1
                return if (e.kind == PairingException.Kind.REFUSED && e.detail == "update-needed") refusal("update-needed") else refusal("refused")
            } catch (e: Exception) {
                attemptCount += 1
                return refusal("refused")
            }
        }
    }

    override fun toString(): String = "OfferSession(offer=${offer.offerId})"

    companion object {
        const val MAX_ATTEMPTS = 5
        const val GRACE_SECONDS = 600.0

        /** Every reason used here is in [Enrollment.REFUSAL_REASONS]; an unknown one falls back to the generic frame. */
        fun refusal(reason: String): Outcome = try {
            Outcome.Refuse(Enrollment.refusal(reason))
        } catch (e: PairingException) {
            Outcome.Refuse(Enrollment.REFUSED_MAGIC + "{\"reason\":\"refused\"}".toByteArray(Charsets.US_ASCII))
        }
    }
}
