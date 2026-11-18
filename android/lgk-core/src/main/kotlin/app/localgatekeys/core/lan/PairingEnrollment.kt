package app.localgatekeys.core.lan

import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange

/** The user side of one armed offer (the app's pairing model): the Accept prompt and its results. */
interface PairingDecider {
    /** A request verified: show it and block until Accept (true) or Decline / timeout / close (false). */
    fun ask(request: Enrollment.Request, session: OfferSession): Boolean

    /** The device was pinned and its reply is about to be sent. */
    fun didPair(request: Enrollment.Request, session: OfferSession)

    /** Pairing failed after the request verified ([reason]: `refused` or `full`). */
    fun failed(reason: String, session: OfferSession)
}

/**
 * The listener's enrollment handler for one offer (desktop `enroll_verify` -> `await_decision` -> `enroll_finish`, Swift
 * `PairingEnrollment`): verify (nothing pinned), send the reveal of a version-2 offer, ask the user, then re-check
 * against the current state, pin the device and seal the group key to it. Pins nothing unless the user chose Accept.
 * A phone host stores its peers without an endpoint ([keepEndpoint] false): they always dial it.
 */
class PairingEnrollment(
    val session: OfferSession,
    private val store: ItemStore,
    private val random: RandomSource,
    private val clock: UnixClock,
    private val decider: PairingDecider,
    private val keepEndpoint: Boolean = false,
) : EnrollmentHandling {
    override fun enroll(raw: ByteArray, sendInterim: (ByteArray) -> Unit): ByteArray? {
        val state = try {
            store.load().sync
        } catch (e: Exception) {
            null
        }
        val request = when (val outcome = LanPeers.verifyEnrollment(raw, session, state)) {
            is OfferSession.Outcome.Refuse -> return outcome.frame
            OfferSession.Outcome.Close -> return null
            is OfferSession.Outcome.Verified -> outcome.request
        }
        // A version-2 offer: the reveal goes to this one verified request (it consumed the offer), before the prompt,
        // so both codes cover it (desktop `enroll_reveal`). The device is gone when it cannot be sent: no prompt, no answer.
        try {
            Enrollment.revealFrame(session.offer)?.let(sendInterim)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            decider.failed("refused", session)
            return null
        } catch (e: Exception) {
            decider.failed("refused", session)
            return null
        }
        if (!decider.ask(request, session)) return refusal("declined")
        return try {
            val snap = store.load()
            val current = snap.sync ?: throw PairingException(PairingException.Kind.REFUSED, "refused")
            val (reply, pinned) = LanPeers.acceptEnrollment(request, session.offer, current, clock.now, random, keepEndpoint)
            store.commit(StoreChange(snap.revision, snap.records, snap.meta, pinned))
            decider.didPair(request, session)
            reply
        } catch (e: PairingException) {
            val reason = if (e.kind == PairingException.Kind.REFUSED && e.detail == "full") "full" else "refused"
            decider.failed(reason, session)
            refusal(reason)
        } catch (e: Exception) {
            decider.failed("refused", session)
            refusal("refused")
        }
    }

    override fun toString(): String = "PairingEnrollment(${session.offer.offerId})"

    companion object {
        fun refusal(reason: String): ByteArray = try {
            Enrollment.refusal(reason)
        } catch (e: Exception) {
            Enrollment.REFUSED_MAGIC + "{\"reason\":\"refused\"}".toByteArray(Charsets.US_ASCII)
        }
    }
}
