package app.localgatekeys.android.sync

import app.localgatekeys.core.lan.Enrollment
import app.localgatekeys.core.lan.EnrollmentHandling
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.LanPeer
import app.localgatekeys.core.lan.LanPeers
import app.localgatekeys.core.lan.MonotonicClock
import app.localgatekeys.core.lan.OfferSession
import app.localgatekeys.core.lan.PairingDecider
import app.localgatekeys.core.lan.PairingEnrollment
import app.localgatekeys.core.lan.PairingOffer
import app.localgatekeys.core.lan.SystemMonotonicClock
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The phone host's side of Wi-Fi pairing (the Mac's `HostPairingModel`, desktop `qr_show` / `qr_poll` / `qr_decide` /
 * `qr_copy` / `qr_close`): one offer shown as a QR code and as code text; a device that proves it scanned it is shown
 * with its name, 6-digit code and key fingerprint for Accept or Decline (Decline by itself after 60 s); after Accept the
 * device is pinned and can be removed again with Undo.
 *
 * Thread-safe: the listener's connection thread calls the [PairingDecider] side ([ask] blocks it until the user
 * decides); the screen calls the rest. What the screen shows is [state]; its words come from the UI (names are raw
 * here: sanitize before showing).
 */
class HostPairing(
    private val store: ItemStore,
    private val random: RandomSource,
    private val clock: UnixClock,
    private val monotonic: MonotonicClock = SystemMonotonicClock,
) : PairingDecider {
    enum class Stage { IDLE, SHOWING, CONFIRM, ADDING, PAIRED, DECLINED, EXPIRED }

    /** What the pairing sheet says below its buttons (the Mac's `message`). */
    enum class Note { COPIED, CLOSED, NOT_WAITING, DECLINED, ADDING, STEP_FAILED, TOO_MANY_PEERS }

    /** A verified request waiting for Accept or Decline. [name] is the device's own (unsanitized). */
    data class Request(val deviceId: String, val name: String, val code: String, val fingerprint: String) {
        override fun toString(): String = "Request(deviceId=$deviceId)"
    }

    data class Paired(val deviceId: String, val name: String, val fingerprint: String) {
        override fun toString(): String = "Paired(deviceId=$deviceId)"
    }

    data class State(
        val stage: Stage = Stage.IDLE,
        /** The `lgk-pair:` text of the shown offer (the QR code's content, "Copy code text"). */
        val qrText: String? = null,
        /** The offer's 8-digit code ("Code: …"). */
        val offerCode: String? = null,
        val endpoint: LanEndpoint? = null,
        /** Seconds until the offer expires (0: expired); null while no offer is shown. */
        val expiresIn: Long? = null,
        val request: Request? = null,
        /** Seconds until a waiting request is declined by itself. */
        val secondsLeft: Int? = null,
        val paired: Paired? = null,
        val note: Note? = null,
    ) {
        /** Never shows the offer text. */
        override fun toString(): String = "State(stage=$stage, request=$request, paired=$paired, note=$note)"
    }

    private val lock = Any()
    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()

    /** Desktop `ACCEPT_TIMEOUT_SECONDS`. */
    @Volatile
    var acceptSeconds: Double = Enrollment.ACCEPT_TIMEOUT_SECONDS.toDouble()

    /** Called (on the connection thread) after a device was added: the host then syncs. */
    @Volatile
    var onPaired: (() -> Unit)? = null

    private var session: OfferSession? = null
    private var decision: DecisionBox? = null
    private var decisionDeadline = 0.0

    val currentSession: OfferSession? get() = synchronized(lock) { session }

    /** An offer is shown, or a device that scanned it is being confirmed or added (a free host keeps listening). */
    val isShown: Boolean
        get() = synchronized(lock) { session != null && _state.value.stage in setOf(Stage.SHOWING, Stage.CONFIRM, Stage.ADDING) }

    /**
     * `begin_pairing_job`: a Wi-Fi group when the vault has none yet, then a new offer reachable at [endpoint]. Returns
     * the enrollment handler to install on the listener. Any earlier offer is closed first. Blocking (store); throws
     * [SyncActionException] with `rejoin-required` when the group belongs to another install.
     */
    fun begin(endpoint: LanEndpoint, installId: String): EnrollmentHandling {
        close()
        var snapshot = store.load()
        if (snapshot.sync == null) {
            val state = LanPeers.createWifiGroup(installId, random)
            store.commit(StoreChange(snapshot.revision, snapshot.records, snapshot.meta, state))
            snapshot = store.load()
        }
        val state = snapshot.sync ?: throw SyncActionException("not-joined")
        if (state.installId != installId) throw SyncActionException("rejoin-required")
        val (offer, _) = PairingOffer.create(state.groupId, state.identity, endpoint, clock, random)
        return arm(OfferSession(offer, state.identity, clock, monotonic))
    }

    /** Shows [session]'s offer and returns its enrollment handler ([begin]; tests arm a recorded offer). */
    fun arm(session: OfferSession): EnrollmentHandling {
        val offer = session.offer
        val text = offer.qrPayload()
        synchronized(lock) {
            this.session = session
            _state.value = State(
                stage = Stage.SHOWING, qrText = text, offerCode = offer.code, endpoint = offer.endpoint,
                expiresIn = maxOf(0L, offer.expiresAt - clock.now),
            )
        }
        return PairingEnrollment(session, store, random, clock, this, keepEndpoint = false)
    }

    /** The timer tick (every second while the sheet is open): expire the offer, update the countdowns. */
    fun tick() {
        val s = synchronized(lock) { session } ?: return
        s.expire()
        synchronized(lock) {
            if (session !== s) return
            val left = maxOf(0L, s.offer.expiresAt - clock.now)
            var next = _state.value.copy(expiresIn = left)
            if (next.stage == Stage.CONFIRM) {
                next = next.copy(secondsLeft = maxOf(0, Math.ceil(decisionDeadline - monotonic.seconds()).toInt()))
            }
            if (next.stage == Stage.SHOWING && (left <= 0 || s.isExhausted)) next = next.copy(stage = Stage.EXPIRED, expiresIn = 0)
            _state.value = next
        }
    }

    /** "Copy code text": the offer text while it is still open, else null (and [Note.CLOSED]). */
    fun copyCodeText(): String? = synchronized(lock) {
        val s = session
        val st = _state.value
        if (s == null || st.qrText == null || st.stage !in setOf(Stage.SHOWING, Stage.CONFIRM) || s.offer.expiresAt <= clock.now) {
            _state.value = st.copy(note = Note.CLOSED)
            return null
        }
        _state.value = st.copy(note = Note.COPIED)
        st.qrText
    }

    /** Accept or Decline the waiting request; false (and [Note.NOT_WAITING]) when none waits. */
    fun decide(accept: Boolean, deviceId: String): Boolean = synchronized(lock) {
        val st = _state.value
        val box = decision
        if (st.stage != Stage.CONFIRM || box == null || deviceId != st.request?.deviceId || !box.resolve(accept)) {
            _state.value = st.copy(note = Note.NOT_WAITING)
            return false
        }
        true
    }

    /** Close: disarm the offer (later requests get no answer); a request waiting for Accept is declined. */
    fun close() {
        val (s, d) = synchronized(lock) {
            val r = session to decision
            session = null
            decision = null
            val paired = _state.value.paired
            // A device just added stays offered for Undo / Keep after the sheet closed.
            _state.value = if (paired != null && _state.value.stage == Stage.PAIRED) State(stage = Stage.PAIRED, paired = paired) else State()
            r
        }
        s?.stop()
        d?.resolve(false)
    }

    /** Keep the device just added. */
    fun keep() = synchronized(lock) {
        val st = _state.value
        _state.value = if (st.stage == Stage.PAIRED) State() else st.copy(paired = null)
    }

    /** Undo = Remove a device: the device just added is revoked (stays listed so its id cannot come back). Blocking. */
    fun undo(): Boolean {
        val p = synchronized(lock) { _state.value.paired } ?: return false
        try {
            val snap = store.load()
            val state = snap.sync ?: return false
            val (revoked, found) = LanPeers.revoking(p.deviceId, state)
            if (!found) return false
            store.commit(StoreChange(snap.revision, snap.records, snap.meta, revoked))
        } catch (e: Exception) {
            synchronized(lock) { _state.value = _state.value.copy(note = Note.STEP_FAILED) }
            return false
        }
        synchronized(lock) {
            session?.stop()
            session = null
            _state.value = State()
        }
        return true
    }

    // MARK: PairingDecider (the listener's connection thread)

    /** A request verified: show it and wait for Accept or Decline (Decline after [acceptSeconds]). */
    override fun ask(request: Enrollment.Request, session: OfferSession): Boolean {
        val box = DecisionBox()
        val seconds = acceptSeconds
        synchronized(lock) {
            if (this.session !== session) return false
            // One request at a time: a second one while the first waits for Accept is declined.
            if (decision != null) return false
            decision = box
            decisionDeadline = monotonic.seconds() + seconds
            val fingerprint = fingerprintText(
                LanPeer(request.deviceId, session.offer.groupId, signingPublic = request.signingPublic, exchangePublic = request.exchangePublic).fingerprint,
            )
            _state.value = _state.value.copy(
                stage = Stage.CONFIRM, request = Request(request.deviceId, request.name, formatCode(request.code), fingerprint),
                secondsLeft = seconds.toInt(), note = null, paired = null,
            )
        }
        val accepted = box.await((maxOf(0.0, seconds) * 1000).toLong())
        synchronized(lock) {
            if (decision === box) decision = null
            if (this.session !== session) return false
            _state.value = if (accepted) {
                _state.value.copy(stage = Stage.ADDING, secondsLeft = null, note = Note.ADDING)
            } else {
                _state.value.copy(stage = Stage.DECLINED, secondsLeft = null, request = null, note = Note.DECLINED)
            }
        }
        return accepted
    }

    override fun didPair(request: Enrollment.Request, session: OfferSession) {
        synchronized(lock) {
            if (this.session !== session) return
            val fingerprint = _state.value.request?.fingerprint ?: ""
            _state.value = _state.value.copy(
                stage = Stage.PAIRED, paired = Paired(request.deviceId, request.name, fingerprint), request = null, qrText = null, note = null,
            )
        }
        onPaired?.invoke()
    }

    override fun failed(reason: String, session: OfferSession) {
        synchronized(lock) {
            if (this.session !== session) return
            _state.value = _state.value.copy(
                stage = Stage.DECLINED, request = null, secondsLeft = null,
                note = if (reason == "full") Note.TOO_MANY_PEERS else Note.STEP_FAILED,
            )
        }
    }

    override fun toString(): String = "HostPairing(stage=${_state.value.stage})"

    /** Resolves once (Accept, Decline, timeout or close); [await] returns the first answer. */
    class DecisionBox {
        private val latch = CountDownLatch(1)
        private val lock = Any()
        private var value: Boolean? = null

        fun resolve(accept: Boolean): Boolean {
            synchronized(lock) {
                if (value != null) return false
                value = accept
            }
            latch.countDown()
            return true
        }

        /** Waits up to [millis] (then declines); an interrupt declines too. */
        fun await(millis: Long): Boolean {
            try {
                latch.await(millis, TimeUnit.MILLISECONDS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            }
            resolve(false)
            return synchronized(lock) { value ?: false }
        }
    }

    companion object {
        /** `format_verification_code`: "123456" -> "123 456"; empty when malformed. */
        fun formatCode(code: String): String {
            if (code.length != 6 || !code.all { it in '0'..'9' }) return ""
            return code.substring(0, 3) + " " + code.substring(3)
        }

        /** `paired_fingerprint`: the first 16 hex digits in groups of four; empty when malformed. */
        fun fingerprintText(hex: String): String {
            if (hex.isEmpty() || !hex.all { it in "0123456789abcdef" }) return ""
            return hex.take(16).chunked(4).joinToString(" ")
        }

        /** `countdown_text`'s clock: "m:ss". */
        fun clock(secondsLeft: Long): String = "${secondsLeft / 60}:" + (secondsLeft % 60).toString().padStart(2, '0')
    }
}
