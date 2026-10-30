package app.localgatekeys.android.pro

import androidx.annotation.StringRes
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.records.License
import app.localgatekeys.core.records.LicenseException
import app.localgatekeys.core.records.LicenseInfo
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.json.JsonValue
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Pro on this phone: the `pro_unlimited` purchase or a valid synced desktop licence. The state is one [StateFlow], so
 * [isPro] can be read from any thread (the editor reads it on IO at save time).
 *
 * [purchased] starts as the last known entitlement (tests pass true for a Pro phone); [refresh] re-reads it.
 */
/** Which message the Pro sheet shows. Held as an id, not text, so it follows the display language. */
enum class ProNote(@StringRes val res: Int) {
    UNAVAILABLE(R.string.pro_unavailable),
    PENDING(R.string.pro_purchase_pending),
    UNVERIFIED(R.string.pro_unverified),
    PURCHASE_FAILED(R.string.pro_purchase_failed),
    NOTHING_TO_RESTORE(R.string.pro_nothing_to_restore),
    RESTORE_FAILED(R.string.pro_restore_failed),
}

class ProModel(
    private val purchases: ProPurchasing,
    private val licenseKeys: Map<String, ByteArray> = LicenseKeys.production,
    purchased: Boolean = false,
    /** Task 9: trades the Play purchase for a desktop licence; null never claims (tests that do not need it). */
    private val claimer: LicenceClaiming? = null,
    private val claimFlags: ClaimFlagStore = MemoryClaimFlags(),
    /** Resolves the messages shown on the Pro sheet and in Settings. */
    private val txt: Txt,
) {
    data class State(
        val purchased: Boolean = false,
        val license: LicenseInfo? = null,
        val price: String? = null,
        val busy: Boolean = false,
        val note: ProNote? = null,
        /** False once Play has said there is no `pro_unlimited` product (or no billing): Buy is disabled. */
        val canBuy: Boolean = true,
        /** The licence's `LGK1-` paste form for Copy key; null without a licence. */
        val licenceKey: String? = null,
    ) {
        val isPro: Boolean get() = purchased || license != null

        /** The licence by id only: never the holder's name or email. */
        override fun toString(): String =
            "State(purchased=$purchased, license=${license?.licenseId}, price=$price, busy=$busy, note=$note, canBuy=$canBuy, licenceKey=${if (licenceKey == null) "none" else "set"})"
    }

    private val _state = MutableStateFlow(State(purchased = purchased))
    val state: StateFlow<State> = _state.asStateFlow()

    val isPro: Boolean get() = _state.value.isPro
    val purchased: Boolean get() = _state.value.purchased
    val license: LicenseInfo? get() = _state.value.license
    val price: String? get() = _state.value.price
    val busy: Boolean get() = _state.value.busy
    val note: ProNote? get() = _state.value.note

    /** The current note in the current display language. */
    val message: String? get() = _state.value.note?.let { txt.s(it.res) }
    val canBuy: Boolean get() = _state.value.canBuy

    private val observing = AtomicBoolean(false)
    private val claiming = AtomicBoolean(false)

    /** A claim that failed this launch waits for the next one. */
    @Volatile private var claimFailedThisLaunch = false

    /**
     * The entitlement only (Play's purchase list, cached by the Play Store). Runs at launch, so it never looks up the
     * product. A refresh whose coroutine was cancelled meanwhile keeps the last known value: a cut-short read could
     * otherwise say "not purchased".
     */
    suspend fun refresh() {
        val entitled = purchases.isEntitled()
        if (!currentCoroutineContext().isActive) return
        _state.update { it.copy(purchased = entitled) }
    }

    /** The product price, loaded only when the upgrade sheet is shown. */
    suspend fun loadPrice() {
        if (_state.value.price != null) return
        when (val offer = purchases.offer()) {
            is ProOffer.Available -> _state.update {
                // An earlier lookup that found none said so: the product is there now.
                it.copy(price = offer.price, canBuy = true, note = if (it.note == ProNote.UNAVAILABLE) null else it.note)
            }
            ProOffer.Unavailable -> markUnavailable()
            ProOffer.Unknown -> {}
        }
    }

    private fun markUnavailable() = _state.update { it.copy(canBuy = false, note = ProNote.UNAVAILABLE) }

    /** Once: every purchase update from Play re-reads the entitlement, in [scope] (the app's). */
    fun startObserving(scope: CoroutineScope) {
        if (!observing.compareAndSet(false, true)) return
        val changes = purchases.entitlementChanges()
        scope.launch { changes.collect { refresh() } }
    }

    /** Re-reads the synced licence states. */
    fun update(snapshot: StoreSnapshot) {
        val info = ItemLimit.validLicense(snapshot, licenseKeys)
        val key = info?.let { snapshot.records[License.stateId(it.licenseId)] }
            ?.let { (it as? JsonValue.Obj)?.fields?.get("record") }
            ?.let { LicenceText.encode(it) }
        _state.update { it.copy(license = info, licenceKey = key) }
    }

    /**
     * Task 9: after an acknowledged `pro_unlimited` purchase, with no valid licence state in [store], claim the desktop
     * licence once and write it as the licence state sync already carries ([onWritten] tells sync). Silent: Pro on this
     * phone never depends on it. A failure retries at the next launch; a refusal (403) stops for good.
     */
    suspend fun claimIfNeeded(store: ItemStore, onWritten: () -> Unit = {}) {
        val claimer = claimer ?: return
        if (!_state.value.purchased || claimFailedThisLaunch) return
        if (claimFlags.read() == ClaimFlag.REFUSED) return
        if (!claiming.compareAndSet(false, true)) return
        try {
            val snap = store.load()
            update(snap)
            if (_state.value.license != null) return
            val token = purchases.purchaseToken() ?: return
            when (val answer = claimer.claim(token)) {
                ClaimResult.Refused -> claimFlags.write(ClaimFlag.REFUSED)
                ClaimResult.RetryLater -> retryLater()
                is ClaimResult.Licence -> if (write(store, answer.text)) {
                    claimFlags.write(ClaimFlag.NONE)
                    onWritten()
                } else {
                    retryLater()
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // A locked vault, a store write that failed: silent, the next launch tries again.
            retryLater()
        } finally {
            claiming.set(false)
        }
    }

    private fun retryLater() {
        claimFailedThisLaunch = true
        claimFlags.write(ClaimFlag.RETRY)
    }

    /** Verifies [text] with the app's licence keys, then stores it under its `lic:` id; false when it does not verify. */
    private fun write(store: ItemStore, text: String): Boolean {
        val bundle = LicenceText.decode(text) ?: return false
        val info = try {
            License.verify(bundle, licenseKeys)
        } catch (e: LicenseException) {
            return false
        }
        val snap = store.load()
        val records = LinkedHashMap(snap.records)
        records[License.stateId(info.licenseId)] = Wrapper.make(Namespace.LICENSE, bundle)
        store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
        update(store.load())
        return true
    }

    suspend fun buy() {
        if (!_state.value.canBuy) {
            _state.update { it.copy(note = ProNote.UNAVAILABLE) }
            return
        }
        _state.update { it.copy(busy = true, note = null) }
        try {
            when (purchases.purchase()) {
                PurchaseOutcome.PURCHASED -> {
                    val entitled = purchases.isEntitled()
                    _state.update { it.copy(purchased = entitled) }
                }
                PurchaseOutcome.PENDING -> setNote(ProNote.PENDING)
                PurchaseOutcome.CANCELLED -> {}
                PurchaseOutcome.UNVERIFIED -> setNote(ProNote.UNVERIFIED)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: ProPurchaseException.Unavailable) {
            markUnavailable()
        } catch (e: Exception) {
            // Cancelled by the user: nothing to say.
            if (!ProPurchaseException.isCancellation(e)) setNote(ProNote.PURCHASE_FAILED)
        } finally {
            _state.update { it.copy(busy = false) }
        }
    }

    suspend fun restore() {
        _state.update { it.copy(busy = true, note = null) }
        try {
            val found = purchases.restore()
            _state.update {
                it.copy(purchased = found, note = if (found) null else ProNote.NOTHING_TO_RESTORE)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: ProPurchaseException.Unavailable) {
            // Ruling 24: no billing on this phone: the sheet keeps saying Pro is not available (Buy disabled).
            markUnavailable()
        } catch (e: Exception) {
            if (ProPurchaseException.isCancellation(e)) {
                // Cancelled: silent (but a missing product still says so).
                if (!_state.value.canBuy) setNote(ProNote.UNAVAILABLE)
            } else {
                setNote(ProNote.RESTORE_FAILED)
            }
        } finally {
            _state.update { it.copy(busy = false) }
        }
    }

    private fun setNote(note: ProNote) = _state.update { it.copy(note = note) }

    val unavailableMessage: String get() = txt.s(R.string.pro_unavailable)
    val pendingMessage: String get() = txt.s(R.string.pro_purchase_pending)

    /** Ruling 25: the iPhone's "The App Store could not verify…" with Google Play swapped in (no leading "The"). */
    val unverifiedMessage: String get() = txt.s(R.string.pro_unverified)
    val purchaseFailedMessage: String get() = txt.s(R.string.pro_purchase_failed)
    val nothingToRestoreMessage: String get() = txt.s(R.string.pro_nothing_to_restore)
    val restoreFailedMessage: String get() = txt.s(R.string.pro_restore_failed)
}
