package app.localgatekeys.android.pro

import app.localgatekeys.core.records.LicenseInfo
import app.localgatekeys.core.sync.StoreSnapshot
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
class ProModel(
    private val purchases: ProPurchasing,
    private val licenseKeys: Map<String, ByteArray> = LicenseKeys.production,
    purchased: Boolean = false,
) {
    data class State(
        val purchased: Boolean = false,
        val license: LicenseInfo? = null,
        val price: String? = null,
        val busy: Boolean = false,
        val message: String? = null,
        /** False once Play has said there is no `pro_unlimited` product (or no billing): Buy is disabled. */
        val canBuy: Boolean = true,
    ) {
        val isPro: Boolean get() = purchased || license != null

        /** The licence by id only: never the holder's name or email. */
        override fun toString(): String =
            "State(purchased=$purchased, license=${license?.licenseId}, price=$price, busy=$busy, message=$message, canBuy=$canBuy)"
    }

    private val _state = MutableStateFlow(State(purchased = purchased))
    val state: StateFlow<State> = _state.asStateFlow()

    val isPro: Boolean get() = _state.value.isPro
    val purchased: Boolean get() = _state.value.purchased
    val license: LicenseInfo? get() = _state.value.license
    val price: String? get() = _state.value.price
    val busy: Boolean get() = _state.value.busy
    val message: String? get() = _state.value.message
    val canBuy: Boolean get() = _state.value.canBuy

    private val observing = AtomicBoolean(false)

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
                it.copy(price = offer.price, canBuy = true, message = if (it.message == UNAVAILABLE_MESSAGE) null else it.message)
            }
            ProOffer.Unavailable -> markUnavailable()
            ProOffer.Unknown -> {}
        }
    }

    private fun markUnavailable() = _state.update { it.copy(canBuy = false, message = UNAVAILABLE_MESSAGE) }

    /** Once: every purchase update from Play re-reads the entitlement, in [scope] (the app's). */
    fun startObserving(scope: CoroutineScope) {
        if (!observing.compareAndSet(false, true)) return
        val changes = purchases.entitlementChanges()
        scope.launch { changes.collect { refresh() } }
    }

    /** Re-reads the synced licence states. */
    fun update(snapshot: StoreSnapshot) {
        val info = ItemLimit.validLicense(snapshot, licenseKeys)
        _state.update { it.copy(license = info) }
    }

    suspend fun buy() {
        if (!_state.value.canBuy) {
            _state.update { it.copy(message = UNAVAILABLE_MESSAGE) }
            return
        }
        _state.update { it.copy(busy = true, message = null) }
        try {
            when (purchases.purchase()) {
                PurchaseOutcome.PURCHASED -> {
                    val entitled = purchases.isEntitled()
                    _state.update { it.copy(purchased = entitled) }
                }
                PurchaseOutcome.PENDING -> setMessage(PENDING_MESSAGE)
                PurchaseOutcome.CANCELLED -> {}
                PurchaseOutcome.UNVERIFIED -> setMessage(UNVERIFIED_MESSAGE)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: ProPurchaseException.Unavailable) {
            markUnavailable()
        } catch (e: Exception) {
            // Cancelled by the user: nothing to say.
            if (!ProPurchaseException.isCancellation(e)) setMessage(PURCHASE_FAILED_MESSAGE)
        } finally {
            _state.update { it.copy(busy = false) }
        }
    }

    suspend fun restore() {
        _state.update { it.copy(busy = true, message = null) }
        try {
            val found = purchases.restore()
            _state.update {
                it.copy(purchased = found, message = if (found) null else NOTHING_TO_RESTORE_MESSAGE)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: ProPurchaseException.Unavailable) {
            // Ruling 24: no billing on this phone: the sheet keeps saying Pro is not available (Buy disabled).
            markUnavailable()
        } catch (e: Exception) {
            if (ProPurchaseException.isCancellation(e)) {
                // Cancelled: silent (but a missing product still says so).
                if (!_state.value.canBuy) setMessage(UNAVAILABLE_MESSAGE)
            } else {
                setMessage(RESTORE_FAILED_MESSAGE)
            }
        } finally {
            _state.update { it.copy(busy = false) }
        }
    }

    private fun setMessage(text: String) = _state.update { it.copy(message = text) }

    companion object {
        const val UNAVAILABLE_MESSAGE = "Pro isn't available yet"
        const val PENDING_MESSAGE = "The purchase is waiting for approval."

        /** Ruling 25: the iPhone's "The App Store could not verify…" with Google Play swapped in (no leading "The"). */
        const val UNVERIFIED_MESSAGE = "Google Play could not verify this purchase. Try Restore purchases or try again later."
        const val PURCHASE_FAILED_MESSAGE = "The purchase could not be completed. Try again later."
        const val NOTHING_TO_RESTORE_MESSAGE = "No purchase was found for this Google account."
        const val RESTORE_FAILED_MESSAGE = "Purchases could not be restored. Try again later."
    }
}
