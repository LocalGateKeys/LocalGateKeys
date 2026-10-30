package app.localgatekeys.android.pro

import com.android.billingclient.api.BillingClient.BillingResponseCode
import kotlinx.coroutines.flow.Flow

/** `UNVERIFIED`: Play returned a purchase in no known state; it grants nothing. */
enum class PurchaseOutcome { PURCHASED, PENDING, CANCELLED, UNVERIFIED }

/**
 * What Google Play says about `pro_unlimited`. [Unavailable]: the lookup worked and returned no product (not set up in
 * the Play Console yet, not sold in this country), or billing is not available on this phone (no Play Store, Play not
 * signed in). [Unknown]: the lookup failed (offline); the product may exist.
 */
sealed interface ProOffer {
    data class Available(val price: String) : ProOffer
    data object Unavailable : ProOffer
    data object Unknown : ProOffer
}

sealed class ProPurchaseException(message: String) : Exception(message) {
    /** There is no `pro_unlimited` product to buy (or no billing on this phone). */
    class Unavailable : ProPurchaseException("pro_unlimited is not available")

    companion object {
        /** A cancellation by the user: Play's USER_CANCELED (StoreKit's other cancellation shapes have no Play twin). */
        fun isCancellation(e: Throwable): Boolean = e is BillingException && e.responseCode == BillingResponseCode.USER_CANCELED
    }
}

/** A Play Billing call that failed: its response code and Play's debug message (no purchase data; never shown to users). */
class BillingException(val responseCode: Int, debugMessage: String) : Exception("billing response $responseCode: $debugMessage")

/** Play Billing behind an interface so model tests use a fake (no test talks to Play). */
interface ProPurchasing {
    /** True while Play lists a PURCHASED `pro_unlimited` (served from the Play Store's cache when offline). */
    suspend fun isEntitled(): Boolean

    suspend fun offer(): ProOffer

    suspend fun purchase(): PurchaseOutcome

    /** "Restore purchases": re-read the purchases from Play, then the entitlement. */
    suspend fun restore(): Boolean

    /**
     * The token of the PURCHASED `pro_unlimited` purchase once it is acknowledged (the licence claim's proof); null when
     * there is none, it is not acknowledged yet, or Play cannot answer. Never logged.
     */
    suspend fun purchaseToken(): String?

    /** Fires when a purchase update arrives outside a purchase call (a pending purchase approved, a refund). */
    fun entitlementChanges(): Flow<Unit>
}
