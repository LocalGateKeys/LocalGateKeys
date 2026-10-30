package app.localgatekeys.android.pro

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow

/** The Swift test `FakePurchases`: a scripted [ProPurchasing] that counts its calls. */
class FakePurchases : ProPurchasing {
    @Volatile var entitled = false
    var purchaseResult = PurchaseOutcome.PURCHASED
    var restoreFinds = false
    var offerResult: ProOffer = ProOffer.Available("$4.99")
    var purchaseError: Exception? = null
    var restoreError: Exception? = null
    var purchaseCalls = 0
    var restoreCalls = 0
    var priceCalls = 0
    var entitledCalls = 0

    /** The acknowledged purchase's token ([purchaseToken]); null when none. */
    var token: String? = null

    /** Runs while the entitlement read is "in flight" (a slow Play answer). */
    var duringIsEntitled: (() -> Unit)? = null

    /** Awaited inside [purchase] (the Play purchase screen still open). */
    var purchaseGate: CompletableDeferred<Unit>? = null

    /** Out-of-band purchase updates (a pending purchase approved later, a refund). */
    val changes = MutableSharedFlow<Unit>(extraBufferCapacity = 8)

    override suspend fun isEntitled(): Boolean {
        entitledCalls++
        duringIsEntitled?.invoke()
        return entitled
    }

    override suspend fun offer(): ProOffer {
        priceCalls++
        return offerResult
    }

    override suspend fun purchase(): PurchaseOutcome {
        purchaseCalls++
        purchaseGate?.await()
        purchaseError?.let { throw it }
        if (purchaseResult == PurchaseOutcome.PURCHASED) entitled = true
        return purchaseResult
    }

    override suspend fun restore(): Boolean {
        restoreCalls++
        restoreError?.let { throw it }
        if (restoreFinds) entitled = true
        return entitled
    }

    override suspend fun purchaseToken(): String? = if (entitled) token else null

    override fun entitlementChanges(): Flow<Unit> = changes
}
