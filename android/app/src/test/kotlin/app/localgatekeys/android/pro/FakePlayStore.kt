package app.localgatekeys.android.pro

import com.android.billingclient.api.BillingClient.BillingResponseCode
import com.android.billingclient.api.Purchase.PurchaseState

/**
 * A Play Store in memory behind the [PlayBillingPort] seam (the Swift tests' StoreKit test session): the owned purchases,
 * the product, and what the purchase sheet does when launched. Never talks to Google Play.
 */
class FakePlayStore : PlayBillingPort {
    /** What connecting answers (BILLING_UNAVAILABLE: no Play Store, or not signed in). */
    var connectCode = BillingResponseCode.OK
    var purchasesCode = BillingResponseCode.OK
    var productCode = BillingResponseCode.OK

    /** The product's formatted price; null: Play has no such product (not set up in the Play Console). */
    var price: String? = "$4.99"
    val owned = mutableListOf<PlayPurchase>()

    /** What the purchase sheet answers through the listener; null: launch returns [launchCode] and nothing arrives. */
    var sheet: (() -> Pair<Int, List<PlayPurchase>?>)? = {
        val p = PlayPurchase(listOf(PlayBillingPurchases.PRODUCT_ID), PurchaseState.PURCHASED, acknowledged = false, token = "tok-1")
        own(p)
        BillingResponseCode.OK to listOf(p)
    }

    /** Adds [p] to the account, replacing a purchase with the same token (Play keeps one purchase per token). */
    fun own(p: PlayPurchase) {
        owned.removeAll { it.token == p.token }
        owned += p
    }

    var launchCode = BillingResponseCode.OK

    /** Play's debug message on every answer (never shown to users). */
    var debugMessage = ""
    var ackCode = BillingResponseCode.OK
    var connectCalls = 0
    var launchCalls = 0
    var productQueries = 0
    var purchaseQueries = 0
    val acknowledged = mutableListOf<String>()

    private var listener: (PlayResult<List<PlayPurchase>?>) -> Unit = {}

    override fun setListener(listener: (PlayResult<List<PlayPurchase>?>) -> Unit) {
        this.listener = listener
    }

    /** A purchase update outside any purchase call (a pending purchase completed, a purchase on another phone). */
    fun deliver(code: Int, purchases: List<PlayPurchase>?) = listener(PlayResult(code, purchases, debugMessage))

    override suspend fun connect(): PlayResult<Unit> {
        connectCalls++
        return PlayResult(connectCode, Unit, debugMessage)
    }

    override suspend fun queryPurchases(): PlayResult<List<PlayPurchase>> {
        purchaseQueries++
        return PlayResult(purchasesCode, if (purchasesCode == BillingResponseCode.OK) owned.toList() else emptyList(), debugMessage)
    }

    override suspend fun queryProduct(): PlayResult<String?> {
        productQueries++
        return PlayResult(productCode, if (productCode == BillingResponseCode.OK) price else null, debugMessage)
    }

    override suspend fun launch(): PlayResult<Unit> {
        launchCalls++
        if (launchCode != BillingResponseCode.OK) return PlayResult(launchCode, Unit, debugMessage)
        val s = sheet ?: return PlayResult(BillingResponseCode.OK, Unit)
        val (code, list) = s()
        listener(PlayResult(code, list, debugMessage))
        return PlayResult(BillingResponseCode.OK, Unit)
    }

    override suspend fun acknowledge(token: String): Int {
        acknowledged += token
        if (ackCode == BillingResponseCode.OK) {
            owned.replaceAll { if (it.token == token) it.copy(acknowledged = true) else it }
        }
        return ackCode
    }
}
