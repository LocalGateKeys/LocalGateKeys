package app.localgatekeys.android.pro

import android.app.Activity
import android.content.Context
import com.android.billingclient.api.AcknowledgePurchaseParams
import com.android.billingclient.api.BillingClient
import com.android.billingclient.api.BillingClient.BillingResponseCode
import com.android.billingclient.api.BillingClientStateListener
import com.android.billingclient.api.BillingFlowParams
import com.android.billingclient.api.BillingResult
import com.android.billingclient.api.PendingPurchasesParams
import com.android.billingclient.api.ProductDetails
import com.android.billingclient.api.Purchase
import com.android.billingclient.api.Purchase.PurchaseState
import com.android.billingclient.api.QueryProductDetailsParams
import com.android.billingclient.api.QueryPurchasesParams
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/** One Play purchase, as much of it as the rules need (from `Purchase`). Its token is never printed. */
data class PlayPurchase(
    val products: List<String>,
    /** `Purchase.PurchaseState`. */
    val state: Int,
    val acknowledged: Boolean,
    val token: String,
) {
    override fun toString(): String = "PlayPurchase(products=$products, state=$state, acknowledged=$acknowledged)"
}

/** One Play answer: its `BillingResponseCode`, the value, and Play's debug message (for errors only; never shown to users). */
data class PlayResult<out T>(val code: Int, val value: T, val debugMessage: String = "")

/** What Play's answers mean for `pro_unlimited` (pure, so JVM tests cover them). */
object PlayBillingRules {
    private val unavailableCodes = setOf(
        BillingResponseCode.ITEM_UNAVAILABLE, BillingResponseCode.BILLING_UNAVAILABLE, BillingResponseCode.FEATURE_NOT_SUPPORTED,
    )

    private fun mine(purchases: List<PlayPurchase>) = purchases.filter { PlayBillingPurchases.PRODUCT_ID in it.products }

    /** Only a PURCHASED `pro_unlimited` is the entitlement; PENDING grants nothing. */
    fun entitled(purchases: List<PlayPurchase>): Boolean = mine(purchases).any { it.state == PurchaseState.PURCHASED }

    /** Tokens of PURCHASED `pro_unlimited` purchases not acknowledged yet (Play refunds those after 3 days). */
    fun toAcknowledge(purchases: List<PlayPurchase>): List<String> =
        mine(purchases).filter { it.state == PurchaseState.PURCHASED && !it.acknowledged }.map { it.token }

    /** The claim token: a PURCHASED `pro_unlimited` that Play lists as acknowledged or whose acknowledgement just worked. */
    fun claimToken(purchases: List<PlayPurchase>, acknowledgedNow: Set<String>): String? =
        mine(purchases).firstOrNull { it.state == PurchaseState.PURCHASED && (it.acknowledged || it.token in acknowledgedNow) }?.token

    /** The purchase sheet's answer. Throws [ProPurchaseException.Unavailable] or [BillingException] for failures. */
    fun outcome(code: Int, purchases: List<PlayPurchase>?, debugMessage: String = ""): PurchaseOutcome = when (code) {
        BillingResponseCode.OK -> {
            val list = mine(purchases.orEmpty())
            when {
                list.any { it.state == PurchaseState.PURCHASED } -> PurchaseOutcome.PURCHASED
                list.any { it.state == PurchaseState.PENDING } -> PurchaseOutcome.PENDING
                list.isNotEmpty() -> PurchaseOutcome.UNVERIFIED
                // Nothing listed: the model re-reads the entitlement, which decides.
                else -> PurchaseOutcome.PURCHASED
            }
        }
        BillingResponseCode.USER_CANCELED -> PurchaseOutcome.CANCELLED
        // Bought before on this account: the entitlement read that follows finds (and acknowledges) it.
        BillingResponseCode.ITEM_ALREADY_OWNED -> PurchaseOutcome.PURCHASED
        else -> throw failure(code, debugMessage)
    }

    /** The product lookup's answer ([price] null: Play listed no such product). */
    fun offer(code: Int, price: String?): ProOffer = when {
        code == BillingResponseCode.OK -> price?.let { ProOffer.Available(it) } ?: ProOffer.Unavailable
        code in unavailableCodes -> ProOffer.Unavailable
        else -> ProOffer.Unknown
    }

    /** No product or no billing on this phone: unavailable; anything else: a billing error carrying Play's debug message. */
    fun failure(code: Int, debugMessage: String = ""): Exception =
        if (code in unavailableCodes) ProPurchaseException.Unavailable() else BillingException(code, debugMessage)
}

/** The few Play Billing calls the app makes, as plain values, so [PlayBillingPurchases] runs in JVM tests over a fake. */
interface PlayBillingPort {
    /** The purchase updates (`PurchasesUpdatedListener`): the purchase sheet's results and updates outside a purchase. */
    fun setListener(listener: (PlayResult<List<PlayPurchase>?>) -> Unit)

    /** Connects when not connected; OK once connected (BILLING_UNAVAILABLE: no Play Store, or not signed in). */
    suspend fun connect(): PlayResult<Unit>

    /** `queryPurchasesAsync` (INAPP): the account's current purchases, from the Play Store's cache when offline. */
    suspend fun queryPurchases(): PlayResult<List<PlayPurchase>>

    /** `queryProductDetailsAsync` for `pro_unlimited`: its formatted one-time price, or null when Play has no such product. */
    suspend fun queryProduct(): PlayResult<String?>

    /** `launchBillingFlow` for the product last found by [queryProduct]; the result arrives through the listener. */
    suspend fun launch(): PlayResult<Unit>

    suspend fun acknowledge(token: String): Int
}

/**
 * Google Play Billing for `pro_unlimited`, a one-time (INAPP) product (the Android `StoreKitPurchases`).
 *
 * * Entitlement: a PURCHASED `pro_unlimited` in `queryPurchasesAsync`. A PENDING purchase grants nothing and is never
 *   acknowledged; it counts once Play reports it PURCHASED (an update outside the purchase call fires [entitlementChanges]).
 * * Every PURCHASED purchase is acknowledged on receipt; a failed acknowledgement is retried at the next entitlement read.
 * * A failed purchase query (Play busy or disconnected) keeps this process's last answer, so a hiccup never takes Pro
 *   away; with no Play Billing at all the answer is false (a synced licence still unlocks, in [ProModel]).
 */
class PlayBillingPurchases(private val port: PlayBillingPort) : ProPurchasing {
    /** [activity]: the activity Play's purchase sheet shows over. */
    constructor(context: Context, activity: () -> Activity?) : this(PlayBillingClientPort(context, activity))

    @Volatile private var lastKnown = false
    private val changes = MutableSharedFlow<Unit>(extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)

    /** The purchase call waiting for the sheet's answer; null when none. */
    private val waiting = AtomicReference<CompletableDeferred<PlayResult<List<PlayPurchase>?>>?>(null)
    private val purchaseLock = Mutex()

    init {
        port.setListener { answer ->
            val w = waiting.getAndSet(null)
            if (w != null) w.complete(answer) else changes.tryEmit(Unit)
        }
    }

    override suspend fun isEntitled(): Boolean = try {
        entitlement()
    } catch (e: ProPurchaseException) {
        false
    } catch (e: BillingException) {
        lastKnown
    }

    /** Reads the purchases and acknowledges any not acknowledged yet; throws when Play cannot answer. */
    private suspend fun entitlement(): Boolean {
        ok(port.connect())
        val answer = port.queryPurchases()
        ok(answer)
        acknowledge(answer.value)
        lastKnown = PlayBillingRules.entitled(answer.value)
        return lastKnown
    }

    /** Returns the tokens Play acknowledged now. */
    private suspend fun acknowledge(list: List<PlayPurchase>): Set<String> {
        // Best effort: a failure leaves the purchase owned; the next read tries again.
        val done = HashSet<String>()
        for (token in PlayBillingRules.toAcknowledge(list)) {
            if (port.acknowledge(token) == BillingResponseCode.OK) done.add(token)
        }
        return done
    }

    override suspend fun purchaseToken(): String? = try {
        ok(port.connect())
        val answer = port.queryPurchases()
        ok(answer)
        PlayBillingRules.claimToken(answer.value, acknowledge(answer.value))
    } catch (e: ProPurchaseException) {
        null
    } catch (e: BillingException) {
        null
    }

    override suspend fun offer(): ProOffer {
        val c = port.connect()
        if (c.code != BillingResponseCode.OK) return PlayBillingRules.offer(c.code, null)
        val product = port.queryProduct()
        return PlayBillingRules.offer(product.code, product.value)
    }

    override suspend fun purchase(): PurchaseOutcome = purchaseLock.withLock {
        ok(port.connect())
        val product = port.queryProduct()
        ok(product)
        if (product.value == null) throw ProPurchaseException.Unavailable()
        val answer = CompletableDeferred<PlayResult<List<PlayPurchase>?>>()
        waiting.set(answer)
        try {
            val launched = port.launch()
            if (launched.code != BillingResponseCode.OK) {
                return@withLock PlayBillingRules.outcome(launched.code, null, launched.debugMessage)
            }
            val result = answer.await()
            val outcome = PlayBillingRules.outcome(result.code, result.value, result.debugMessage)
            if (outcome == PurchaseOutcome.PURCHASED) acknowledge(result.value.orEmpty())
            outcome
        } finally {
            waiting.compareAndSet(answer, null)
        }
    }

    override suspend fun restore(): Boolean = entitlement()

    override fun entitlementChanges(): Flow<Unit> = changes

    private fun ok(answer: PlayResult<*>) {
        if (answer.code != BillingResponseCode.OK) throw PlayBillingRules.failure(answer.code, answer.debugMessage)
    }

    companion object {
        /** The Play Console product: one-time, US$4.99. */
        const val PRODUCT_ID = "pro_unlimited"
        const val PRODUCT_TYPE = BillingClient.ProductType.INAPP
    }
}

/** The real [PlayBillingPort]: one `BillingClient` for the process. Play calls back on the main thread. */
internal class PlayBillingClientPort(context: Context, private val activity: () -> Activity?) : PlayBillingPort {
    @Volatile private var listener: (PlayResult<List<PlayPurchase>?>) -> Unit = {}
    @Volatile private var details: ProductDetails? = null
    private val connectLock = Mutex()

    private val client: BillingClient = BillingClient.newBuilder(context.applicationContext)
        .setListener { result, purchases -> listener(PlayResult(result.responseCode, purchases?.map(::plain), result.debugMessage)) }
        .enablePendingPurchases(PendingPurchasesParams.newBuilder().enableOneTimeProducts().build())
        .enableAutoServiceReconnection()
        .build()

    override fun setListener(listener: (PlayResult<List<PlayPurchase>?>) -> Unit) {
        this.listener = listener
    }

    override suspend fun connect(): PlayResult<Unit> = connectLock.withLock {
        // Not isReady: with automatic reconnection it reads true while disconnected, and every call then answers
        // SERVICE_DISCONNECTED, so a phone without Play Billing would never hear BILLING_UNAVAILABLE.
        if (client.connectionState == BillingClient.ConnectionState.CONNECTED) return@withLock PlayResult(BillingResponseCode.OK, Unit)
        withTimeoutOrNull(CONNECT_TIMEOUT_MS) {
            suspendCancellableCoroutine { cont ->
                val once = AtomicBoolean(false)
                client.startConnection(object : BillingClientStateListener {
                    override fun onBillingSetupFinished(result: BillingResult) {
                        if (once.compareAndSet(false, true)) cont.resume(PlayResult(result.responseCode, Unit, result.debugMessage))
                    }

                    override fun onBillingServiceDisconnected() {
                        if (once.compareAndSet(false, true)) cont.resume(PlayResult(BillingResponseCode.SERVICE_DISCONNECTED, Unit))
                    }
                })
            }
        } ?: PlayResult(BillingResponseCode.SERVICE_TIMEOUT, Unit)
    }

    override suspend fun queryPurchases(): PlayResult<List<PlayPurchase>> = suspendCancellableCoroutine { cont ->
        val params = QueryPurchasesParams.newBuilder().setProductType(PlayBillingPurchases.PRODUCT_TYPE).build()
        client.queryPurchasesAsync(params) { result, list ->
            cont.resume(PlayResult(result.responseCode, list.map(::plain), result.debugMessage))
        }
    }

    override suspend fun queryProduct(): PlayResult<String?> = suspendCancellableCoroutine { cont ->
        val product = QueryProductDetailsParams.Product.newBuilder()
            .setProductId(PlayBillingPurchases.PRODUCT_ID).setProductType(PlayBillingPurchases.PRODUCT_TYPE).build()
        val params = QueryProductDetailsParams.newBuilder().setProductList(listOf(product)).build()
        client.queryProductDetailsAsync(params) { result, found ->
            val d = found.productDetailsList.firstOrNull { it.productId == PlayBillingPurchases.PRODUCT_ID }?.takeIf { offerOf(it) != null }
            if (result.responseCode == BillingResponseCode.OK) details = d
            cont.resume(PlayResult(result.responseCode, d?.let { offerOf(it)?.formattedPrice }, result.debugMessage))
        }
    }

    override suspend fun launch(): PlayResult<Unit> = withContext(Dispatchers.Main) {
        val a = activity() ?: return@withContext PlayResult(BillingResponseCode.ERROR, Unit, "no activity to show the purchase over")
        val d = details ?: return@withContext PlayResult(BillingResponseCode.ITEM_UNAVAILABLE, Unit)
        val p = BillingFlowParams.ProductDetailsParams.newBuilder().setProductDetails(d)
        offerOf(d)?.offerToken?.let { p.setOfferToken(it) }
        val params = BillingFlowParams.newBuilder().setProductDetailsParamsList(listOf(p.build())).build()
        val r = client.launchBillingFlow(a, params)
        PlayResult(r.responseCode, Unit, r.debugMessage)
    }

    override suspend fun acknowledge(token: String): Int = suspendCancellableCoroutine { cont ->
        val params = AcknowledgePurchaseParams.newBuilder().setPurchaseToken(token).build()
        client.acknowledgePurchase(params) { result -> cont.resume(result.responseCode) }
    }

    private fun offerOf(d: ProductDetails): ProductDetails.OneTimePurchaseOfferDetails? =
        d.oneTimePurchaseOfferDetailsList?.firstOrNull() ?: d.oneTimePurchaseOfferDetails

    private fun plain(p: Purchase) = PlayPurchase(p.products, p.purchaseState, p.isAcknowledged, p.purchaseToken)

    private companion object {
        const val CONNECT_TIMEOUT_MS = 15_000L
    }
}
