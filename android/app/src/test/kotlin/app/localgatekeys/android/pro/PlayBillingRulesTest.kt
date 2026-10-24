package app.localgatekeys.android.pro

import com.android.billingclient.api.BillingClient.BillingResponseCode
import com.android.billingclient.api.BillingClient.ProductType
import com.android.billingclient.api.Purchase.PurchaseState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * What PlayBillingPurchases makes of Play's answers (the Play side of StoreKitPurchaseTests; no test talks to Play):
 * `pro_unlimited` is a one-time INAPP product, only a PURCHASED purchase is the entitlement, purchases are acknowledged on
 * receipt, a pending one grants nothing, and billing that is unavailable says so.
 */
class PlayBillingRulesTest {
    private fun purchase(state: Int, acknowledged: Boolean = false, products: List<String> = listOf("pro_unlimited"), token: String = "tok-1") =
        PlayPurchase(products, state, acknowledged, token)

    @Test fun the_product_is_pro_unlimited_a_one_time_inapp_product() {
        assertEquals("pro_unlimited", PlayBillingPurchases.PRODUCT_ID)
        assertEquals(ProductType.INAPP, PlayBillingPurchases.PRODUCT_TYPE)
        assertEquals("inapp", PlayBillingPurchases.PRODUCT_TYPE)
    }

    @Test fun only_a_purchased_pro_unlimited_is_the_entitlement() {
        assertTrue(PlayBillingRules.entitled(listOf(purchase(PurchaseState.PURCHASED))))
        assertTrue(PlayBillingRules.entitled(listOf(purchase(PurchaseState.PURCHASED, acknowledged = true))))
        assertFalse(PlayBillingRules.entitled(emptyList()))
        assertFalse(PlayBillingRules.entitled(listOf(purchase(PurchaseState.UNSPECIFIED_STATE))))
        assertFalse(PlayBillingRules.entitled(listOf(purchase(PurchaseState.PURCHASED, products = listOf("other_product")))))
    }

    @Test fun pending_purchase_grants_nothing() {
        val pending = listOf(purchase(PurchaseState.PENDING))
        assertFalse(PlayBillingRules.entitled(pending))
        assertTrue("a pending purchase is never acknowledged", PlayBillingRules.toAcknowledge(pending).isEmpty())
        assertEquals(PurchaseOutcome.PENDING, PlayBillingRules.outcome(BillingResponseCode.OK, pending))
    }

    @Test fun purchased_and_unacknowledged_purchases_are_acknowledged() {
        val list = listOf(
            purchase(PurchaseState.PURCHASED, acknowledged = false, token = "a"),
            purchase(PurchaseState.PURCHASED, acknowledged = true, token = "b"),
            purchase(PurchaseState.PENDING, token = "c"),
            purchase(PurchaseState.PURCHASED, products = listOf("other_product"), token = "d"),
        )
        assertEquals(listOf("a"), PlayBillingRules.toAcknowledge(list))
    }

    @Test fun purchase_results_map_to_outcomes() {
        assertEquals(PurchaseOutcome.PURCHASED, PlayBillingRules.outcome(BillingResponseCode.OK, listOf(purchase(PurchaseState.PURCHASED))))
        assertEquals(
            "a purchased one wins over an older pending one",
            PurchaseOutcome.PURCHASED,
            PlayBillingRules.outcome(BillingResponseCode.OK, listOf(purchase(PurchaseState.PENDING), purchase(PurchaseState.PURCHASED))),
        )
        assertEquals(PurchaseOutcome.UNVERIFIED, PlayBillingRules.outcome(BillingResponseCode.OK, listOf(purchase(PurchaseState.UNSPECIFIED_STATE))))
        // OK with nothing listed: the model re-reads the entitlement, which decides.
        assertEquals(PurchaseOutcome.PURCHASED, PlayBillingRules.outcome(BillingResponseCode.OK, null))
        assertEquals(PurchaseOutcome.CANCELLED, PlayBillingRules.outcome(BillingResponseCode.USER_CANCELED, null))
        // Bought before (another phone, a lost acknowledgement): the entitlement read finds and acknowledges it.
        assertEquals(PurchaseOutcome.PURCHASED, PlayBillingRules.outcome(BillingResponseCode.ITEM_ALREADY_OWNED, null))
    }

    @Test fun missing_product_or_billing_is_unavailable_and_other_failures_are_errors() {
        for (code in listOf(BillingResponseCode.ITEM_UNAVAILABLE, BillingResponseCode.BILLING_UNAVAILABLE, BillingResponseCode.FEATURE_NOT_SUPPORTED)) {
            try {
                PlayBillingRules.outcome(code, null)
                fail("code $code")
            } catch (e: ProPurchaseException.Unavailable) {
                // expected
            }
        }
        for (code in listOf(BillingResponseCode.ERROR, BillingResponseCode.NETWORK_ERROR, BillingResponseCode.SERVICE_UNAVAILABLE,
            BillingResponseCode.SERVICE_DISCONNECTED, BillingResponseCode.DEVELOPER_ERROR)) {
            try {
                PlayBillingRules.outcome(code, null)
                fail("code $code")
            } catch (e: BillingException) {
                assertEquals(code, e.responseCode)
                assertFalse(ProPurchaseException.isCancellation(e))
            }
        }
        assertTrue(ProPurchaseException.isCancellation(BillingException(BillingResponseCode.USER_CANCELED, "")))
        assertFalse(ProPurchaseException.isCancellation(ProPurchaseException.Unavailable()))
    }

    @Test fun a_failure_keeps_plays_debug_message() {
        val e = PlayBillingRules.failure(BillingResponseCode.ERROR, "Play says: try later")
        assertTrue(e is BillingException)
        assertTrue(e.message!!.contains("Play says: try later"))
    }

    @Test fun offers() {
        assertEquals(ProOffer.Available("US$4.99"), PlayBillingRules.offer(BillingResponseCode.OK, "US$4.99"))
        assertEquals("lookup worked, no product", ProOffer.Unavailable, PlayBillingRules.offer(BillingResponseCode.OK, null))
        assertEquals("no Play Store / not signed in", ProOffer.Unavailable, PlayBillingRules.offer(BillingResponseCode.BILLING_UNAVAILABLE, null))
        assertEquals(ProOffer.Unavailable, PlayBillingRules.offer(BillingResponseCode.ITEM_UNAVAILABLE, null))
        for (code in listOf(BillingResponseCode.NETWORK_ERROR, BillingResponseCode.SERVICE_UNAVAILABLE, BillingResponseCode.SERVICE_TIMEOUT,
            BillingResponseCode.SERVICE_DISCONNECTED, BillingResponseCode.ERROR)) {
            assertEquals("code $code: the product may exist", ProOffer.Unknown, PlayBillingRules.offer(code, null))
        }
    }

    @Test fun a_purchase_never_prints_its_token() {
        val p = purchase(PurchaseState.PURCHASED, token = "secret-token-123")
        assertFalse(p.toString().contains("secret-token-123"))
    }
}
