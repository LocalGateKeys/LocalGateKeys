package app.localgatekeys.android.pro

import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.editor.clock
import app.localgatekeys.android.editor.numberedNotes
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.vault.snapshot
import com.android.billingclient.api.BillingClient.BillingResponseCode
import com.android.billingclient.api.Purchase.PurchaseState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Port of `ios/LocalGateKeysTests/StoreKitPurchaseTests.swift`: the StoreKit test session becomes [FakePlayStore] behind
 * the [PlayBillingPort] seam, so the real PlayBillingPurchases code runs. Plus the Play rules of the spec: one-time INAPP
 * product, acknowledged on receipt, pending grants nothing, entitlement from `queryPurchasesAsync`. Nothing here contacts
 * Google Play.
 */
class PlayBillingPurchasesTest {
    private fun purchase(state: Int, acknowledged: Boolean = false, token: String = "tok-1", product: String = PlayBillingPurchases.PRODUCT_ID) =
        PlayPurchase(listOf(product), state, acknowledged, token)

    // MARK: StoreKitPurchaseTests

    @Test fun play_purchase_and_restore() = runBlocking {
        val play = FakePlayStore()
        val store = PlayBillingPurchases(play)
        assertFalse(store.isEntitled())
        assertTrue(store.offer() is ProOffer.Available)
        assertEquals(PurchaseOutcome.PURCHASED, store.purchase())
        assertTrue(store.isEntitled())

        val p = ProModel(store, emptyMap())
        p.restore()
        assertTrue(p.isPro)

        play.owned.clear()
        assertFalse(store.isEntitled())
    }

    /** `test_storekit_product_is_a_non_consumable_without_family_sharing`: the product kind (its price is Play Console data). */
    @Test fun the_product_is_the_one_time_pro_unlimited() = runBlocking {
        assertEquals("pro_unlimited", PlayBillingPurchases.PRODUCT_ID)
        assertEquals("inapp", PlayBillingPurchases.PRODUCT_TYPE)
        val play = FakePlayStore()
        val store = PlayBillingPurchases(play)
        assertEquals(ProOffer.Available("$4.99"), store.offer())
        store.isEntitled()
        assertEquals(1, play.productQueries)
        assertEquals(1, play.purchaseQueries)
    }

    /** The item-limit gate end to end: blocked, buy, allowed; then a fresh model with nothing in memory restores. */
    @Test fun gate_end_to_end_buy_then_restore() = runBlocking {
        val play = FakePlayStore()
        val store = CountingStore(snapshot(numberedNotes(ItemLimit.FREE_ITEMS)))
        val pro = ProModel(PlayBillingPurchases(play), emptyMap())
        pro.refresh()
        assertFalse(pro.isPro)
        val random = CountingRandom() // one source for every editor, so each new note gets its own id
        fun newNote(p: ProModel) = EditorModel(store, null, EditorKind.NOTE, { p.isPro }, clock(), random)
            .apply { set(titleKey, "More"); set("body", "x") }
        val blocked = newNote(pro)
        assertEquals(SaveResult.NEEDS_PRO, blocked.save())
        assertTrue(blocked.showUpgrade)
        pro.buy()
        assertNull(pro.message)
        assertTrue(pro.isPro)
        assertEquals(SaveResult.SAVED, newNote(pro).save())

        val fresh = ProModel(PlayBillingPurchases(play), emptyMap())
        assertFalse(fresh.isPro)
        fresh.restore()
        assertTrue(fresh.isPro)
        assertEquals(SaveResult.SAVED, newNote(fresh).save())
        assertEquals(2, store.commits)

        // With the purchase gone (refunded), restore finds nothing: the entitlement above came from Play, not memory.
        play.owned.clear()
        val cleared = ProModel(PlayBillingPurchases(play), emptyMap())
        cleared.restore()
        assertFalse(cleared.isPro)
        assertEquals(SaveResult.NEEDS_PRO, newNote(cleared).save())
    }

    @Test fun missing_product_is_unavailable_and_buy_never_reaches_play() = runBlocking {
        val play = FakePlayStore().apply { price = null }
        val store = PlayBillingPurchases(play)
        assertEquals(ProOffer.Unavailable, store.offer())
        try {
            store.purchase()
            fail("bought a missing product")
        } catch (e: ProPurchaseException.Unavailable) {
            // expected
        }
        assertEquals(0, play.launchCalls)
        val p = ProModel(store, emptyMap())
        p.loadPrice()
        assertFalse(p.canBuy)
        assertEquals("Pro isn't available yet", p.message)
        p.buy()
        assertEquals("Pro isn't available yet", p.message)
        assertFalse(p.isPro)
        assertEquals(0, play.launchCalls)
    }

    @Test fun a_failed_lookup_is_unknown() = runBlocking {
        for (code in listOf(BillingResponseCode.NETWORK_ERROR, BillingResponseCode.SERVICE_UNAVAILABLE, BillingResponseCode.ERROR)) {
            assertEquals("$code", ProOffer.Unknown, PlayBillingPurchases(FakePlayStore().apply { productCode = code }).offer())
            assertEquals("$code", ProOffer.Unknown, PlayBillingPurchases(FakePlayStore().apply { connectCode = code }).offer())
        }
        assertEquals(ProOffer.Unavailable, PlayBillingPurchases(FakePlayStore().apply { productCode = BillingResponseCode.ITEM_UNAVAILABLE }).offer())
    }

    // MARK: acknowledgement

    @Test fun a_purchase_is_acknowledged_on_receipt() = runBlocking {
        val play = FakePlayStore()
        assertEquals(PurchaseOutcome.PURCHASED, PlayBillingPurchases(play).purchase())
        assertEquals(listOf("tok-1"), play.acknowledged)
        assertTrue(play.owned.single().acknowledged)
    }

    @Test fun a_failed_acknowledgement_is_retried_by_the_next_entitlement_read() = runBlocking {
        val play = FakePlayStore().apply { ackCode = BillingResponseCode.SERVICE_UNAVAILABLE }
        val store = PlayBillingPurchases(play)
        assertEquals("the purchase is owned even when the acknowledgement fails", PurchaseOutcome.PURCHASED, store.purchase())
        play.ackCode = BillingResponseCode.OK
        assertTrue(store.isEntitled())
        assertEquals(listOf("tok-1", "tok-1"), play.acknowledged)
        assertTrue(play.owned.single().acknowledged)
        // Already acknowledged: never again.
        assertTrue(store.isEntitled())
        assertEquals(2, play.acknowledged.size)
    }

    @Test fun other_products_are_ignored() = runBlocking {
        val play = FakePlayStore()
        play.owned += purchase(PurchaseState.PURCHASED, product = "something_else", token = "other")
        assertFalse(PlayBillingPurchases(play).isEntitled())
        assertTrue(play.acknowledged.isEmpty())
    }

    // MARK: plan review focus 4

    @Test fun pending_purchase_grants_nothing() = runBlocking {
        val play = FakePlayStore()
        play.sheet = {
            val p = purchase(PurchaseState.PENDING)
            play.own(p)
            BillingResponseCode.OK to listOf(p)
        }
        val store = PlayBillingPurchases(play)
        assertEquals(PurchaseOutcome.PENDING, store.purchase())
        assertFalse(store.isEntitled())
        assertTrue("a pending purchase is never acknowledged", play.acknowledged.isEmpty())

        val pro = ProModel(store, emptyMap())
        val scope = CoroutineScope(Dispatchers.Unconfined + Job())
        pro.startObserving(scope)
        pro.buy()
        assertFalse(pro.isPro)
        assertEquals("The purchase is waiting for approval.", pro.message)
        pro.restore()
        assertFalse(pro.isPro)

        // The payment went through later: Play reports it outside any purchase call; the model refreshes and acknowledges.
        play.owned.replaceAll { it.copy(state = PurchaseState.PURCHASED) }
        play.deliver(BillingResponseCode.OK, play.owned.toList())
        assertTrue(pro.isPro)
        assertEquals(listOf("tok-1"), play.acknowledged)
        scope.cancel()
    }

    @Test fun billing_unavailable_keeps_synced_licence() = runBlocking {
        val v = LicenseVector.load()
        val play = FakePlayStore().apply { connectCode = BillingResponseCode.BILLING_UNAVAILABLE }
        val store = PlayBillingPurchases(play)
        assertEquals(ProOffer.Unavailable, store.offer())
        assertFalse(store.isEntitled())
        for (call in listOf<suspend () -> Unit>({ store.purchase() }, { store.restore() })) {
            try {
                call()
                fail("no Play Store, yet the call went through")
            } catch (e: ProPurchaseException.Unavailable) {
                // expected
            }
        }
        assertEquals(0, play.launchCalls)

        val pro = ProModel(store, v.keys)
        pro.refresh()
        pro.update(snapshot(numberedNotes(4), extra = mapOf(v.id to v.wrapper)))
        pro.loadPrice()
        assertEquals(ProModel.UNAVAILABLE_MESSAGE, pro.message)
        assertFalse(pro.canBuy)
        assertTrue("a synced desktop licence still unlocks", pro.isPro)
        pro.restore()
        assertTrue(pro.isPro)
        assertEquals("Ruling 24: restore with no billing still says Pro is not available", ProModel.UNAVAILABLE_MESSAGE, pro.message)
        val store4 = CountingStore(snapshot(numberedNotes(4), extra = mapOf(v.id to v.wrapper)))
        val fifth = EditorModel(store4, null, EditorKind.NOTE, { pro.isPro }, clock(), CountingRandom())
            .apply { set("title", "Fifth"); set("body", "b") }
        assertEquals(SaveResult.SAVED, fifth.save())
    }

    @Test fun billing_unavailable_from_the_sheet_is_unavailable() = runBlocking {
        val sheet = FakePlayStore().apply { sheet = { BillingResponseCode.BILLING_UNAVAILABLE to null } }
        try {
            PlayBillingPurchases(sheet).purchase()
            fail()
        } catch (e: ProPurchaseException.Unavailable) {
            // expected
        }
    }

    // MARK: outcomes

    @Test fun a_cancelled_sheet_is_cancelled() = runBlocking {
        val play = FakePlayStore().apply { sheet = { BillingResponseCode.USER_CANCELED to null } }
        assertEquals(PurchaseOutcome.CANCELLED, PlayBillingPurchases(play).purchase())
        val p = ProModel(PlayBillingPurchases(play), emptyMap())
        p.buy()
        assertNull(p.message)
        assertFalse(p.isPro)
    }

    @Test fun already_owned_counts_as_purchased() = runBlocking {
        val play = FakePlayStore()
        play.owned += purchase(PurchaseState.PURCHASED)
        play.sheet = { BillingResponseCode.ITEM_ALREADY_OWNED to null }
        val p = ProModel(PlayBillingPurchases(play), emptyMap())
        p.buy()
        assertTrue(p.isPro)
        assertNull(p.message)
        assertEquals(listOf("tok-1"), play.acknowledged)
    }

    @Test fun an_ok_answer_listing_nothing_rereads_the_entitlement() = runBlocking {
        val play = FakePlayStore().apply { sheet = { BillingResponseCode.OK to null } }
        val p = ProModel(PlayBillingPurchases(play), emptyMap())
        p.buy()
        assertFalse("nothing owned: the entitlement read says no", p.isPro)
        val odd = FakePlayStore().apply {
            sheet = { BillingResponseCode.OK to listOf(purchase(PurchaseState.UNSPECIFIED_STATE, token = "t")) }
        }
        assertEquals(PurchaseOutcome.UNVERIFIED, PlayBillingPurchases(odd).purchase())
        assertTrue(odd.acknowledged.isEmpty())
    }

    @Test fun a_launch_failure_or_an_error_answer_is_an_error() = runBlocking {
        val launch = FakePlayStore().apply { launchCode = BillingResponseCode.DEVELOPER_ERROR }
        val answer = FakePlayStore().apply { sheet = { BillingResponseCode.ERROR to null } }
        for (play in listOf(launch, answer)) {
            try {
                PlayBillingPurchases(play).purchase()
                fail()
            } catch (e: BillingException) {
                assertTrue(e.responseCode == BillingResponseCode.DEVELOPER_ERROR || e.responseCode == BillingResponseCode.ERROR)
            }
            val p = ProModel(PlayBillingPurchases(play), emptyMap())
            p.buy()
            assertEquals("The purchase could not be completed. Try again later.", p.message)
        }
    }

    @Test fun a_failed_purchase_query_keeps_the_last_known_entitlement() = runBlocking {
        val play = FakePlayStore()
        play.owned += purchase(PurchaseState.PURCHASED, acknowledged = true)
        val store = PlayBillingPurchases(play)
        assertTrue(store.isEntitled())
        play.purchasesCode = BillingResponseCode.SERVICE_DISCONNECTED
        assertTrue("a Play hiccup does not take Pro away", store.isEntitled())
        play.purchasesCode = BillingResponseCode.OK
        play.owned.clear()
        assertFalse(store.isEntitled())
        play.purchasesCode = BillingResponseCode.SERVICE_UNAVAILABLE
        try {
            store.restore()
            fail()
        } catch (e: BillingException) {
            assertEquals(BillingResponseCode.SERVICE_UNAVAILABLE, e.responseCode)
        }
    }

    @Test fun billing_errors_carry_plays_debug_message_but_users_never_see_it() = runBlocking {
        val play = FakePlayStore().apply { purchasesCode = BillingResponseCode.ERROR; debugMessage = "Play says: try later" }
        val store = PlayBillingPurchases(play)
        try {
            store.restore()
            fail()
        } catch (e: BillingException) {
            assertTrue(e.message!!.contains("Play says: try later"))
        }
        val p = ProModel(store, emptyMap())
        p.restore()
        assertEquals("Purchases could not be restored. Try again later.", p.message)
        val sheet = FakePlayStore().apply { sheet = { BillingResponseCode.ERROR to null }; debugMessage = "sheet failed" }
        try {
            PlayBillingPurchases(sheet).purchase()
            fail()
        } catch (e: BillingException) {
            assertTrue(e.message!!.contains("sheet failed"))
        }
    }

    @Test fun updates_outside_a_purchase_are_entitlement_changes() = runBlocking {
        val play = FakePlayStore()
        val store = PlayBillingPurchases(play)
        var changes = 0
        val scope = CoroutineScope(Dispatchers.Unconfined + Job())
        scope.launch { store.entitlementChanges().collect { changes++ } }
        play.deliver(BillingResponseCode.OK, emptyList())
        assertEquals(1, changes)
        // An update that answers this phone's own purchase call is that call's result, not a change.
        store.purchase()
        assertEquals(1, changes)
        scope.cancel()
    }
}
