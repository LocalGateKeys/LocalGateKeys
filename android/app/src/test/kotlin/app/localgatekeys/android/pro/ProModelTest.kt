package app.localgatekeys.android.pro

import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.editor.clock
import app.localgatekeys.android.editor.editor
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.editor.numberedNotes
import app.localgatekeys.android.vault.snapshot
import com.android.billingclient.api.BillingClient.BillingResponseCode
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.plus
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The ProModel rules. Ports of `ProAvailabilityTests`, `ProOutcomeTests`, `test_launch_refresh_reads_only_the_entitlement`
 * (EditorTOTPAndInputTests), the restore / buy / cancelled part of `test_fifth_item_needs_pro` (EditorAndLimitTests) and
 * `StoreKitPurchaseTests` (over the fake: tests never reach Play), plus the Android cases.
 */
class ProModelTest {
    private fun pro(purchases: ProPurchasing = FakePurchases(), keys: Map<String, ByteArray> = emptyMap()) =
        ProModel(purchases, keys)

    /** One random source for every editor, so each new note gets its own id. */
    private val random = CountingRandom()

    private fun newNote(store: CountingStore, p: ProModel): EditorModel =
        EditorModel(store, null, EditorKind.NOTE, { p.isPro }, clock(), random).also { it.set(it.titleKey, "More"); it.set("body", "x") }

    // MARK: ProAvailabilityTests

    @Test fun no_product_shows_not_available_and_disables_buy() = runBlocking {
        val purchases = FakePurchases().apply { offerResult = ProOffer.Unavailable }
        val p = pro(purchases)
        assertTrue("until the product is looked up", p.canBuy)
        p.loadPrice()
        assertFalse(p.canBuy)
        assertNull(p.price)
        assertEquals(ProModel.UNAVAILABLE_MESSAGE, p.message)
        assertEquals("Pro isn't available yet", ProModel.UNAVAILABLE_MESSAGE)
        p.buy()
        assertEquals("Buy never starts a purchase of a missing product", 0, purchases.purchaseCalls)
        assertEquals("Pro isn't available yet", p.message)
    }

    @Test fun a_later_lookup_that_finds_the_product_clears_the_message() = runBlocking {
        val purchases = FakePurchases().apply { offerResult = ProOffer.Unavailable }
        val p = pro(purchases)
        p.loadPrice()
        assertEquals(ProModel.UNAVAILABLE_MESSAGE, p.message)
        purchases.offerResult = ProOffer.Available("$4.99")
        p.loadPrice() // the sheet opened again once the product went live
        assertNull(p.message)
        assertTrue(p.canBuy)
        assertEquals("$4.99", p.price)
    }

    @Test fun purchase_finding_no_product_says_not_available() = runBlocking {
        val purchases = FakePurchases().apply { purchaseError = ProPurchaseException.Unavailable() }
        val p = pro(purchases)
        p.buy()
        assertEquals("Pro isn't available yet", p.message)
        assertFalse(p.canBuy)
    }

    @Test fun lookup_failure_keeps_buy_enabled() = runBlocking {
        val purchases = FakePurchases().apply { offerResult = ProOffer.Unknown }
        val p = pro(purchases)
        p.loadPrice()
        assertTrue("offline: the lookup failed, the product may well exist", p.canBuy)
        assertNull(p.message)
    }

    @Test fun cancelled_restore_or_purchase_is_silent() = runBlocking {
        // Play reports a cancellation as USER_CANCELED (StoreKit had three shapes; Play has this one).
        val cancellations = listOf(BillingException(BillingResponseCode.USER_CANCELED, "cancelled"))
        for (error in cancellations) {
            val purchases = FakePurchases().apply { restoreError = error; purchaseError = error }
            val p = pro(purchases)
            p.restore()
            assertNull("restore: $error", p.message)
            p.buy()
            assertNull("buy: $error", p.message)
            assertTrue(p.canBuy)
        }
    }

    @Test fun other_restore_failures_still_explain() = runBlocking {
        val purchases = FakePurchases().apply { restoreError = BillingException(BillingResponseCode.NETWORK_ERROR, "offline") }
        val p = pro(purchases)
        p.restore()
        assertEquals("Purchases could not be restored. Try again later.", p.message)
    }

    // MARK: ProOutcomeTests

    @Test fun unverified_purchase_shows_an_error_not_cancelled() = runBlocking {
        val fake = FakePurchases().apply { purchaseResult = PurchaseOutcome.UNVERIFIED }
        val p = pro(fake)
        p.buy()
        assertFalse(p.isPro)
        assertEquals("Google Play could not verify this purchase. Try Restore purchases or try again later.", p.message)
        fake.purchaseResult = PurchaseOutcome.CANCELLED
        p.buy()
        assertNull(p.message)
    }

    // MARK: EditorTOTPAndInputTests.test_launch_refresh_reads_only_the_entitlement

    @Test fun launch_refresh_reads_only_the_entitlement() = runBlocking {
        val purchases = FakePurchases()
        val p = pro(purchases)
        val observer = Job()
        p.startObserving(this + observer)
        p.refresh()
        assertEquals("no product lookup at launch", 0, purchases.priceCalls)
        assertEquals("no restore at launch", 0, purchases.restoreCalls)
        assertNull(p.price)
        p.loadPrice()
        assertEquals("$4.99", p.price)
        observer.cancel()
    }

    // MARK: EditorAndLimitTests.test_fifth_item_needs_pro (the purchase half; the limit half is EditorModelTest)

    @Test fun fifth_item_needs_pro() = runBlocking {
        val store = CountingStore(snapshot(numberedNotes(3)))
        val purchases = FakePurchases()
        val p = pro(purchases)
        p.refresh(); p.update(store.snapshot)
        val fourth = editor(store, null, EditorKind.NOTE, { p.isPro }).also { it.set("title", "Fourth"); it.set("body", "b") }
        assertEquals(SaveResult.SAVED, fourth.save())
        assertEquals(4, ItemLimit.liveCount(store.snapshot))

        val fifth = editor(store, null, EditorKind.NOTE, { p.isPro }).also { it.set("title", "Fifth"); it.set("body", "b") }
        assertEquals(SaveResult.NEEDS_PRO, fifth.save())
        assertTrue(fifth.showUpgrade)
        assertEquals(4, ItemLimit.liveCount(store.snapshot))

        // Restore purchases with nothing to restore keeps the limit.
        p.restore()
        assertFalse(p.isPro)
        assertEquals("No purchase was found for this Google account.", p.message)

        p.buy()
        assertEquals(1, purchases.purchaseCalls)
        assertTrue(p.isPro)
        assertNull(p.message)
        assertEquals(SaveResult.SAVED, fifth.save())
        assertEquals(5, ItemLimit.liveCount(store.snapshot))

        // A cancelled purchase leaves the free plan in place.
        val other = FakePurchases().apply { purchaseResult = PurchaseOutcome.CANCELLED }
        val q = pro(other)
        q.buy()
        assertFalse(q.isPro)
        assertNull(q.message)
    }

    // MARK: StoreKitPurchaseTests, over the fake (the Play side is PlayBillingRulesTest)

    @Test fun purchase_and_restore() = runBlocking {
        val store = FakePurchases()
        assertFalse(store.isEntitled())
        assertTrue(store.offer() is ProOffer.Available)
        assertEquals(PurchaseOutcome.PURCHASED, store.purchase())
        assertTrue(store.isEntitled())

        val p = pro(store)
        p.restore()
        assertTrue(p.isPro)

        store.entitled = false // refunded / cleared
        p.refresh()
        assertFalse(p.isPro)
    }

    /** The item-limit gate end to end: blocked, buy, allowed; then a fresh model with nothing in memory restores. */
    @Test fun gate_end_to_end_buy_then_restore() = runBlocking {
        val store = CountingStore(snapshot(numberedNotes(ItemLimit.FREE_ITEMS)))
        val play = FakePurchases()
        val p = pro(play)
        p.refresh()
        assertFalse(p.isPro)
        val blocked = newNote(store, p)
        assertEquals(SaveResult.NEEDS_PRO, blocked.save())
        assertTrue(blocked.showUpgrade)
        p.buy()
        assertNull(p.message)
        assertTrue(p.isPro)
        assertEquals(SaveResult.SAVED, newNote(store, p).save())

        val fresh = pro(play)
        assertFalse(fresh.isPro)
        fresh.restore()
        assertTrue(fresh.isPro)
        assertEquals(SaveResult.SAVED, newNote(store, fresh).save())
        assertEquals(2, store.commits)

        // With the purchase gone, restore must find nothing: the entitlement above came from restore reading Play.
        play.entitled = false
        val cleared = pro(play)
        cleared.restore()
        assertFalse(cleared.isPro)
        assertEquals(SaveResult.NEEDS_PRO, newNote(store, cleared).save())
    }

    @Test fun missing_product_is_unavailable_and_buy_never_reaches_play() = runBlocking {
        val play = FakePurchases().apply { offerResult = ProOffer.Unavailable; purchaseError = ProPurchaseException.Unavailable() }
        val p = pro(play)
        p.loadPrice()
        assertFalse(p.canBuy)
        assertEquals("Pro isn't available yet", p.message)
        p.buy()
        assertEquals(0, play.purchaseCalls)
        assertEquals("Pro isn't available yet", p.message)
        assertFalse(p.isPro)
    }

    // MARK: Android cases

    @Test fun pending_purchase_grants_nothing() = runBlocking {
        val play = FakePurchases().apply { purchaseResult = PurchaseOutcome.PENDING }
        val p = pro(play)
        p.buy()
        assertFalse(p.isPro)
        assertEquals("The purchase is waiting for approval.", p.message)
        p.refresh()
        assertFalse("a pending purchase is not an entitlement", p.isPro)
        // Approved later: Play reports it outside the purchase call and the observer re-reads the entitlement.
        val observer = Job()
        p.startObserving(this + observer)
        yield() // the observer subscribes
        play.entitled = true
        play.changes.emit(Unit)
        withTimeout(5_000) { while (!p.isPro) yield() }
        observer.cancel()
    }

    @Test fun billing_unavailable_keeps_synced_licence() = runBlocking {
        val v = LicenseVector.load()
        val (stateId, wrapper, keys) = Triple(v.id, v.wrapper, v.keys)
        val store = CountingStore(snapshot(numberedNotes(4), extra = mapOf(stateId to wrapper)))
        val play = FakePurchases().apply {
            offerResult = ProOffer.Unavailable
            purchaseError = ProPurchaseException.Unavailable()
            restoreError = ProPurchaseException.Unavailable()
        }
        val p = pro(play, keys)
        p.refresh(); p.update(store.snapshot)
        assertTrue(p.isPro)
        assertEquals("lic-vector-0001", p.license?.licenseId)
        p.loadPrice()
        assertFalse(p.canBuy)
        assertEquals(ProModel.UNAVAILABLE_MESSAGE, p.message)
        p.restore()
        assertTrue("billing failing never takes the synced licence away", p.isPro)
        assertEquals("Ruling 24: restore with no billing still says Pro is not available", ProModel.UNAVAILABLE_MESSAGE, p.message)
        assertEquals(SaveResult.SAVED, newNote(store, p).save())

        // The licence goes away with the next snapshot that lacks it.
        p.update(snapshot(numberedNotes(5)))
        assertFalse(p.isPro)
    }

    @Test fun licence_needs_known_keys() = runBlocking {
        val v = LicenseVector.load()
        val (stateId, wrapper) = v.id to v.wrapper
        val p = pro(keys = emptyMap())
        p.update(snapshot(numberedNotes(1), extra = mapOf(stateId to wrapper)))
        assertFalse("no licence keys known: the licence cannot verify", p.isPro)
        assertNull(p.license)
    }

    @Test fun a_cancelled_refresh_keeps_the_last_known_entitlement() = runBlocking {
        val play = FakePurchases().apply { entitled = true }
        val p = ProModel(play, emptyMap(), purchased = true)
        assertTrue(p.isPro)
        lateinit var job: Job
        play.entitled = false
        play.duringIsEntitled = { job.cancel() }
        job = launch(start = CoroutineStart.LAZY) { p.refresh() }
        job.join()
        assertTrue("a cut-short entitlement read never says 'not purchased'", p.isPro)
    }

    @Test fun observing_starts_once_and_refreshes_on_every_change() = runBlocking {
        val play = FakePurchases()
        val p = pro(play)
        val observer = Job()
        p.startObserving(this + observer)
        p.startObserving(this + observer)
        yield()
        play.entitled = true
        play.changes.emit(Unit)
        withTimeout(5_000) { while (!p.isPro) yield() }
        assertEquals("one observer, one refresh per change", 1, play.entitledCalls)
        play.entitled = false
        play.changes.emit(Unit)
        withTimeout(5_000) { while (p.isPro) yield() }
        observer.cancelAndJoin()
    }

    @Test fun busy_while_buying_and_cleared_after() = runBlocking {
        val gate = CompletableDeferred<Unit>()
        val play = FakePurchases().apply { purchaseGate = gate }
        val p = pro(play)
        val buying = launch { p.buy() }
        withTimeout(5_000) { while (!p.busy) yield() }
        assertNull(p.message)
        gate.complete(Unit)
        buying.join()
        assertFalse(p.busy)
        assertTrue(p.isPro)
    }

    @Test fun a_purchase_that_fails_otherwise_explains() = runBlocking {
        val play = FakePurchases().apply { purchaseError = BillingException(BillingResponseCode.SERVICE_UNAVAILABLE, "down") }
        val p = pro(play)
        p.buy()
        assertEquals("The purchase could not be completed. Try again later.", p.message)
        assertTrue(p.canBuy)
        assertFalse(p.busy)
    }

    @Test fun a_cancelled_restore_after_no_product_still_says_not_available() = runBlocking {
        val play = FakePurchases().apply { offerResult = ProOffer.Unavailable; restoreError = BillingException(BillingResponseCode.USER_CANCELED, "") }
        val p = pro(play)
        p.loadPrice()
        p.restore()
        assertEquals(ProModel.UNAVAILABLE_MESSAGE, p.message)
    }

    @Test fun state_never_prints_the_licence_holder() {
        val v = LicenseVector.load()
        val p = pro(keys = v.keys)
        p.update(snapshot(numberedNotes(1), extra = mapOf(v.id to v.wrapper)))
        val info = p.license!!
        val text = p.state.value.toString()
        assertFalse(text, text.contains(info.name))
        assertFalse(text, text.contains(info.email))
        assertTrue(text, text.contains(info.licenseId))
    }

    @Test fun messages_use_google_play_words() {
        val messages = listOf(
            ProModel.UNAVAILABLE_MESSAGE, ProModel.PENDING_MESSAGE, ProModel.UNVERIFIED_MESSAGE, ProModel.PURCHASE_FAILED_MESSAGE,
            ProModel.NOTHING_TO_RESTORE_MESSAGE, ProModel.RESTORE_FAILED_MESSAGE,
        )
        for (m in messages) assertFalse(m, m.contains("Apple") || m.contains("App Store") || m.contains("iPhone"))
        assertEquals("Google Play could not verify this purchase. Try Restore purchases or try again later.", ProModel.UNVERIFIED_MESSAGE)
        assertEquals("No purchase was found for this Google account.", ProModel.NOTHING_TO_RESTORE_MESSAGE)
    }

    /** EditorModel reads isPro on an IO thread at save time: the state is readable from any thread. */
    @Test fun is_pro_is_read_safely_from_another_thread() = runBlocking {
        val p = pro()
        p.buy()
        val seen = AtomicBoolean(false)
        val done = CountDownLatch(1)
        Thread { seen.set(p.isPro); done.countDown() }.start()
        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertTrue(seen.get())
        assertNotNull(p.state.value)
        launch(Dispatchers.IO) { assertTrue(p.isPro) }.join()
    }
}
