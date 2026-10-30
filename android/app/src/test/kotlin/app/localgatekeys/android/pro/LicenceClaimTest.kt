package app.localgatekeys.android.pro

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import com.android.billingclient.api.Purchase.PurchaseState
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Task 9 (the Swift LicenceClaimTests): a Play purchase claims a desktop licence, silently, once. */
class LicenceClaimTest {
    private val vector = LicenseVector.load()
    private val bundle = (vector.wrapper as JsonValue.Obj).fields.getValue("record")
    private val licenceText = LicenceText.encode(bundle)

    private class MemStore(var snap: StoreSnapshot = StoreSnapshot()) : ItemStore {
        var commits = 0
        override fun load(): StoreSnapshot = snap
        override fun commit(change: StoreChange) {
            commits++
            snap = StoreSnapshot(change.records, change.meta, change.sync, snap.revision + 1)
        }
    }

    private class FakeClaimer(var result: ClaimResult) : LicenceClaiming {
        val tokens = mutableListOf<String>()
        override suspend fun claim(purchaseToken: String): ClaimResult {
            tokens += purchaseToken
            return result
        }
    }

    private fun model(claimer: LicenceClaiming, flags: ClaimFlagStore, entitled: Boolean = true, token: String? = "tok") =
        ProModel(
            FakePurchases().also { it.entitled = entitled; it.token = token },
            licenseKeys = vector.keys, purchased = entitled, claimer = claimer, claimFlags = flags,
            txt = EnglishTxt(),
        )

    @Test
    fun claim_writes_licence_state() = runBlocking {
        val claimer = FakeClaimer(ClaimResult.Licence(licenceText))
        val store = MemStore()
        var written = 0
        val m = model(claimer, MemoryClaimFlags())
        m.claimIfNeeded(store) { written++ }
        assertEquals(listOf("tok"), claimer.tokens)
        assertEquals(vector.wrapper, store.snap.records[vector.id])
        assertEquals(1, written)
        assertNotNull(m.license)
        assertEquals(licenceText, m.state.value.licenceKey)
    }

    @Test
    fun no_claim_when_licence_exists() = runBlocking {
        val claimer = FakeClaimer(ClaimResult.Licence(licenceText))
        val store = MemStore(StoreSnapshot(records = mapOf(vector.id to vector.wrapper)))
        model(claimer, MemoryClaimFlags()).claimIfNeeded(store)
        assertTrue(claimer.tokens.isEmpty())
        assertEquals(0, store.commits)
    }

    @Test
    fun offline_retries_next_launch() = runBlocking {
        val flags = MemoryClaimFlags()
        val claimer = FakeClaimer(ClaimResult.RetryLater)
        val store = MemStore()
        val first = model(claimer, flags)
        first.claimIfNeeded(store)
        first.claimIfNeeded(store) // same launch: not again
        assertEquals(1, claimer.tokens.size)
        assertEquals(ClaimFlag.RETRY, flags.read())
        assertEquals(0, store.commits)
        // Next launch (a new model, the persisted flag): online now.
        claimer.result = ClaimResult.Licence(licenceText)
        model(claimer, flags).claimIfNeeded(store)
        assertEquals(2, claimer.tokens.size)
        assertEquals(vector.wrapper, store.snap.records[vector.id])
        assertEquals(ClaimFlag.NONE, flags.read())
    }

    @Test
    fun refused_stops_retrying() = runBlocking {
        val flags = MemoryClaimFlags()
        val claimer = FakeClaimer(ClaimResult.Refused)
        val store = MemStore()
        model(claimer, flags).claimIfNeeded(store)
        assertEquals(ClaimFlag.REFUSED, flags.read())
        model(claimer, flags).claimIfNeeded(store)
        assertEquals(1, claimer.tokens.size)
        assertEquals(0, store.commits)
    }

    @Test
    fun bad_licence_not_written() = runBlocking {
        val store = MemStore()
        for (text in listOf("LGK1-notbase64!", "LGK1-", "garbage")) {
            model(FakeClaimer(ClaimResult.Licence(text)), MemoryClaimFlags()).claimIfNeeded(store)
        }
        // Correctly shaped but signed by a key the app does not hold.
        val other = ProModel(
            FakePurchases().also { it.entitled = true; it.token = "tok" }, licenseKeys = LicenseKeys.production,
            purchased = true, claimer = FakeClaimer(ClaimResult.Licence(licenceText)), claimFlags = MemoryClaimFlags(),
            txt = EnglishTxt(),
        )
        other.claimIfNeeded(store)
        assertEquals(0, store.commits)
        assertNull(other.license)
    }

    @Test
    fun no_claim_without_entitlement() = runBlocking {
        val claimer = FakeClaimer(ClaimResult.Licence(licenceText))
        val store = MemStore()
        model(claimer, MemoryClaimFlags(), entitled = false).claimIfNeeded(store)
        // Entitled but no acknowledged purchase yet: nothing to claim with.
        model(claimer, MemoryClaimFlags(), token = null).claimIfNeeded(store)
        assertTrue(claimer.tokens.isEmpty())
        assertEquals(0, store.commits)
    }

    @Test
    fun only_an_acknowledged_purchase_token_is_claimed() {
        val id = listOf(PlayBillingPurchases.PRODUCT_ID)
        assertNull(PlayBillingRules.claimToken(listOf(PlayPurchase(id, PurchaseState.PURCHASED, false, "a")), emptySet()))
        assertNull(PlayBillingRules.claimToken(listOf(PlayPurchase(id, PurchaseState.PENDING, true, "p")), emptySet()))
        assertEquals("a", PlayBillingRules.claimToken(listOf(PlayPurchase(id, PurchaseState.PURCHASED, false, "a")), setOf("a")))
        assertEquals("b", PlayBillingRules.claimToken(listOf(PlayPurchase(id, PurchaseState.PURCHASED, true, "b")), emptySet()))
    }

    @Test
    fun request_and_response_follow_the_worker() {
        val body = CanonicalJson.parse(HttpLicenceClaim.requestBody("t\"k")).obj().fields
        assertEquals(mapOf("purchaseToken" to JsonValue.Str("t\"k"), "productId" to JsonValue.Str("pro_unlimited")), body)
        assertEquals(
            ClaimResult.Licence("LGK1-abc"),
            HttpLicenceClaim.result(200, """{"licence": "LGK1-abc"}""".toByteArray()),
        )
        assertEquals(ClaimResult.Refused, HttpLicenceClaim.result(403, ByteArray(0)))
        assertEquals(ClaimResult.RetryLater, HttpLicenceClaim.result(400, ByteArray(0)))
        assertEquals(ClaimResult.RetryLater, HttpLicenceClaim.result(429, ByteArray(0)))
        assertEquals(ClaimResult.RetryLater, HttpLicenceClaim.result(503, ByteArray(0)))
        assertEquals(ClaimResult.RetryLater, HttpLicenceClaim.result(200, "not json".toByteArray()))
        assertEquals("https://licenses.localgatekeys.app/play/claim", HttpLicenceClaim.URL)
    }

    @Test
    fun licence_text_round_trips() {
        assertTrue(licenceText.startsWith("LGK1-"))
        assertEquals(bundle, LicenceText.decode(licenceText))
        assertEquals(bundle, LicenceText.decode("  " + licenceText.chunked(20).joinToString("\n") + ".\n"))
        assertNull(LicenceText.decode("LGK1-%%%"))
    }
}
