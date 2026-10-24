package app.localgatekeys.android.pro

import android.content.Intent
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The real Play Billing client on a phone without the Play Store (the LGK test emulators): billing is unavailable, so the
 * sheet says Pro is not available and nothing is entitled. Skipped where the Play Store is installed, so this test never
 * talks to Google Play.
 */
class PlayBillingNoStoreTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    /** Whether a Play Store with a billing service is installed (the emulator images carry a stub without one). */
    private fun playStoreInstalled(): Boolean =
        context.packageManager.queryIntentServices(
            Intent("com.android.vending.billing.InAppBillingService.BIND").setPackage("com.android.vending"), 0,
        ).isNotEmpty()

    @Test fun no_play_store_means_billing_unavailable() = runBlocking {
        assumeTrue("the Play Store is installed: skipped so no test contacts Play", !playStoreInstalled())
        val port = PlayBillingClientPort(context) { null }
        val unavailable = com.android.billingclient.api.BillingClient.BillingResponseCode.BILLING_UNAVAILABLE
        assertEquals(unavailable, port.connect().code)
        // Again, after the failed connection (automatic reconnection makes isReady read true from here on).
        assertEquals(unavailable, port.connect().code)
        val play = PlayBillingPurchases(port)
        assertEquals(ProOffer.Unavailable, play.offer())
        assertFalse(play.isEntitled())
        val pro = ProModel(play, emptyMap())
        pro.loadPrice()
        assertFalse(pro.canBuy)
        assertEquals(ProModel.UNAVAILABLE_MESSAGE, pro.message)
    }
}
