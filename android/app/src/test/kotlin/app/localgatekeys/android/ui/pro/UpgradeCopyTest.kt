package app.localgatekeys.android.ui.pro

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The upgrade sheet's and capacity strip's copy (UpgradeView.swift, platform words adapted). */
class UpgradeCopyTest {
    @Test fun capacity_strip_caption() {
        assertEquals("No limit on items", CapacityStrip.caption(used = 2, isPro = true))
        assertEquals("No limit on items", CapacityStrip.caption(used = null, isPro = true))
        assertEquals("Free: 4 items. Pro: no limit.", CapacityStrip.caption(used = null, isPro = false))
        assertEquals("0 of 4 free items used. Pro: no limit.", CapacityStrip.caption(used = 0, isPro = false))
        assertEquals("3 of 4 free items used. Pro: no limit.", CapacityStrip.caption(used = 3, isPro = false))
        assertEquals("over the limit still reads 4 of 4", "4 of 4 free items used. Pro: no limit.", CapacityStrip.caption(used = 9, isPro = false))
    }

    @Test fun capacity_strip_slots() {
        assertEquals(listOf(true, true, false, false), (0 until 4).map { CapacityStrip.filled(it, used = 2, isPro = false) })
        assertEquals(listOf(false, false, false, false), (0 until 4).map { CapacityStrip.filled(it, used = null, isPro = false) })
        assertEquals(listOf(true, true, true, true), (0 until 4).map { CapacityStrip.filled(it, used = 7, isPro = false) })
        assertEquals(listOf(true, true, true, true), (0 until 4).map { CapacityStrip.filled(it, used = 0, isPro = true) })
    }

    @Test fun sheet_copy() {
        assertEquals("LocalGateKeys Pro", UpgradeCopy.TITLE)
        assertEquals("Everything is unlocked on this phone.", UpgradeCopy.subtitle(isPro = true))
        assertEquals("Pay once for unlimited items and two‑factor codes.", UpgradeCopy.subtitle(isPro = false))
        assertEquals("Buy for $4.99", UpgradeCopy.buyLabel("$4.99"))
        assertEquals("Buy Pro", UpgradeCopy.buyLabel(null))
        assertEquals(
            listOf(
                "Unlimited items" to "Logins, cards, notes and everything else, past the free 4.",
                "Two-factor codes" to "Add and change 2FA codes. Codes you already saved keep working without Pro.",
                "One payment" to "No subscription and no account. Restore it on another phone with the same Google account.",
            ),
            UpgradeCopy.benefits,
        )
        assertEquals("Sync with your PC needs Pro on the PC as well.", UpgradeCopy.SYNC_FOOTER)
        assertEquals("One-time purchase, no subscription.", UpgradeCopy.ONE_TIME)
        assertEquals("Pro is active", UpgradeCopy.ACTIVE)
        assertEquals("Restore purchases", UpgradeCopy.RESTORE)
        assertEquals("Close", UpgradeCopy.CLOSE)
    }

    @Test fun no_apple_words_and_no_website_links() {
        val all = listOf(UpgradeCopy.TITLE, UpgradeCopy.subtitle(true), UpgradeCopy.subtitle(false), UpgradeCopy.SYNC_FOOTER,
            UpgradeCopy.ONE_TIME, UpgradeCopy.ACTIVE, UpgradeCopy.RESTORE) + UpgradeCopy.benefits.flatMap { listOf(it.first, it.second) }
        for (s in all) {
            assertFalse(s, s.contains("iPhone") || s.contains("Apple") || s.contains("App Store"))
            assertFalse(s, s.contains("http") || s.contains("localgatekeys.app"))
        }
        assertTrue(UpgradeCopy.benefits.size == 3)
    }
}
