package app.localgatekeys.android.ui.theme

import app.localgatekeys.android.settings.AvatarInitials
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Port of AuroraTests.swift (the settings round trip is in AppSettingsTest). */
class AuroraTest {
    @Test fun reduce_transparency_is_plain_background() {
        assertNull(AuroraStyle.blobOpacity(dark = false, reduceTransparency = true, increasedContrast = false))
        assertNull(AuroraStyle.blobOpacity(dark = true, reduceTransparency = true, increasedContrast = true))
    }

    @Test fun opacity_light_dark_and_contrast() {
        assertEquals(0.35f, AuroraStyle.blobOpacity(false, false, false)!!, 0.0001f)
        assertEquals(0.45f, AuroraStyle.blobOpacity(true, false, false)!!, 0.0001f)
        assertEquals(0.175f, AuroraStyle.blobOpacity(false, false, true)!!, 0.0001f)
        assertEquals(0.225f, AuroraStyle.blobOpacity(true, false, true)!!, 0.0001f)
    }

    @Test fun blur_is_100_dp() {
        assertEquals(100, AuroraStyle.BLUR_DP)
    }

    @Test fun avatar_initials() {
        assertNull(AvatarInitials.from(""))
        assertNull(AvatarInitials.from("  "))
        assertNull(AvatarInitials.from("12"))
        assertEquals("IP", AvatarInitials.from("ip"))
        assertEquals("IP", AvatarInitials.from(" i p "))
        assertEquals("AE", AvatarInitials.from("Alex Example"))
        assertEquals("AB", AvatarInitials.from("abc"))
        assertEquals("É", AvatarInitials.from("é"))
    }
}
