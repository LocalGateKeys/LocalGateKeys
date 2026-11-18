package app.localgatekeys.android.ui.theme

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toPixelMap
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.unit.dp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test

/** Glass and the toast surface on a device: no backdrop inside a host's content, and toasts never let content through. */
class GlassTest {
    @get:Rule val rule = createComposeRule()

    @Test fun glass_inside_a_backdrop_hosts_content_gets_no_backdrop_and_draws() {
        var seen: Any? = "unset"
        rule.setContent {
            LgkTheme {
                GlassBackdropHost(Modifier.fillMaxSize()) {
                    AuroraBackground()
                    seen = LocalGlassBackdrop.current
                    // Placed inside the content on purpose: it must fall back to the solid fill, not sample its own layer.
                    Box(Modifier.size(48.dp).lgkGlass(CircleShape).testTag("inner-glass"))
                }
            }
        }
        rule.waitForIdle()
        assertNull(seen)
        rule.onNodeWithTag("inner-glass").captureToImage()
    }

    @Test fun the_toast_surface_is_opaque_over_content() {
        var surface = Color.Unspecified
        rule.setContent {
            LgkTheme {
                surface = LgkTheme.colors.groupSurface
                Box(Modifier.fillMaxSize().background(Color.Red)) {
                    Box(Modifier.align(Alignment.Center).size(200.dp, 48.dp).lgkToastSurface(RoundedCornerShape(24.dp)).testTag("toast"))
                }
            }
        }
        val pixels = rule.onNodeWithTag("toast").captureToImage().toPixelMap()
        // The middle of the capsule (no text there): the group surface, with none of the red below showing through.
        assertEquals(surface, pixels[pixels.width / 2, pixels.height / 2])
    }
}
