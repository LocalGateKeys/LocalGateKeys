package app.localgatekeys.android.ui.vault

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.vault.SiteLogoImages
import app.localgatekeys.android.vault.SiteLogos
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.siteLogo

/**
 * The row icon: a bundled brand logo on its brand colour for a web login whose site is listed (no website icon is ever
 * downloaded on Android), else the kind symbol on its tint at 14%. Corner radius is 0.29 of the size.
 */
@Composable
fun ItemAvatar(item: VaultItem, size: Dp = 42.dp, logos: SiteLogos = SiteLogos.shared(LocalContext.current)) {
    val c = LgkTheme.colors
    val shape = RoundedCornerShape(size * 0.29f)
    val logo = remember(item.id, item.record, logos) { item.siteLogo(logos) }
    val drawable = logo?.let { SiteLogoImages.ids[it.slug] }
    if (logo != null && drawable != null) {
        Box(Modifier.size(size).background(Color(0xFF000000 or logo.rgb.toLong()), shape), contentAlignment = Alignment.Center) {
            Icon(
                painterResource(drawable), null,
                Modifier.size(size).padding(size * 0.24f),
                tint = if (logo.isLight) Color.Black else Color.White,
            )
        }
    } else {
        val tint = KindStyle.tint(item.kind, c)
        Box(Modifier.size(size).background(tint.copy(alpha = 0.14f), shape), contentAlignment = Alignment.Center) {
            Icon(KindStyle.icon(item.kind), null, Modifier.size(size * 0.5f), tint = tint)
        }
    }
}
