package app.localgatekeys.android.ui.vault

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountBalance
import androidx.compose.material.icons.filled.Badge
import androidx.compose.material.icons.filled.Bookmark
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Repeat
import androidx.compose.material.icons.filled.ShoppingBag
import androidx.compose.material.icons.filled.StickyNote2
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import app.localgatekeys.android.ui.theme.Palette

/** The kind symbol and tint of a row (iPhone `VaultRow.icon` / `tint`, mapped to Material icons). */
object KindStyle {
    fun icon(kind: String): ImageVector = when (kind) {
        "web" -> Icons.Filled.Language
        "desktop" -> Icons.Filled.Computer
        "note" -> Icons.Filled.StickyNote2
        "card" -> Icons.Filled.CreditCard
        "identity" -> Icons.Filled.Badge
        "bookmark" -> Icons.Filled.Bookmark
        "wifi" -> Icons.Filled.Wifi
        "passkey" -> Icons.Filled.Fingerprint
        "ssh_key" -> Icons.Filled.Terminal
        "api_key" -> Icons.Filled.Code
        "license" -> Icons.Filled.Key
        "purchase" -> Icons.Filled.ShoppingBag
        "subscription" -> Icons.Filled.Repeat
        "warranty" -> Icons.Filled.VerifiedUser
        "bank_account" -> Icons.Filled.AccountBalance
        else -> Icons.Filled.Description
    }

    fun tint(kind: String, c: Palette.Tokens): Color = when (kind) {
        "card", "bank_account", "purchase", "subscription", "warranty" -> c.success
        "note", "license" -> c.warning
        "identity" -> c.identityTint
        "passkey" -> c.accent
        else -> c.accentText
    }
}
