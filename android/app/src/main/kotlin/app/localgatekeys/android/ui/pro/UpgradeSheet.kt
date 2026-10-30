package app.localgatekeys.android.ui.pro
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.i18n.Txt
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.annotation.StringRes

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.Pin
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.R
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.pro.ProModel
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGlass
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import kotlinx.coroutines.launch

/** The upgrade sheet's copy (ios/App/Pro/UpgradeView.swift, platform words adapted). */
object UpgradeCopy {
    @StringRes val TITLE = R.string.pro_title
    @StringRes val SYNC_FOOTER = R.string.pro_sync_footer
    @StringRes val ACTIVE = R.string.settings_pro_active
    @StringRes val ONE_TIME = R.string.pro_one_time
    @StringRes val RESTORE = R.string.pro_restore
    @StringRes val CLOSE = R.string.common_close

    /** The free subtitle has a U+2011 non-breaking hyphen, as on the iPhone. */
    @StringRes fun subtitle(isPro: Boolean): Int = if (isPro) R.string.pro_subtitle_active else R.string.pro_subtitle_free

    /** Title and detail resource ids; every detail takes the free item limit as its first argument. The first is a plural. */
    val benefits: List<Pair<Int, Int>> = listOf(
        R.string.pro_benefit_items_title to R.plurals.pro_benefit_items_detail,
        R.string.pro_benefit_codes_title to R.string.pro_benefit_codes_detail,
        R.string.pro_benefit_payment_title to R.string.pro_benefit_payment_detail,
    )

    fun benefit(index: Int, txt: Txt): Pair<String, String> =
        txt.s(benefits[index].first) to
            if (index == 0) txt.plural(benefits[index].second, ItemLimit.FREE_ITEMS, ItemLimit.FREE_ITEMS)
            else txt.s(benefits[index].second, ItemLimit.FREE_ITEMS)

    fun buyLabel(price: String?, txt: Txt): String = price?.let { txt.s(R.string.pro_buy_for, it) } ?: txt.s(R.string.pro_buy)
}

/**
 * The upgrade sheet (port of `UpgradeView`): the Google Play purchase and "Restore purchases". The free plan's item slots
 * are drawn as a capacity strip ([itemsUsed]: live items, null where the caller does not have the count), and the purchase
 * sits in a glass bar pinned to the bottom. No links out of the app (spec section 4). Opening it re-reads the entitlement
 * and looks up the price; a purchase or restore that makes this phone Pro closes it.
 */
@Composable
fun UpgradeSheet(pro: ProModel, itemsUsed: Int?, onClose: () -> Unit) {
    val c = LgkTheme.colors
    val state by pro.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    LaunchedEffect(pro) {
        pro.refresh()
        pro.loadPrice()
    }
    BackHandler(onBack = onClose)
    // Takes every touch, so none reaches the screen underneath.
    Box(Modifier.fillMaxSize().pointerInput(Unit) { awaitPointerEventScope { while (true) awaitPointerEvent() } }.testTag("upgrade")) {
        GlassBackdropHost(Modifier.fillMaxSize()) { AuroraBackground() }
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            Row(Modifier.fillMaxWidth().height(56.dp).padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClose) { Text(stringResource(UpgradeCopy.CLOSE), color = c.accentText) }
            }
            Column(
                Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState())
                    .padding(start = 24.dp, end = 24.dp, top = 8.dp, bottom = 24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Column(
                    Modifier.widthIn(max = 520.dp).fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(22.dp),
                ) {
                    Header(state.isPro)
                    CapacityStrip(itemsUsed, state.isPro)
                    Column(
                        Modifier.fillMaxWidth().lgkGroupSurface(24.dp).padding(18.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        val icons = listOf(Icons.Filled.Layers, Icons.Filled.Pin, Icons.Filled.Verified)
                        UpgradeCopy.benefits.forEachIndexed { i, (title, detail) ->
                            Benefit(
                                icons[i], stringResource(title),
                                if (i == 0) pluralStringResource(detail, ItemLimit.FREE_ITEMS, ItemLimit.FREE_ITEMS)
                                else stringResource(detail, ItemLimit.FREE_ITEMS),
                            )
                        }
                    }
                    Text(
                        stringResource(UpgradeCopy.SYNC_FOOTER), color = c.secondaryText, style = MaterialTheme.typography.bodySmall,
                        textAlign = TextAlign.Center,
                    )
                }
            }
            PurchaseBar(state, onBuy = {
                scope.launch {
                    pro.buy()
                    if (pro.isPro) onClose()
                }
            }, onRestore = {
                scope.launch {
                    pro.restore()
                    if (pro.isPro) onClose()
                }
            })
        }
    }
}

@Composable
private fun Header(isPro: Boolean) {
    val c = LgkTheme.colors
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Image(
            painterResource(R.drawable.brand_mark), contentDescription = null,
            modifier = Modifier.size(72.dp).shadow(24.dp, RoundedCornerShape(16.dp), ambientColor = c.glowBlue, spotColor = c.glowBlue),
        )
        Text(
            stringResource(UpgradeCopy.TITLE), color = c.text, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            stringResource(UpgradeCopy.subtitle(isPro)),
            color = c.secondaryText, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center,
        )
    }
}

/** One line of what Pro adds: an icon in an accent tile, a title and one sentence. */
@Composable
private fun Benefit(icon: ImageVector, title: String, detail: String) {
    val c = LgkTheme.colors
    val benefitDescription = stringResource(R.string.upgrade_benefit_description, title, detail)
    Row(
        Modifier.fillMaxWidth().clearAndSetSemantics { contentDescription = benefitDescription },
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Box(
            Modifier.size(40.dp).background(c.accent.copy(alpha = 0.16f), RoundedCornerShape(12.dp)),
            contentAlignment = Alignment.Center,
        ) { Icon(icon, null, tint = c.accentText, modifier = Modifier.size(22.dp)) }
        Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(title, color = c.text, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text(detail, color = c.secondaryText, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun PurchaseBar(state: ProModel.State, onBuy: () -> Unit, onRestore: () -> Unit) {
    val c = LgkTheme.colors
    Box(Modifier.fillMaxWidth().lgkGlass(RectangleShape), contentAlignment = Alignment.TopCenter) {
        Column(
            Modifier.widthIn(max = 520.dp).fillMaxWidth().navigationBarsPadding()
                .padding(start = 24.dp, end = 24.dp, top = 14.dp, bottom = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            if (state.isPro) {
                Row(
                    Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("upgrade-active"),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(Icons.Filled.Verified, null, tint = c.success, modifier = Modifier.padding(end = 8.dp))
                    Text(stringResource(UpgradeCopy.ACTIVE), color = c.success, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                }
            } else {
                val label = UpgradeCopy.buyLabel(state.price, rememberTxt())
                Button(
                    onBuy,
                    enabled = !state.busy && state.canBuy,
                    colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
                    modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp).testTag("upgrade-buy")
                        .then(if (state.busy) Modifier.semantics { contentDescription = label } else Modifier),
                ) {
                    if (state.busy) {
                        CircularProgressIndicator(color = Color.White, strokeWidth = 2.dp, modifier = Modifier.size(22.dp))
                    } else {
                        Text(label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    }
                }
                Text(stringResource(UpgradeCopy.ONE_TIME), color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
                TextButton(onRestore, enabled = !state.busy, modifier = Modifier.testTag("upgrade-restore")) {
                    Text(stringResource(UpgradeCopy.RESTORE), color = if (state.busy) c.secondaryText else c.accentText)
                }
            }
            state.note?.let {
                Text(
                    stringResource(it.res), color = c.secondaryText, style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center,
                    modifier = Modifier.testTag("upgrade-message"),
                )
            }
        }
    }
}
