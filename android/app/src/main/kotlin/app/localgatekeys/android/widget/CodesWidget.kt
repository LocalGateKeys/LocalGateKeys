package app.localgatekeys.android.widget

import android.content.Context
import android.content.Intent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.glance.GlanceId
import androidx.glance.GlanceModifier
import androidx.glance.ColorFilter
import androidx.glance.GlanceTheme
import androidx.glance.Image
import androidx.glance.ImageProvider
import androidx.glance.LocalContext
import androidx.glance.action.clickable
import androidx.glance.appwidget.GlanceAppWidget
import androidx.glance.appwidget.SizeMode
import androidx.glance.appwidget.action.actionStartActivity
import androidx.glance.appwidget.appWidgetBackground
import androidx.glance.appwidget.cornerRadius
import androidx.glance.appwidget.provideContent
import androidx.glance.background
import androidx.glance.layout.Alignment
import androidx.glance.layout.Column
import androidx.glance.layout.Row
import androidx.glance.layout.Spacer
import androidx.glance.layout.fillMaxSize
import androidx.glance.layout.fillMaxWidth
import androidx.glance.semantics.contentDescription
import androidx.glance.semantics.semantics
import androidx.glance.layout.height
import androidx.glance.layout.padding
import androidx.glance.layout.size
import androidx.glance.layout.width
import androidx.glance.state.GlanceStateDefinition
import androidx.glance.text.FontFamily
import androidx.glance.text.FontWeight
import androidx.glance.text.Text
import androidx.glance.text.TextAlign
import androidx.glance.text.TextStyle
import app.localgatekeys.android.LgkApp
import app.localgatekeys.android.MainActivity
import app.localgatekeys.android.R

/**
 * The home-screen widget: up to four pinned codes (title and code), "Unlock to show codes" while the vault is locked,
 * or how to pin one when nothing is pinned. Any tap opens the app the way its launcher icon does (an explicit intent to
 * MainActivity; nothing the widget sends changes state, and no other app can use it).
 */
class CodesWidget : GlanceAppWidget() {
    override val sizeMode: SizeMode = SizeMode.Single

    /** No Glance state file: the widget keeps nothing on disk (the codes come from [CodesWidgetUpdates] in memory). */
    override val stateDefinition: GlanceStateDefinition<*>? = null

    override suspend fun provideGlance(context: Context, id: GlanceId) {
        val updates = (context.applicationContext as LgkApp).codesWidget
        updates.prepareForWidget()
        provideContent {
            val state by updates.state.collectAsState()
            GlanceTheme { Content(state) }
        }
    }

    @Composable
    private fun Content(state: CodesWidgetState) {
        val context = appLocaleContext(LocalContext.current)
        val name = context.getString(R.string.widget_codes_name)
        val open = Intent(context, MainActivity::class.java)
            .setAction(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
        val colors = GlanceTheme.colors
        Column(
            GlanceModifier.fillMaxSize().appWidgetBackground().cornerRadius(24.dp).background(colors.widgetBackground)
                .padding(12.dp).clickable(actionStartActivity(open))
                .semantics { contentDescription = name },
        ) {
            Row(GlanceModifier.fillMaxWidth().padding(start = 4.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Image(
                    ImageProvider(R.drawable.ic_tile_code), contentDescription = null,
                    colorFilter = ColorFilter.tint(colors.primary), modifier = GlanceModifier.size(16.dp),
                )
                Spacer(GlanceModifier.width(6.dp))
                Text(
                    name, maxLines = 1,
                    style = TextStyle(color = colors.onSurfaceVariant, fontSize = 13.sp, fontWeight = FontWeight.Medium),
                )
            }
            when (state) {
                is CodesWidgetState.Codes -> state.rows.forEachIndexed { i, row ->
                    if (i > 0) Spacer(GlanceModifier.height(6.dp))
                    Row(
                        GlanceModifier.fillMaxWidth().cornerRadius(16.dp).background(colors.secondaryContainer)
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            row.title, maxLines = 1, modifier = GlanceModifier.defaultWeight(),
                            style = TextStyle(color = colors.onSecondaryContainer, fontSize = 13.sp, fontWeight = FontWeight.Medium),
                        )
                        Spacer(GlanceModifier.width(8.dp))
                        Text(
                            row.code, maxLines = 1,
                            style = TextStyle(
                                color = colors.primary, fontSize = 20.sp, fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                            ),
                        )
                    }
                }
                CodesWidgetState.Locked -> Message(R.drawable.ic_widget_lock, context.getString(R.string.widget_codes_locked))
                CodesWidgetState.LockedImmediately ->
                    Message(R.drawable.ic_widget_lock, context.getString(R.string.widget_codes_locked_immediately))
                CodesWidgetState.Empty -> Message(R.drawable.ic_tile_code, context.getString(R.string.widget_codes_empty))
            }
        }
    }

    /** A locked or empty state: an icon over a short centred message, filling the space under the header. */
    @Composable
    private fun Message(icon: Int, text: String) {
        val colors = GlanceTheme.colors
        Column(
            GlanceModifier.fillMaxSize().cornerRadius(16.dp).background(colors.secondaryContainer).padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally, verticalAlignment = Alignment.CenterVertically,
        ) {
            Image(
                ImageProvider(icon), contentDescription = null,
                colorFilter = ColorFilter.tint(colors.primary), modifier = GlanceModifier.size(28.dp),
            )
            Spacer(GlanceModifier.height(8.dp))
            Text(
                text, maxLines = 3,
                style = TextStyle(color = colors.onSecondaryContainer, fontSize = 13.sp, textAlign = TextAlign.Center),
            )
        }
    }
}
