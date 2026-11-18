package app.localgatekeys.android.widget

import android.content.Context
import android.content.Intent
import androidx.glance.appwidget.GlanceAppWidget
import androidx.glance.appwidget.GlanceAppWidgetReceiver
import app.localgatekeys.android.LgkApp
import kotlinx.coroutines.launch

/** The codes widget's provider. Not exported: only the system's widget host and the app's own alarm reach it. */
class CodesWidgetReceiver : GlanceAppWidgetReceiver() {
    override val glanceAppWidget: GlanceAppWidget = CodesWidget()

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != CodesWidgetAlarm.ACTION_REFRESH) {
            super.onReceive(context, intent)
            return
        }
        val app = context.applicationContext as? LgkApp ?: return
        val pending = goAsync()
        app.appScope.launch {
            try {
                app.codesWidget.refresh()
            } finally {
                pending.finish()
            }
        }
    }
}
