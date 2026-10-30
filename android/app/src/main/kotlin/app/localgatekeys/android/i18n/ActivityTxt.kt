package app.localgatekeys.android.i18n

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext

/**
 * The [Txt] for UI code: built from the current Activity's resources (Compose's `LocalContext`), never the Application's,
 * so it follows the per-app language chosen in Settings. It is rebuilt when the configuration (locale) changes.
 */
@Composable
fun rememberTxt(): Txt {
    val context = LocalContext.current
    val configuration = LocalConfiguration.current
    return remember(context, configuration) { AndroidTxt(context.resources) }
}

/**
 * A [Txt] for process-wide models built once in the Application ([app.localgatekeys.android.LgkApp]): it forwards to the
 * Activity-resource [Txt] the running Activity attaches with [use] (Ruling B: not Application resources).
 */
class SwitchableTxt(@Volatile private var current: Txt) : Txt {
    fun use(txt: Txt) { current = txt }
    override fun s(id: Int, vararg args: Any): String = current.s(id, *args)
    override fun plural(id: Int, count: Int, vararg args: Any): String = current.plural(id, count, *args)
}
