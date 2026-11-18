package app.localgatekeys.android.ui.unlock

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import app.localgatekeys.android.R
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.ui.theme.LgkTheme

/**
 * "A vault was erased from this phone": shown once, on the first screen after another device removed this phone from
 * sync and it erased itself ([AppSettings.deviceErasedNotice], set before that erase). OK clears the flag for good.
 * [erasures]: the guard's erase count, so an erase while this screen shows brings the notice up.
 */
@Composable
fun DeviceErasedNotice(settings: AppSettings, erasures: Int = 0) {
    // Re-read when an erase on removal ran while this screen was already showing (a locked check).
    var show by remember(erasures) { mutableStateOf(settings.deviceErasedNotice) }
    if (!show) return
    val c = LgkTheme.colors
    AlertDialog(
        onDismissRequest = {},
        title = { Text(stringResource(R.string.app_erased_title)) },
        text = { Text(stringResource(R.string.app_erased_message)) },
        confirmButton = {
            TextButton({ settings.deviceErasedNotice = false; show = false }, modifier = Modifier.testTag("erased-notice-ok")) {
                Text(stringResource(R.string.common_ok), color = c.accentText)
            }
        },
    )
}
