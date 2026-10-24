package app.localgatekeys.android.ui.unlock

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.R
import app.localgatekeys.android.unlock.AppLockModel
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.LgkTheme

/** The unlock screen for [model]; [onUnlock] and [onStartFresh] launch the model's suspend calls. */
@Composable
fun UnlockScreen(model: AppLockModel, onUnlock: () -> Unit, onStartFresh: () -> Unit) {
    val state by model.state.collectAsStateWithLifecycle()
    val errorMessage by model.errorMessage.collectAsStateWithLifecycle()
    val offersStartFresh by model.offersStartFresh.collectAsStateWithLifecycle()
    UnlockContent(
        unlocking = state == AppLockModel.State.UNLOCKING,
        errorMessage = errorMessage,
        offersStartFresh = offersStartFresh,
        onUnlock = onUnlock,
        onStartFresh = onStartFresh,
    )
}

/**
 * Port of `ios/App/Unlock/UnlockView.swift`: aurora, brand mark, title, the last error, "Start fresh anyway" when
 * offered (two confirmations), and the Unlock button. Both buttons are disabled while unlocking.
 */
@Composable
fun UnlockContent(
    unlocking: Boolean,
    errorMessage: String?,
    offersStartFresh: Boolean,
    onUnlock: () -> Unit,
    onStartFresh: () -> Unit,
) {
    val colors = LgkTheme.colors
    // "Start fresh anyway": 0 none, 1 first confirmation, 2 second.
    var freshStep by rememberSaveable { mutableIntStateOf(0) }
    Box(Modifier.fillMaxSize()) {
        AuroraBackground()
        Column(
            Modifier.fillMaxSize().systemBarsPadding(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            Spacer(Modifier.weight(1f))
            Image(
                painterResource(R.drawable.brand_mark),
                contentDescription = null,
                modifier = Modifier
                    .size(96.dp)
                    .shadow(16.dp, RoundedCornerShape(22.dp), ambientColor = Color.Black.copy(alpha = 0.25f), spotColor = Color.Black.copy(alpha = 0.25f))
                    .testTag("brandMark"),
            )
            Text("LocalGateKeys", color = colors.text, fontSize = 28.sp, fontWeight = FontWeight.Bold)
            if (errorMessage != null) {
                Text(
                    errorMessage,
                    color = colors.secondaryText,
                    fontSize = 16.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 32.dp),
                )
            }
            if (offersStartFresh) {
                TextButton(onClick = { freshStep = 1 }, enabled = !unlocking) {
                    Text("Start fresh anyway", color = if (unlocking) colors.secondaryText else colors.danger)
                }
            }
            Spacer(Modifier.weight(1f))
            Button(
                onClick = onUnlock,
                enabled = !unlocking,
                colors = ButtonDefaults.buttonColors(containerColor = colors.accent, contentColor = Color.White),
                modifier = Modifier.fillMaxWidth().padding(start = 32.dp, end = 32.dp, bottom = 48.dp),
            ) {
                Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Unlock", modifier = Modifier.padding(vertical = 6.dp))
            }
        }
    }
    if (freshStep == 1) {
        AlertDialog(
            onDismissRequest = { freshStep = 0 },
            text = { Text(AppLockModel.START_FRESH_CONFIRM_1) },
            confirmButton = { TextButton(onClick = { freshStep = 2 }) { Text("Start fresh", color = colors.danger) } },
            dismissButton = { TextButton(onClick = { freshStep = 0 }) { Text("Cancel") } },
        )
    }
    if (freshStep == 2) {
        AlertDialog(
            onDismissRequest = { freshStep = 0 },
            text = { Text(AppLockModel.START_FRESH_CONFIRM_2) },
            confirmButton = {
                TextButton(onClick = {
                    freshStep = 0
                    onStartFresh()
                }) { Text("Start fresh now", color = colors.danger) }
            },
            dismissButton = { TextButton(onClick = { freshStep = 0 }) { Text("Cancel") } },
        )
    }
}
