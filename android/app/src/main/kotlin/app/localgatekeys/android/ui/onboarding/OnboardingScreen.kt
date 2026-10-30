package app.localgatekeys.android.ui.onboarding

import androidx.compose.ui.res.stringResource
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.rememberTxt
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.settings.Onboarding
import app.localgatekeys.android.settings.SetupStep
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface

/**
 * The setup pages (workstream 4): one page per open step, Skip on each, Skip setup on the first. A step whose action
 * opens another screen (Import, Settings, Autofill settings) counts as done and closes the pages; the steps left go to
 * the vault's "Finish setting up" card. [onAction] runs that step's action (the pages are already closed).
 */
@Composable
fun OnboardingScreen(onboarding: Onboarding, onAction: (SetupStep) -> Unit) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    val first = remember(onboarding) { onboarding.firstPage() }
    var step by remember(onboarding) { mutableStateOf(first) }
    val advance: () -> Unit = {
        val next = onboarding.next(step)
        if (next == null) onboarding.closePages() else step = next
    }
    BackHandler { onboarding.closePages() }
    Box(Modifier.fillMaxSize().pointerInput(Unit) { awaitPointerEventScope { while (true) awaitPointerEvent() } }.testTag("onboarding")) {
        GlassBackdropHost(Modifier.fillMaxSize()) { AuroraBackground() }
        Column(
            Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().verticalScroll(rememberScrollState()).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(onboarding.pageCount(step), color = c.secondaryText, style = MaterialTheme.typography.labelLarge, modifier = Modifier.weight(1f))
                if (step == first) {
                    TextButton({ onboarding.closePages() }, Modifier.testTag("onboarding-skip-setup")) {
                        Text(onboarding.skipSetup, color = c.accentText)
                    }
                }
            }
            Spacer(Modifier.heightIn(min = 24.dp))
            Column(Modifier.fillMaxWidth().lgkGroupSurface().padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    step.title(txt), color = c.text, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.semantics { heading() }.testTag("onboarding-title"),
                )
                Text(step.text(txt), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
            }
            Button(
                {
                    onboarding.complete(step)
                    when (step) {
                        SetupStep.CREATE, SetupStep.UNLOCK -> advance()
                        else -> {
                            onboarding.closePages()
                            onAction(step)
                        }
                    }
                },
                colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("onboarding-action"),
            ) { Text(step.action(txt), fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center) }
            if (step != SetupStep.CREATE) {
                TextButton(advance, Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("onboarding-skip")) {
                    Text(onboarding.skip, color = c.accentText)
                }
            }
        }
    }
}

/** "Finish setting up · 3 of 5" at the top of the vault: tap to open the pages again, Hide to put it away. */
@Composable
fun SetupCard(text: String, onOpen: () -> Unit, onHide: () -> Unit) {
    val c = LgkTheme.colors
    Row(
        Modifier.fillMaxWidth().padding(top = 8.dp).lgkGroupSurface().padding(start = 16.dp, end = 4.dp, top = 4.dp, bottom = 4.dp)
            .testTag("setup-card"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        TextButton(onOpen, Modifier.weight(1f).heightIn(min = 48.dp).testTag("setup-card-open")) {
            Text(text, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.fillMaxWidth())
        }
        TextButton(onHide, Modifier.heightIn(min = 48.dp).testTag("setup-card-hide")) { Text(stringResource(R.string.home_hide), color = c.secondaryText) }
    }
}
