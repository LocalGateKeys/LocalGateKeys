package app.localgatekeys.android.autofill

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.R

/** The site prompts that must be answered before a save or fill goes on ([SiteCheck]). */
internal fun SitePrompt.needsAnswer(): Boolean = this is SitePrompt.Guard || this is SitePrompt.SameAccount || this is SitePrompt.Mismatch ||
    this is SitePrompt.UnverifiedApp

/** The save sheet's site line: verified or related (accent), new (plain), lookalike the person continued on (error). */
@Composable
internal fun SiteVerdictLine(site: SitePrompt) {
    val (text, color) = when (site) {
        SitePrompt.Verified -> stringResource(R.string.autofill_site_verified) to MaterialTheme.colorScheme.primary
        SitePrompt.Related, is SitePrompt.SameAccount -> stringResource(R.string.autofill_site_related) to MaterialTheme.colorScheme.primary
        SitePrompt.New -> stringResource(R.string.autofill_site_new) to MaterialTheme.colorScheme.onSurfaceVariant
        is SitePrompt.Guard, is SitePrompt.Mismatch, is SitePrompt.UnverifiedApp -> stringResource(R.string.autofill_site_lookalike) to MaterialTheme.colorScheme.error
    }
    Text(text, color = color, style = MaterialTheme.typography.labelLarge, modifier = Modifier.testTag("save-site-verdict"))
}

/**
 * "Is this the right site?" (or the softer "same account" question), shared by the save sheet, the fill sheet (a login
 * picked by hand) and the Credential Manager save. "Go back" is the main button and saves or fills nothing.
 */
@Composable
internal fun LookalikeGuard(site: SitePrompt, onGoBack: () -> Unit, onContinue: () -> Unit) {
    Column(Modifier.fillMaxWidth().safeDrawingPadding().padding(20.dp).testTag("save-lookalike-guard"), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        when (site) {
            is SitePrompt.SameAccount -> {
                Text(stringResource(R.string.autofill_same_account_title, site.savedHost), style = MaterialTheme.typography.titleLarge)
                Text(stringResource(R.string.autofill_same_account_body, site.host, site.savedHost), style = MaterialTheme.typography.bodyMedium)
            }
            is SitePrompt.Guard -> {
                Text(stringResource(R.string.autofill_guard_title), style = MaterialTheme.typography.titleLarge)
                val saved = site.savedHost
                Text(
                    if (saved != null) stringResource(R.string.autofill_guard_body, site.host, saved) else stringResource(R.string.autofill_guard_body_mixed, site.host),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            is SitePrompt.Mismatch -> {
                Text(stringResource(R.string.autofill_guard_title), style = MaterialTheme.typography.titleLarge)
                val saved = site.savedHost
                if (site.otherSite) {
                    Text(
                        if (saved != null) stringResource(R.string.autofill_pick_other_site_body, site.host, saved) else stringResource(R.string.autofill_pick_no_site_body, site.host),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                if (!site.schemeKnown) {
                    Text(stringResource(R.string.autofill_pick_scheme_unknown_body, site.host), style = MaterialTheme.typography.bodyMedium)
                }
            }
            is SitePrompt.UnverifiedApp -> {
                Text(stringResource(R.string.autofill_app_unverified_title), style = MaterialTheme.typography.titleLarge)
                val saved = site.savedHost
                Text(
                    if (saved != null) stringResource(R.string.autofill_app_unverified_body, site.packageName, saved)
                    else stringResource(R.string.autofill_app_unverified_no_site_body, site.packageName),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            else -> return@Column
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = onGoBack, modifier = Modifier.testTag("save-guard-go-back")) { Text(stringResource(R.string.autofill_guard_go_back)) }
            TextButton(onClick = onContinue, modifier = Modifier.testTag("save-guard-continue")) {
                Text(
                    when (site) {
                        is SitePrompt.SameAccount -> stringResource(R.string.autofill_same_account_yes)
                        is SitePrompt.Guard -> stringResource(R.string.autofill_guard_continue, site.host)
                        is SitePrompt.Mismatch -> stringResource(R.string.autofill_guard_continue, site.host)
                        is SitePrompt.UnverifiedApp -> stringResource(R.string.autofill_app_fill_continue, site.packageName)
                        else -> ""
                    },
                )
            }
        }
    }
}
