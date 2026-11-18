package app.localgatekeys.android.ui.security

import android.content.Context
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.BuildConfig
import app.localgatekeys.android.R
import app.localgatekeys.android.backup.RestoreTest
import app.localgatekeys.core.backup.ComputerBackup
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.security.HealthReport
import app.localgatekeys.android.settings.AppPasswordSeams
import app.localgatekeys.android.settings.FactorSeams
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.ui.theme.lgkSwitchColors
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Where the last restore test result (no secret, no title) and the weekly setting are kept. */
object RestoreTestPrefs {
    private const val FILE = "lgk_restore_test"
    private const val LAST = "last"
    private const val WEEKLY = "weekly"

    private fun prefs(context: Context) = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
    fun last(context: Context): RestoreTest.Result? = RestoreTest.decode(prefs(context).getString(LAST, null))
    fun save(context: Context, r: RestoreTest.Result) = prefs(context).edit().putString(LAST, RestoreTest.encode(r)).apply()
    fun weekly(context: Context): Boolean = prefs(context).getBoolean(WEEKLY, true)
    fun setWeekly(context: Context, on: Boolean) = prefs(context).edit().putBoolean(WEEKLY, on).apply()

    /** Scratch folders live under the app's private data dir and are deleted after each test. */
    fun scratchRoot(context: Context) = File(context.noBackupFilesDir, "restore-test")
}

/**
 * Security > Backup checks (sub-plan 12): the last restore test row, "Test backup restore now" (pick a backup and type
 * its password; the password lives only in this dialog's state and is cleared after the run), the weekly setting with
 * its due hint, and "Print vault health report".
 */
@Composable
fun BackupChecksSection(
    modifier: Modifier = Modifier,
    appPassword: AppPasswordSeams? = null,
    factors: FactorSeams? = null,
    onPickerOpen: () -> Unit = {},
    onPickerClose: () -> Boolean = { true },
) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var last by remember { mutableStateOf(RestoreTestPrefs.last(context)) }
    var weekly by remember { mutableStateOf(RestoreTestPrefs.weekly(context)) }
    var picked by remember { mutableStateOf<Uri?>(null) }
    var password by remember { mutableStateOf("") }
    var masterPassword by remember { mutableStateOf("") }
    // The picked file is a computer's full backup (.lgk/.lgkfull): the dialog also asks for its master password.
    var pickedIsComputer by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    val now = System.currentTimeMillis() / 1000
    // Ruling 21, as Export backup: the system file picker must not trip the "Immediately" auto-lock. A result that
    // arrives after the vault locked anyway is dropped.
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val stillUnlocked = onPickerClose()
        if (uri != null && stillUnlocked) {
            scope.launch {
                pickedIsComputer = withContext(Dispatchers.IO) {
                    try {
                        context.contentResolver.openInputStream(uri)?.use { s ->
                            val head = ByteArray(2)
                            ComputerBackup.looksLikeComputerBackup(head.copyOf(maxOf(0, s.read(head))))
                        } ?: false
                    } catch (e: Exception) { false }
                }
                picked = uri
            }
        }
    }

    Column(modifier.padding(top = 16.dp)) {
        Text(
            stringResource(R.string.restore_test_header), color = c.secondaryText, style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.padding(bottom = 8.dp).semantics { heading() },
        )
        Column(Modifier.fillMaxWidth().lgkGroupSurface().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(RestoreTest.rowText(last, now, txt), color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.testTag("restore-test-row"))
            if (RestoreTest.due(last, now, weekly)) {
                Text(stringResource(R.string.restore_test_due), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("restore-test-due"))
            }
            message?.let { Text(it, color = c.secondaryText, style = MaterialTheme.typography.bodyMedium) }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.restore_test_weekly), color = c.text, modifier = Modifier.weight(1f))
                Switch(weekly, { on -> weekly = on; RestoreTestPrefs.setWeekly(context, on) }, colors = lgkSwitchColors(), modifier = Modifier.testTag("restore-test-weekly"))
            }
            TextButton(onClick = {
                if (!busy) {
                    onPickerOpen()
                    picker.launch(arrayOf("*/*"))
                }
            }, modifier = Modifier.testTag("restore-test-run")) {
                Text(stringResource(R.string.restore_test_run), color = c.accentText)
            }
            TextButton(
                onClick = {
                    scope.launch {
                        val pwOn = appPassword?.isOn?.invoke()
                        val factorText = if (pwOn == null) {
                            null
                        } else {
                            val f = if (pwOn) factors?.state?.invoke() else null
                            HealthReport.factorsText(
                                appPasswordOn = pwOn,
                                biometric = pwOn && appPassword?.biometricOn?.invoke() == true,
                                keyFile = f?.keyFile == true,
                                yubiKey = f?.yubiKeySlot != null,
                                t = txt,
                            )
                        }
                        val facts = HealthReport.Facts(
                            generatedAt = System.currentTimeMillis() / 1000,
                            factors = factorText,
                            restoreTest = RestoreTest.valueText(last, System.currentTimeMillis() / 1000, txt),
                            build = "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})",
                        )
                        HealthReportPrint.print(context, txt, facts)
                    }
                },
                modifier = Modifier.testTag("health-report-print"),
            ) { Text(stringResource(R.string.health_report_print), color = c.accentText) }
        }
    }

    val uri = picked
    if (uri != null) {
        fun close() { picked = null; password = ""; masterPassword = ""; pickedIsComputer = false }
        AlertDialog(
            onDismissRequest = { if (!busy) close() },
            title = { Text(stringResource(R.string.restore_test_run)) },
            text = {
                Column {
                    if (pickedIsComputer) {
                        Text(stringResource(R.string.restore_test_computer_hint), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(bottom = 8.dp))
                    }
                    OutlinedTextField(
                        password, { password = it }, label = { Text(stringResource(R.string.restore_test_password)) }, singleLine = true,
                        visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        modifier = Modifier.testTag("restore-test-password"),
                    )
                    if (pickedIsComputer) {
                        OutlinedTextField(
                            masterPassword, { masterPassword = it }, label = { Text(stringResource(R.string.restore_test_master_password)) },
                            singleLine = true, visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                            modifier = Modifier.padding(top = 8.dp).testTag("restore-test-master-password"),
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(enabled = !busy && password.isNotEmpty() && (!pickedIsComputer || masterPassword.isNotEmpty()), onClick = {
                    val pw = password
                    val master = masterPassword
                    password = ""
                    masterPassword = ""
                    busy = true
                    scope.launch {
                        val result = withContext(Dispatchers.IO) {
                            val bytes = try { context.contentResolver.openInputStream(uri)?.use { it.readBytes() } } catch (e: Exception) { null }
                            RestoreTest.run(uri.lastPathSegment ?: "", bytes, pw, RestoreTestPrefs.scratchRoot(context), System.currentTimeMillis() / 1000,
                                masterPassword = master)
                        }
                        RestoreTestPrefs.save(context, result)
                        last = result
                        message = if (result.ok) txt.plural(R.plurals.restore_test_items, result.items, result.items) else null
                        busy = false
                        close()
                    }
                }) { Text(stringResource(R.string.restore_test_start)) }
            },
            dismissButton = { TextButton(enabled = !busy, onClick = { close() }) { Text(stringResource(R.string.restore_test_cancel)) } },
        )
    }
}
