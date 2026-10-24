package app.localgatekeys.android.ui.settings

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.backup.BackupText
import app.localgatekeys.android.generator.GeneratorDefaults
import app.localgatekeys.android.generator.GeneratorOptions
import app.localgatekeys.android.generator.GeneratorStrength
import app.localgatekeys.android.pro.ProModel
import app.localgatekeys.android.settings.Acknowledgement
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.Appearance
import app.localgatekeys.android.settings.AutoLockDelay
import app.localgatekeys.android.settings.AutofillStatusModel
import app.localgatekeys.android.settings.ClipboardExpiry
import app.localgatekeys.android.settings.IdleLock
import app.localgatekeys.android.settings.InitialsField
import app.localgatekeys.android.settings.SettingsText
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.ui.generator.StrengthMeter
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.ui.theme.lgkSwitchColors
import app.localgatekeys.android.unlock.LocalActivityMonitor
import app.localgatekeys.android.unlock.VaultEraser
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * What Settings needs from the app (Ruling 1: lambdas for what MainActivity provides). [appearance] applies a new
 * Appearance at once (the setting is saved by the screen). [lockNow], [noteActivity] and [erase] go to the lock model
 * ([erase] runs `eraseAndLock` after the two confirmations); [openUrl] opens the browser.
 */
class SettingsSeams(
    val lockNow: () -> Unit,
    val noteActivity: () -> Unit,
    val appearance: (Appearance) -> Unit,
    val erase: () -> Unit,
    val autofill: AutofillStatusModel,
    val acknowledgements: () -> List<Acknowledgement>,
    val version: String,
    val openUrl: (String) -> Unit,
    /** The fresh unlock before an export; true when the owner confirmed (and the vault is still unlocked). */
    val confirmOwner: suspend () -> Boolean,
) {
    override fun toString(): String = "SettingsSeams(version=$version)"
}

/**
 * Settings, opened from the avatar button (ios/App/Settings/SettingsView.swift): Security, Autofill, Appearance,
 * Password generator, Backup, Sync, Pro, About and Erase. Every choice lives in [AppSettings] (nothing secret).
 * Sync opens the Sync tab, where Leave and Reset live ([onOpenSync]: one implementation of each). [pro] null: no Pro
 * section. Back or Done closes it (the initials are stored then too).
 */
@Composable
fun SettingsScreen(
    settings: AppSettings,
    seams: SettingsSeams,
    sync: SyncCoordinator?,
    pro: ProModel?,
    onUpgrade: () -> Unit,
    onExport: () -> Unit,
    onRestore: () -> Unit,
    onOpenSync: () -> Unit,
    onClose: () -> Unit,
) {
    val c = LgkTheme.colors
    val scope = rememberCoroutineScope()
    val initials = remember { InitialsField(settings) }
    var initialsText by remember { mutableStateOf(initials.text) }
    var ack by remember { mutableStateOf<Acknowledgement?>(null) }
    var showAcks by remember { mutableStateOf(false) }
    var eraseStep by remember { mutableIntStateOf(0) }
    val close: () -> Unit = {
        initials.text = initialsText
        initials.submit()
        onClose()
    }
    // Re-checked whenever the screen resumes (back from system settings after "Open Autofill settings").
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(lifecycle, seams.autofill) {
        val observer = LifecycleEventObserver { _, e -> if (e == Lifecycle.Event.ON_RESUME) scope.launch { seams.autofill.refresh() } }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    val opened = ack
    if (opened != null) {
        LicenceText(opened) { ack = null }
        return
    }
    if (showAcks) {
        Acknowledgements(seams.acknowledgements(), onOpen = { ack = it }, onBack = { showAcks = false })
        return
    }
    BackHandler(onBack = close)
    Page("Settings", "settings", onBack = close, doneLabel = "Done") {
        LazyColumn(
            Modifier.fillMaxSize().testTag("settings-list"),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            item(key = "security") { Security(settings, seams, onLock = { close(); seams.lockNow() }) }
            item(key = "autofill") { Autofill(settings, seams.autofill) }
            item(key = "appearance") {
                Appearance(settings, seams, initialsText, onInitials = { initialsText = it }, onSubmit = {
                    initials.text = initialsText
                    initials.submit()
                    initialsText = initials.text
                })
            }
            item(key = "generator") { Generator(settings) }
            item(key = "backup") {
                Section(BackupText.SECTION, footer = BackupText.FOOTER, tag = "settings-backup") {
                    RowButton(BackupText.EXPORT, "settings-export", divider = false, onClick = onExport)
                    RowButton(BackupText.RESTORE, "settings-restore", onClick = onRestore)
                }
            }
            item(key = "sync") { SyncRow(sync, onOpen = { close(); onOpenSync() }) }
            if (pro != null) item(key = "pro") { ProSection(pro, onUpgrade) }
            item(key = "about") { About(seams, onAcknowledgements = { showAcks = true }) }
            item(key = "erase") {
                Section(null, footer = SettingsText.ERASE_FOOTER, tag = "settings-erase") {
                    RowButton(SettingsText.ERASE_BUTTON, "settings-erase-button", destructive = true, divider = false) { eraseStep = 1 }
                }
            }
        }
    }
    if (eraseStep != 0) {
        AlertDialog(
            onDismissRequest = { eraseStep = 0 },
            text = { Text(if (eraseStep == 1) VaultEraser.CONFIRM_TEXT_1 else VaultEraser.CONFIRM_TEXT_2) },
            confirmButton = {
                TextButton({
                    if (eraseStep == 1) {
                        eraseStep = 2
                    } else {
                        eraseStep = 0
                        close()
                        // Locks first whatever happens; a failure shows on the unlock screen and is retried before unlock.
                        seams.erase()
                    }
                }, modifier = Modifier.testTag("erase-confirm")) {
                    Text(if (eraseStep == 1) "Erase" else SettingsText.ERASE_BUTTON, color = c.danger)
                }
            },
            dismissButton = { TextButton({ eraseStep = 0 }) { Text("Cancel", color = c.accentText) } },
        )
    }
}

@Composable
private fun Security(settings: AppSettings, seams: SettingsSeams, onLock: () -> Unit) {
    var autoLock by remember { mutableStateOf(settings.autoLockDelay) }
    var idle by remember { mutableStateOf(settings.idleLock) }
    var clipboard by remember { mutableStateOf(settings.clipboardExpiry) }
    var conceal by remember { mutableStateOf(settings.concealSecretsInDetail) }
    var codes by remember { mutableStateOf(settings.showCodesRow) }
    Section("Security", tag = "settings-security") {
        Picker("Auto-lock after leaving the app", AutoLockDelay.entries, autoLock, { it.label }, divider = false) {
            settings.autoLockDelay = it; autoLock = it
        }
        Picker("Lock when idle", IdleLock.entries, idle, { it.label }) {
            settings.idleLock = it; idle = it
            seams.noteActivity() // restart the timer with the new time
        }
        Picker("Clear clipboard after", ClipboardExpiry.entries, clipboard, { it.label }) { settings.clipboardExpiry = it; clipboard = it }
        Toggle("Hide passwords until tapped", conceal) { settings.concealSecretsInDetail = it; conceal = it }
        Toggle("Show 2FA codes in the Codes row", codes) { settings.showCodesRow = it; codes = it }
        RowButton("Lock now", "settings-lock-now", onClick = onLock)
    }
}

@Composable
private fun Autofill(settings: AppSettings, model: AutofillStatusModel) {
    val scope = rememberCoroutineScope()
    val enabled by model.enabled.collectAsStateWithLifecycle()
    val error by model.openError.collectAsStateWithLifecycle()
    var copyCode by remember { mutableStateOf(settings.copyCodeOnFill) }
    LaunchedEffect(model) { model.refresh() }
    Section("Autofill", tag = "settings-autofill") {
        Value("Autofill service", AutofillStatusModel.statusText(enabled), divider = false)
        RowButton("Open Autofill settings", "settings-open-autofill") { scope.launch { model.openSettings() } }
        error?.let { Text(it, color = LgkTheme.colors.danger, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(bottom = 8.dp)) }
        Toggle("Copy 2FA code when filling", copyCode) { settings.copyCodeOnFill = it; copyCode = it }
    }
}

@Composable
private fun Appearance(
    settings: AppSettings,
    seams: SettingsSeams,
    initials: String,
    onInitials: (String) -> Unit,
    onSubmit: () -> Unit,
) {
    val c = LgkTheme.colors
    val monitor = LocalActivityMonitor.current
    var appearance by remember { mutableStateOf(settings.appearance) }
    Section("Appearance", tag = "settings-appearance") {
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
            Appearance.entries.forEachIndexed { i, a ->
                SegmentedButton(
                    selected = a == appearance,
                    onClick = { settings.appearance = a; appearance = a; seams.appearance(a) },
                    shape = SegmentedButtonDefaults.itemShape(i, Appearance.entries.size),
                    modifier = Modifier.testTag("appearance-${a.raw}"),
                ) { Text(a.label) }
            }
        }
        HorizontalDivider(thickness = 0.5.dp, color = c.separator)
        // Typed freely; normalised to at most two letters only on Done (or when Settings closes).
        BasicTextField(
            value = initials,
            onValueChange = { monitor?.textChanged(); onInitials(it) },
            textStyle = MaterialTheme.typography.bodyLarge.copy(color = c.text),
            cursorBrush = SolidColor(c.accent),
            singleLine = true,
            keyboardOptions = KeyboardOptions(KeyboardCapitalization.Words, autoCorrectEnabled = false, imeAction = ImeAction.Done),
            keyboardActions = KeyboardActions(onDone = { onSubmit() }),
            modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp).testTag("settings-initials").semantics { contentDescription = "Your initials" },
            decorationBox = { inner ->
                Box {
                    if (initials.isEmpty()) Text("Your initials", color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
                    inner()
                }
            },
        )
    }
}

@Composable
private fun Generator(settings: AppSettings) {
    var options by remember { mutableStateOf(GeneratorDefaults(settings).load()) }
    // The passphrase list's size is read off the main thread (normally already cached by LgkApp's warm-up).
    var level by remember { mutableStateOf<GeneratorStrength.Level?>(null) }
    LaunchedEffect(options) { level = withContext(Dispatchers.IO) { GeneratorStrength.level(options) } }
    Section("Password generator", footer = SettingsText.GENERATOR_FOOTER, tag = "settings-generator") {
        Column(Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("New passwords", color = LgkTheme.colors.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                Text(options.summary, color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.bodyLarge)
            }
            level?.let { StrengthMeter(it, Modifier.padding(top = 6.dp)) }
        }
        RowButton("Reset to defaults", "settings-generator-reset") {
            GeneratorDefaults(settings).reset()
            options = GeneratorOptions()
        }
    }
}

@Composable
private fun SyncRow(sync: SyncCoordinator?, onOpen: () -> Unit) {
    val c = LgkTheme.colors
    val membership = sync?.membership?.collectAsStateWithLifecycle()?.value
    val last = sync?.lastSyncedAt?.collectAsStateWithLifecycle()?.value
    val time = remember { DateFormat.getTimeInstance(DateFormat.SHORT) }
    Section("Sync", tag = "settings-sync") {
        Row(
            Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Button, onClick = onOpen).testTag("settings-sync-row"),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Sync", color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Text(
                SettingsText.syncStatus(membership?.joined == true, last) { time.format(Date(it * 1000)) },
                color = c.secondaryText, style = MaterialTheme.typography.bodyLarge,
            )
            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null, tint = c.secondaryText)
        }
    }
}

@Composable
private fun ProSection(pro: ProModel, onUpgrade: () -> Unit) {
    val state by pro.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    Section("Pro", footer = state.message, tag = "settings-pro") {
        Value("Status", SettingsText.proStatus(state.isPro), divider = false)
        if (!state.isPro) RowButton("Upgrade", "settings-upgrade", onClick = onUpgrade)
        RowButton("Restore purchases", "settings-restore-purchases", enabled = !state.busy) { scope.launch { pro.restore() } }
    }
}

@Composable
private fun About(seams: SettingsSeams, onAcknowledgements: () -> Unit) {
    Section("About", footer = SettingsText.DATA_NOT_COLLECTED, tag = "settings-about") {
        Value("Version", seams.version, divider = false)
        RowButton("Acknowledgements", "settings-acknowledgements", onClick = onAcknowledgements)
        RowButton("Privacy Policy", "settings-privacy") { seams.openUrl(SettingsText.PRIVACY_POLICY_URL) }
        RowButton("Licence Agreement", "settings-licence") { seams.openUrl(SettingsText.LICENCE_AGREEMENT_URL) }
    }
}

@Composable
private fun Acknowledgements(list: List<Acknowledgement>, onOpen: (Acknowledgement) -> Unit, onBack: () -> Unit) {
    BackHandler(onBack = onBack)
    Page("Acknowledgements", "acknowledgements", onBack = onBack, doneLabel = "Back") {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
            Section(null) {
                list.forEachIndexed { i, a ->
                    Row(
                        Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Button) { onOpen(a) },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(a.name, color = LgkTheme.colors.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                        Text(a.licence, color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.bodyLarge)
                    }
                    if (i < list.lastIndex) HorizontalDivider(thickness = 0.5.dp, color = LgkTheme.colors.separator)
                }
            }
        }
    }
}

@Composable
private fun LicenceText(a: Acknowledgement, onBack: () -> Unit) {
    BackHandler(onBack = onBack)
    Page(a.name, "licence-text", onBack = onBack, doneLabel = "Back") {
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
            // Verbatim: the licence's URLs stay plain text, never links.
            Text(
                a.text, color = LgkTheme.colors.text, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                modifier = Modifier.fillMaxWidth().lgkGroupSurface().padding(16.dp),
            )
        }
    }
}

/** A full-screen page over the tabs: aurora, a title bar with [doneLabel], and [content]. Takes every touch. */
@Composable
private fun Page(title: String, tag: String, onBack: () -> Unit, doneLabel: String, content: @Composable () -> Unit) {
    val c = LgkTheme.colors
    Box(Modifier.fillMaxSize().pointerInput(Unit) { awaitPointerEventScope { while (true) awaitPointerEvent() } }.testTag(tag)) {
        GlassBackdropHost(Modifier.fillMaxSize()) { AuroraBackground() }
        Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()) {
            Row(Modifier.fillMaxWidth().height(56.dp).padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Spacer(Modifier.width(72.dp))
                Text(
                    title, color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    textAlign = TextAlign.Center, modifier = Modifier.weight(1f).semantics { heading() },
                )
                TextButton(onBack, modifier = Modifier.width(72.dp).testTag("$tag-done")) {
                    Text(doneLabel, color = c.accentText, fontWeight = FontWeight.SemiBold)
                }
            }
            Box(Modifier.weight(1f).fillMaxWidth()) { content() }
        }
    }
}

@Composable
private fun Section(title: String?, footer: String? = null, tag: String? = null, content: @Composable ColumnScope.() -> Unit) {
    val c = LgkTheme.colors
    Column(Modifier.fillMaxWidth().then(if (tag != null) Modifier.testTag(tag) else Modifier)) {
        if (title != null) {
            Text(
                title, color = c.secondaryText, style = MaterialTheme.typography.labelLarge,
                modifier = Modifier.padding(start = 4.dp, bottom = 6.dp).semantics { heading() },
            )
        }
        Column(Modifier.fillMaxWidth().lgkGroupSurface().padding(horizontal = 16.dp, vertical = 4.dp), content = content)
        if (footer != null) {
            Text(footer, color = c.secondaryText, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 4.dp, end = 4.dp, top = 6.dp))
        }
    }
}

@Composable
private fun Value(label: String, value: String, divider: Boolean = true) {
    val c = LgkTheme.colors
    if (divider) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Text(value, color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun Toggle(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    val c = LgkTheme.colors
    HorizontalDivider(thickness = 0.5.dp, color = c.separator)
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Switch) { onChange(!checked) },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Switch(checked, onCheckedChange = onChange, colors = lgkSwitchColors())
    }
}

@Composable
private fun <T> Picker(label: String, choices: List<T>, selected: T, text: (T) -> String, divider: Boolean = true, onPick: (T) -> Unit) {
    val c = LgkTheme.colors
    var open by remember { mutableStateOf(false) }
    if (divider) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
    Box {
        Row(
            Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.DropdownList) { open = true }
                .semantics { contentDescription = "$label: ${text(selected)}" },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Text(text(selected), color = c.accentText, style = MaterialTheme.typography.bodyLarge)
        }
        DropdownMenu(open, onDismissRequest = { open = false }) {
            for (choice in choices) {
                DropdownMenuItem(text = { Text(text(choice)) }, onClick = { open = false; onPick(choice) })
            }
        }
    }
}

/** A button drawn as a list row (the iPhone's List button): full width, a hairline above unless [divider] is false. */
@Composable
internal fun RowButton(
    label: String,
    tag: String,
    enabled: Boolean = true,
    destructive: Boolean = false,
    divider: Boolean = true,
    onClick: () -> Unit,
) {
    val c = LgkTheme.colors
    Column(Modifier.fillMaxWidth()) {
        if (divider) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
        Box(
            Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(enabled = enabled, role = Role.Button, onClick = onClick).testTag(tag),
            contentAlignment = Alignment.CenterStart,
        ) {
            Text(
                label,
                color = when {
                    !enabled -> c.secondaryText
                    destructive -> c.danger
                    else -> c.accentText
                },
                style = MaterialTheme.typography.bodyLarge,
            )
        }
    }
}
