package app.localgatekeys.android.ui.settings

import app.localgatekeys.android.i18n.rememberTxt
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
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowLeft
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.outlined.Brush
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Password
import androidx.compose.material.icons.outlined.PrivacyTip
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material3.IconButton
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.graphics.vector.ImageVector
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
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.reminders.ReminderPrefs
import app.localgatekeys.android.settings.FactorSeams
import app.localgatekeys.android.reminders.Reminders
import app.localgatekeys.android.security.SecurityPrefs
import app.localgatekeys.android.ui.reminders.ReminderSettingsSection
import app.localgatekeys.android.ui.shell.Overlay
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.R
import app.localgatekeys.android.backup.BackupText
import app.localgatekeys.android.i18n.LanguageOptions
import app.localgatekeys.android.importing.ImportText
import app.localgatekeys.android.generator.GeneratorDefaults
import app.localgatekeys.android.generator.GeneratorOptions
import app.localgatekeys.android.generator.GeneratorStrength
import app.localgatekeys.android.pro.ProModel
import app.localgatekeys.android.settings.Acknowledgement
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.AppPasswordSeams
import app.localgatekeys.android.settings.Onboarding
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
    /** Task 7: the optional app password; null hides the section (tests). */
    val appPassword: AppPasswordSeams? = null,
    /** Task 9: copies the licence key (through the secret clipboard). */
    val copyKey: (String) -> Unit = {},
    /** KeePass unlocking Task 9: the app password's key file and YubiKey; null hides the section (tests). */
    val factors: FactorSeams? = null,
    /** The same owner check with the prompt's own title (the CXF export names what it releases). */
    val confirmOwnerFor: suspend (String) -> Boolean = { confirmOwner() },
    /** Sub-plan 08: the duress password (a second app password); null hides the section (tests). */
    val duress: app.localgatekeys.android.duress.DuressSeams? = null,
    /** Sub-plan 08: emergency access; null hides the row (tests). */
    val emergency: app.localgatekeys.android.ui.recovery.EmergencySeams? = null,
) {
    override fun toString(): String = "SettingsSeams(version=$version)"
}

/**
 * The Settings tab (ios/App/Settings/SettingsView.swift): a list of categories (Lock & security, Privacy, Autofill,
 * Sync & data, Password generator, Appearance; then About), under the Pro section; each opens its sections in the same list, with Back.
 * Settings whose effect is not obvious from the name carry an ⓘ button ([InfoButton]). The sections, in the iPhone's order: Security, App password, Breach checks,
 * Reminders, Autofill, Appearance, Password generator, Sync, then Android's data pages (Backup, Import, Receive a shared
 * item, Recently deleted), Pro, Show setup again, About and Erase. Every choice lives in [AppSettings] (nothing secret).
 * Sync opens the Sync tab, where Leave and Reset live ([onOpenSync]: one implementation of each). [pro] null: no Pro
 * section; [security] null: no Breach checks; [reminders] null: no Reminders; [onRecentlyDeleted] null: no row. The
 * initials typed are stored on Done and when the tab goes away. Its own pages (acknowledgements, app password set-up)
 * cover the header and the tab bar through the shell's overlay.
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
    onImport: (() -> Unit)? = null,
    /** Export to a CXF file (sub-plan 03). Null: no row. */
    onExportCxf: (() -> Unit)? = null,
    /** UX workstream 9: Receive a shared item (a .lgkshare file or its QR). Null: no row. */
    onReceiveShare: (() -> Unit)? = null,
    onShowSetup: (() -> Unit)? = null,
    /** Workstream 2: the Security tab's breach-check switches. */
    security: SecurityPrefs? = null,
    /** Workstream 10: "Show item names in notifications" (and the reminders to re-plan when it changes). */
    reminders: ReminderSettings? = null,
    /** Workstream 3: Recently deleted. */
    onRecentlyDeleted: (() -> Unit)? = null,
    /** Opens the generator sheet (the value is copied). Null: no row. */
    onGenerate: (() -> Unit)? = null,
    /** True while that sheet is up; its closing reloads the options summary. */
    generatorOpen: Boolean = false,
    /** Feature pack 2026-11-15 rows (label, test tag, action): Travel mode, Clean up, Privacy proof, Passkey doctor. */
    featureRows: List<Triple<String, String, () -> Unit>> = emptyList(),
    /** Room under the last section (the floating tab bar's clearance in the tab). */
    bottomPadding: Dp = 32.dp,
) {
    val c = LgkTheme.colors
    val txt = rememberTxt()
    val backupText = BackupText(txt)
    val settingsText = SettingsText(txt)
    val scope = rememberCoroutineScope()
    val initials = remember { InitialsField(settings) }
    var initialsText by remember { mutableStateOf(initials.text) }
    var ack by remember { mutableStateOf<Acknowledgement?>(null) }
    var showAcks by remember { mutableStateOf(false) }
    var eraseStep by remember { mutableIntStateOf(0) }
    var appPasswordSetup by remember { mutableStateOf(false) }
    var showEmergency by remember { mutableStateOf(false) }
    var appPasswordRefresh by remember { mutableIntStateOf(0) }
    // The category page open (null: the category list), kept across rotation.
    var categoryName by rememberSaveable { mutableStateOf<String?>(null) }
    val category = categoryName?.let { SettingsCategory.valueOf(it) }
    if (category != null) BackHandler { categoryName = null }
    val autofillOn by seams.autofill.enabled.collectAsStateWithLifecycle()
    // The initials are stored when the tab goes away (another tab, a page over it, a lock), as the iPhone's onDisappear.
    val latestInitials by rememberUpdatedState(initialsText)
    DisposableEffect(initials) {
        onDispose {
            initials.text = latestInitials
            initials.submit()
        }
    }
    // Re-checked whenever the screen resumes (back from system settings after "Open Autofill settings").
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(lifecycle, seams.autofill) {
        val observer = LifecycleEventObserver { _, e -> if (e == Lifecycle.Event.ON_RESUME) scope.launch { seams.autofill.refresh() } }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    val opened = ack
    val appPassword = seams.appPassword
    // A YubiKey asked for by a Settings change (app password or factors) shows its touch dialog over the list.
    seams.factors?.let { YubiKeyTouchDialog(it) }
    when {
        opened != null -> Overlay { LicenceText(opened) { ack = null } }
        appPasswordSetup && appPassword != null -> Overlay {
            AppPasswordSetup(appPassword, onDone = { appPasswordSetup = false; appPasswordRefresh++ })
        }
        showAcks -> Overlay { Acknowledgements(seams.acknowledgements(), onOpen = { ack = it }, onBack = { showAcks = false }) }
        showEmergency && seams.emergency != null -> Overlay {
            app.localgatekeys.android.ui.recovery.EmergencyAccessPage(seams.emergency, onBack = { showEmergency = false })
        }
    }
    LazyColumn(
        Modifier.fillMaxSize().testTag("settings-list"),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = bottomPadding),
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        if (category == null) {
            // Pro stays on the main list, outside the categories, with Upgrade one tap away.
            if (pro != null) item(key = "pro") { ProSection(pro, onUpgrade, seams.copyKey) }
            for (group in 0..1) {
                item(key = "categories-$group") {
                    Section(null, tag = "settings-categories-$group") {
                        SettingsCategory.entries.filter { it.group == group }.forEachIndexed { i, cat ->
                            CategoryRow(cat, badge = cat == SettingsCategory.AUTOFILL && autofillOn == false, divider = i > 0) {
                                categoryName = cat.name
                            }
                        }
                    }
                }
            }
        } else {
            item(key = "category-header") { CategoryHeader(stringResource(category.title)) { categoryName = null } }
        }
        val inSecurity = category == SettingsCategory.LOCK
        val inPrivacy = category == SettingsCategory.PRIVACY
        val inSync = category == SettingsCategory.SYNC
        if (inSecurity) item(key = "security") { Security(settings, seams, onLock = { seams.lockNow() }) }
        if (inSecurity && appPassword != null) {
            item(key = "app-password") { AppPasswordSection(appPassword, appPasswordRefresh, onSetup = { appPasswordSetup = true }, onTurnedOff = { appPasswordRefresh++ }) }
        }
        val factors = seams.factors
        if (inSecurity && factors != null) item(key = "factors") { FactorSection(factors, appPasswordRefresh) }
        if (inSecurity) seams.duress?.let { d -> item(key = "duress") { DuressSection(d, appPasswordRefresh) } }
        if (inPrivacy) item(key = "privacy") { PrivacyOptions(settings) }
        if (inPrivacy && security != null) item(key = "breach-checks") { BreachChecks(security) }
        if (inPrivacy && reminders != null) item(key = "reminders") { ReminderSettingsSection(reminders.prefs, reminders.reminders) }
        if (category == SettingsCategory.AUTOFILL) item(key = "autofill") { Autofill(settings, seams.autofill) }
        if (category == SettingsCategory.APPEARANCE) item(key = "appearance") {
            Appearance(settings, seams, initialsText, onInitials = { initialsText = it }, onSubmit = {
                initials.text = initialsText
                initials.submit()
                initialsText = initials.text
            })
        }
        if (category == SettingsCategory.GENERATOR) item(key = "generator") { Generator(settings, onGenerate, generatorOpen) }
        if (inSync) item(key = "sync") { SyncRow(settings, sync, onOpen = onOpenSync) }
        if (inSecurity && seams.emergency != null) {
            item(key = "emergency") {
                Section(null, footer = stringResource(R.string.heir_settings_footer), tag = "settings-emergency") {
                    NavRow(stringResource(R.string.heir_title), "settings-emergency-row") { showEmergency = true }
                }
            }
        }
        if (inSync) item(key = "backup") {
            Section(backupText.section, footer = backupText.footer, tag = "settings-backup") {
                RowButton(backupText.export, "settings-export", divider = false, onClick = onExport)
                RowButton(backupText.restore, "settings-restore", onClick = onRestore)
            }
        }
        if (inSync && onImport != null) {
            item(key = "import") {
                Section(txt.s(ImportText.SECTION), footer = txt.s(ImportText.FOOTER), tag = "settings-import") {
                    RowButton(txt.s(ImportText.BUTTON), "settings-import-file", divider = false, onClick = onImport)
                }
            }
        }
        if (inSync && onExportCxf != null) {
            item(key = "export-cxf") {
                Section(stringResource(R.string.cxf_export_section), footer = stringResource(R.string.cxf_export_footer), tag = "settings-export-cxf") {
                    RowButton(stringResource(R.string.cxf_export_button), "settings-export-cxf-file", divider = false, onClick = onExportCxf)
                }
            }
        }
        if (inSync && onReceiveShare != null) {
            item(key = "receive-share") {
                Section(
                    txt.s(app.localgatekeys.android.share.ShareText.RECEIVE),
                    footer = txt.s(app.localgatekeys.android.share.ShareText.RECEIVE_FOOTER), tag = "settings-receive-share",
                ) {
                    RowButton(txt.s(app.localgatekeys.android.share.ShareText.RECEIVE), "settings-receive", divider = false, onClick = onReceiveShare)
                }
            }
        }
        if (inSync && onRecentlyDeleted != null) {
            item(key = "recently-deleted") {
                Section(null, tag = "settings-trash") {
                    NavRow(stringResource(R.string.trash_title), "settings-recently-deleted", onClick = onRecentlyDeleted)
                }
            }
        }
        if (inSync && featureRows.isNotEmpty()) {
            item(key = "feature-pack") {
                Section(null, tag = "settings-feature-pack") {
                    featureRows.forEachIndexed { i, (label, tag, action) ->
                        RowButton(label, tag, divider = i < featureRows.lastIndex, onClick = action)
                    }
                }
            }
        }
        if (category == SettingsCategory.ABOUT && onShowSetup != null) {
            item(key = "setup") {
                Section(null, tag = "settings-setup") {
                    RowButton(stringResource(R.string.onboarding_show_again), "settings-show-setup", divider = false, onClick = onShowSetup)
                }
            }
        }
        if (category == SettingsCategory.ABOUT) item(key = "about") { About(seams, onAcknowledgements = { showAcks = true }) }
        if (inSync) item(key = "erase") {
            Section(null, footer = settingsText.eraseFooter, tag = "settings-erase") {
                RowButton(settingsText.eraseButton, "settings-erase-button", destructive = true, divider = false) { eraseStep = 1 }
            }
        }
    }
    if (eraseStep != 0) {
        AlertDialog(
            onDismissRequest = { eraseStep = 0 },
            text = { Text(if (eraseStep == 1) txt.s(VaultEraser.CONFIRM_TEXT_1) else txt.s(VaultEraser.CONFIRM_TEXT_2)) },
            confirmButton = {
                TextButton({
                    if (eraseStep == 1) {
                        eraseStep = 2
                    } else {
                        eraseStep = 0
                        // Locks first whatever happens; a failure shows on the unlock screen and is retried before unlock.
                        seams.erase()
                    }
                }, modifier = Modifier.testTag("erase-confirm")) {
                    Text(if (eraseStep == 1) stringResource(R.string.settings_erase_confirm) else settingsText.eraseButton, color = c.danger)
                }
            },
            dismissButton = { TextButton({ eraseStep = 0 }) { Text(stringResource(R.string.common_cancel), color = c.accentText) } },
        )
    }
}

/** Settings' top-level categories, in the list's order (the iPhone's category rows). */
internal enum class SettingsCategory(val title: Int, val icon: ImageVector, val group: Int = 0) {
    LOCK(R.string.settings_category_lock, Icons.Outlined.Lock),
    PRIVACY(R.string.settings_category_privacy, Icons.Outlined.PrivacyTip),
    AUTOFILL(R.string.settings_section_autofill, Icons.Outlined.CheckCircle),
    SYNC(R.string.settings_category_sync, Icons.Outlined.Sync),
    GENERATOR(R.string.settings_section_generator, Icons.Outlined.Password),
    APPEARANCE(R.string.settings_section_appearance, Icons.Outlined.Brush),
    ABOUT(R.string.settings_section_about, Icons.Outlined.Info, group = 1),
}

/** A category row: icon, title, an attention mark when [badge], chevron. */
@Composable
private fun CategoryRow(cat: SettingsCategory, badge: Boolean, divider: Boolean, onClick: () -> Unit) {
    val c = LgkTheme.colors
    if (divider) HorizontalDivider(thickness = 0.5.dp, color = c.separator, modifier = Modifier.padding(start = 40.dp))
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).clickable(role = Role.Button, onClick = onClick)
            .testTag("settings-category-${cat.name.lowercase()}"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(cat.icon, null, tint = c.secondaryText, modifier = Modifier.width(28.dp))
        Spacer(Modifier.width(12.dp))
        Text(stringResource(cat.title), color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        if (badge) Icon(Icons.Filled.Error, stringResource(R.string.settings_needs_attention), tint = c.danger)
        Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null, tint = c.secondaryText)
    }
}

/** The title row over a category's sections, with Back (system Back works too). */
@Composable
private fun CategoryHeader(title: String, onBack: () -> Unit) {
    val c = LgkTheme.colors
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        TextButton(onBack, modifier = Modifier.testTag("settings-category-back")) {
            Icon(Icons.AutoMirrored.Filled.KeyboardArrowLeft, null, tint = c.accentText)
            Text(stringResource(R.string.common_back), color = c.accentText)
        }
        Text(
            title, color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
            modifier = Modifier.semantics { heading() },
        )
    }
}

/** The reminders' one setting and the planner to re-plan when it changes (Task 4's [ReminderSettingsSection]). */
class ReminderSettings(val prefs: ReminderPrefs, val reminders: Reminders?)

/** Breach checks (workstream 2): off by default, and blocked while strict offline mode is on (the iPhone's section). */
@Composable
private fun BreachChecks(prefs: SecurityPrefs) {
    var strict by remember { mutableStateOf(prefs.strictOfflineMode) }
    var allowed by remember { mutableStateOf(prefs.breachCheckEnabled) }
    Section(
        stringResource(R.string.settings_breach_title),
        footer = stringResource(R.string.settings_breach_footer, stringResource(R.string.security_consent)),
        tag = "settings-breach-checks",
    ) {
        Toggle(stringResource(R.string.settings_strict_offline), strict, divider = false, tag = "settings-strict-offline",
            info = stringResource(R.string.settings_info_strict_offline)) {
            prefs.strictOfflineMode = it; strict = it
        }
        Toggle(stringResource(R.string.settings_allow_breach), allowed, enabled = !strict, tag = "settings-allow-breach",
            info = stringResource(R.string.security_consent)) {
            prefs.breachCheckEnabled = it; allowed = it
        }
    }
}

@Composable
private fun Security(settings: AppSettings, seams: SettingsSeams, onLock: () -> Unit) {
    var autoLock by remember { mutableStateOf(settings.autoLockDelay) }
    val txt = rememberTxt()
    var idle by remember { mutableStateOf(settings.idleLock) }
    var clipboard by remember { mutableStateOf(settings.clipboardExpiry) }
    Section(stringResource(R.string.settings_section_lock), tag = "settings-security") {
        Picker(stringResource(R.string.settings_autolock_picker), AutoLockDelay.entries, autoLock, { it.label(txt) }, divider = false,
            info = stringResource(R.string.settings_info_autolock)) {
            settings.autoLockDelay = it; autoLock = it
        }
        Picker(stringResource(R.string.settings_idle_picker), IdleLock.entries, idle, { it.label(txt) }, info = stringResource(R.string.settings_info_idle)) {
            settings.idleLock = it; idle = it
            seams.noteActivity() // restart the timer with the new time
        }
        Picker(stringResource(R.string.settings_clipboard_picker), ClipboardExpiry.entries, clipboard, { it.label(txt) },
            info = stringResource(R.string.settings_info_clipboard)) { settings.clipboardExpiry = it; clipboard = it }
        RowButton(stringResource(R.string.settings_lock_now), "settings-lock-now", onClick = onLock)
    }
}

/** What shows on screen (the iPhone's Privacy section). */
@Composable
private fun PrivacyOptions(settings: AppSettings) {
    var conceal by remember { mutableStateOf(settings.concealSecretsInDetail) }
    Section(stringResource(R.string.settings_category_privacy), tag = "settings-privacy-options") {
        Toggle(stringResource(R.string.settings_conceal), conceal, divider = false, info = stringResource(R.string.settings_info_conceal)) {
            settings.concealSecretsInDetail = it; conceal = it
        }
    }
}

@Composable
private fun Autofill(settings: AppSettings, model: AutofillStatusModel) {
    val scope = rememberCoroutineScope()
    val txt = rememberTxt()
    val enabled by model.enabled.collectAsStateWithLifecycle()
    val error by model.openError.collectAsStateWithLifecycle()
    var copyCode by remember { mutableStateOf(settings.copyCodeOnFill) }
    var suggestions by remember { mutableStateOf(settings.autofillSuggestions) }
    var keyboard by remember { mutableStateOf(settings.autofillInline) }
    var passkeys by remember { mutableStateOf(settings.passkeyProvider) }
    LaunchedEffect(model) { model.refresh() }
    Section(stringResource(R.string.settings_section_autofill), tag = "settings-autofill") {
        Value(stringResource(R.string.settings_autofill_service), model.statusText(enabled), divider = false,
            info = stringResource(R.string.settings_info_autofill_service))
        RowButton(stringResource(R.string.settings_open_autofill), "settings-open-autofill") { scope.launch { model.openSettings() } }
        error?.let { Text(it, color = LgkTheme.colors.danger, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(bottom = 8.dp)) }
        Toggle(stringResource(R.string.settings_copy_code_on_fill), copyCode, info = stringResource(R.string.settings_info_copy_code)) { settings.copyCodeOnFill = it; copyCode = it }
        Toggle(stringResource(R.string.settings_show_logins), suggestions, info = stringResource(R.string.settings_info_show_logins)) { settings.autofillSuggestions = it; suggestions = it }
        // Review 2026-11-15 UX 2: the keyboard's suggestion strip (Android 11+), on by default.
        Toggle(stringResource(R.string.settings_show_in_keyboard), keyboard, info = stringResource(R.string.settings_info_show_in_keyboard)) {
            settings.autofillInline = it; keyboard = it
        }
        Toggle(stringResource(R.string.settings_offer_passkeys), passkeys, info = stringResource(R.string.settings_info_passkeys)) { settings.passkeyProvider = it; passkeys = it }
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
    var codes by remember { mutableStateOf(settings.showCodesRow) }
    val initialsLabel = stringResource(R.string.settings_initials)
    Section(stringResource(R.string.settings_section_appearance), tag = "settings-appearance") {
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
            Appearance.entries.forEachIndexed { i, a ->
                SegmentedButton(
                    selected = a == appearance,
                    onClick = { settings.appearance = a; appearance = a; seams.appearance(a) },
                    shape = SegmentedButtonDefaults.itemShape(i, Appearance.entries.size),
                    modifier = Modifier.testTag("appearance-${a.raw}"),
                ) { Text(a.label(rememberTxt())) }
            }
        }
        // Per-app language: AppCompat stores it and recreates the activity, so the screen reopens in the new language.
        val appContext = androidx.compose.ui.platform.LocalContext.current.applicationContext
        var language by remember { mutableStateOf(LanguageOptions.currentTag(LanguageOptions.applied())) }
        val systemLabel = stringResource(R.string.settings_language_system)
        Picker(
            label = stringResource(R.string.settings_language),
            choices = LanguageOptions.all.map { it.tag },
            selected = language,
            text = { tag -> LanguageOptions.all.first { it.tag == tag }.nativeName ?: systemLabel },
            info = stringResource(R.string.settings_info_language),
        ) { tag ->
            language = tag; LanguageOptions.apply(tag)
            // The widget and the tile render outside the activity: redraw them in the new language now.
            (appContext as? app.localgatekeys.android.LgkApp)?.codesWidget?.request()
            app.localgatekeys.android.widget.CopyCodeTileService.requestRefresh(appContext)
        }
        Toggle(stringResource(R.string.settings_show_codes), codes, info = stringResource(R.string.settings_info_codes_row)) {
            settings.showCodesRow = it; codes = it
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
            modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp).testTag("settings-initials").semantics { contentDescription = initialsLabel },
            decorationBox = { inner ->
                Box {
                    if (initials.isEmpty()) Text(stringResource(R.string.settings_initials), color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
                    inner()
                }
            },
        )
    }
}

@Composable
private fun Generator(settings: AppSettings, onGenerate: (() -> Unit)?, generatorOpen: Boolean) {
    val txt = rememberTxt()
    var options by remember(generatorOpen) { mutableStateOf(GeneratorDefaults(settings).load()) }
    // The passphrase list's size is read off the main thread (normally already cached by LgkApp's warm-up).
    var level by remember { mutableStateOf<GeneratorStrength.Level?>(null) }
    LaunchedEffect(options) { level = withContext(Dispatchers.IO) { GeneratorStrength.level(options) } }
    Section(stringResource(R.string.settings_section_generator), footer = SettingsText(rememberTxt()).generatorFooter, tag = "settings-generator") {
        Column(Modifier.fillMaxWidth().padding(vertical = 10.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.settings_new_passwords), color = LgkTheme.colors.text, style = MaterialTheme.typography.bodyLarge)
                InfoButton(stringResource(R.string.settings_new_passwords), stringResource(R.string.settings_info_generator))
                Spacer(Modifier.weight(1f))
                Text(options.summary(txt), color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.bodyLarge)
            }
            level?.let { StrengthMeter(it, Modifier.padding(top = 6.dp)) }
        }
        if (onGenerate != null) {
            RowButton(stringResource(R.string.command_generate_password_title), "settings-generator-open", onClick = onGenerate)
        }
        RowButton(stringResource(R.string.settings_reset_defaults), "settings-generator-reset") {
            GeneratorDefaults(settings).reset()
            options = GeneratorOptions()
        }
    }
}

@Composable
private fun SyncRow(settings: AppSettings, sync: SyncCoordinator?, onOpen: () -> Unit) {
    val c = LgkTheme.colors
    val settingsText = SettingsText(rememberTxt())
    var eraseOnRemoval by remember { mutableStateOf(settings.eraseOnSyncRemoval) }
    var autoSync by remember { mutableStateOf(settings.autoSync) }
    val membership = sync?.membership?.collectAsStateWithLifecycle()?.value
    val last = sync?.lastSyncedAt?.collectAsStateWithLifecycle()?.value
    val time = remember { DateFormat.getTimeInstance(DateFormat.SHORT) }
    Section(stringResource(R.string.tab_sync), tag = "settings-sync") {
        Row(
            Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Button, onClick = onOpen).testTag("settings-sync-row"),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(stringResource(R.string.tab_sync), color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Text(
                settingsText.syncStatus(membership?.joined == true, last) { time.format(Date(it * 1000)) },
                color = c.secondaryText, style = MaterialTheme.typography.bodyLarge,
            )
            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null, tint = c.secondaryText)
        }
        Toggle(
            stringResource(R.string.settings_auto_sync_title), autoSync,
            info = stringResource(R.string.settings_auto_sync_desc),
        ) { settings.autoSync = it; autoSync = it }
        // Desktop `erase_on_sync_removal` (default on): a verified removal notice erases this phone's vault.
        Toggle(
            stringResource(R.string.settings_erase_on_sync_removal_title), eraseOnRemoval,
            info = stringResource(R.string.settings_erase_on_sync_removal_desc),
        ) { settings.eraseOnSyncRemoval = it; eraseOnRemoval = it }
    }
}

@Composable
private fun ProSection(pro: ProModel, onUpgrade: () -> Unit, copyKey: (String) -> Unit) {
    val state by pro.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val settingsText = SettingsText(rememberTxt())
    Section(stringResource(R.string.settings_section_pro), footer = state.note?.let { stringResource(it.res) }, tag = "settings-pro") {
        Value(stringResource(R.string.settings_status), settingsText.proStatus(state.isPro), divider = false)
        if (!state.isPro) RowButton(stringResource(R.string.settings_upgrade), "settings-upgrade", onClick = onUpgrade)
        val key = state.licenceKey
        if (state.license != null && key != null) {
            Value(settingsText.alsoUnlocksWindows, "")
            RowButton(settingsText.copyKey, "settings-copy-key") { copyKey(key) }
        }
        RowButton(stringResource(R.string.settings_restore_purchases), "settings-restore-purchases", enabled = !state.busy) { scope.launch { pro.restore() } }
    }
}

@Composable
private fun About(seams: SettingsSeams, onAcknowledgements: () -> Unit) {
    val settingsText = SettingsText(rememberTxt())
    Section(stringResource(R.string.settings_section_about), footer = settingsText.dataNotCollected, tag = "settings-about") {
        Value(stringResource(R.string.settings_version), seams.version, divider = false)
        RowButton(stringResource(R.string.settings_acknowledgements), "settings-acknowledgements", onClick = onAcknowledgements)
        RowButton(stringResource(R.string.settings_privacy_policy), "settings-privacy") { seams.openUrl(SettingsText.PRIVACY_POLICY_URL) }
        RowButton(stringResource(R.string.settings_licence_agreement), "settings-licence") { seams.openUrl(SettingsText.LICENCE_AGREEMENT_URL) }
    }
}

@Composable
private fun Acknowledgements(list: List<Acknowledgement>, onOpen: (Acknowledgement) -> Unit, onBack: () -> Unit) {
    BackHandler(onBack = onBack)
    Page(stringResource(R.string.settings_acknowledgements), "acknowledgements", onBack = onBack, doneLabel = stringResource(R.string.common_back)) {
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
    Page(a.name, "licence-text", onBack = onBack, doneLabel = stringResource(R.string.common_back)) {
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
internal fun Page(title: String, tag: String, onBack: () -> Unit, doneLabel: String, content: @Composable () -> Unit) {
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
internal fun Section(title: String?, footer: String? = null, tag: String? = null, content: @Composable ColumnScope.() -> Unit) {
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
private fun Value(label: String, value: String, divider: Boolean = true, info: String? = null) {
    val c = LgkTheme.colors
    if (divider) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f, fill = info == null))
        if (info != null) { InfoButton(label, info); Spacer(Modifier.weight(1f)) }
        Text(value, color = c.secondaryText, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
internal fun Toggle(
    label: String,
    checked: Boolean,
    description: String? = null,
    divider: Boolean = true,
    enabled: Boolean = true,
    tag: String? = null,
    /** The ⓘ explanation; null: no button. */
    info: String? = null,
    onChange: (Boolean) -> Unit,
) {
    val c = LgkTheme.colors
    if (divider) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(enabled = enabled, role = Role.Switch) { onChange(!checked) }
            .then(if (tag != null) Modifier.testTag(tag) else Modifier),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).padding(vertical = if (description != null) 8.dp else 0.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(label, color = if (enabled) c.text else c.secondaryText, style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.weight(1f, fill = false))
                if (info != null) InfoButton(label, info)
            }
            if (description != null) Text(description, color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
        }
        Switch(checked, onCheckedChange = onChange, enabled = enabled, colors = lgkSwitchColors())
    }
}

/** A row that opens a page (the iPhone's NavigationLink): the label and a chevron. */
@Composable
internal fun NavRow(label: String, tag: String, onClick: () -> Unit) {
    val c = LgkTheme.colors
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.Button, onClick = onClick).testTag(tag),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null, tint = c.secondaryText)
    }
}

@Composable
private fun <T> Picker(
    label: String,
    choices: List<T>,
    selected: T,
    text: (T) -> String,
    divider: Boolean = true,
    info: String? = null,
    onPick: (T) -> Unit,
) {
    val c = LgkTheme.colors
    var open by remember { mutableStateOf(false) }
    val description = stringResource(R.string.common_label_value, label, text(selected))
    if (divider) HorizontalDivider(thickness = 0.5.dp, color = c.separator)
    Box {
        Row(
            Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(role = Role.DropdownList) { open = true }
                .semantics { contentDescription = description },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(label, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f, fill = info == null))
            if (info != null) { InfoButton(label, info); Spacer(Modifier.weight(1f)) }
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

/** The ⓘ next to a setting's title: opens a dialog explaining what [label] does. */
@Composable
internal fun InfoButton(label: String, info: String) {
    val c = LgkTheme.colors
    var open by remember { mutableStateOf(false) }
    IconButton(onClick = { open = true }, modifier = Modifier.testTag("settings-info-$label")) {
        Icon(Icons.Outlined.Info, stringResource(R.string.settings_more_info, label), tint = c.secondaryText, modifier = Modifier.width(20.dp))
    }
    if (open) {
        AlertDialog(
            onDismissRequest = { open = false },
            title = { Text(label) },
            text = { Text(info) },
            confirmButton = { TextButton({ open = false }) { Text(stringResource(android.R.string.ok), color = c.accentText) } },
        )
    }
}
