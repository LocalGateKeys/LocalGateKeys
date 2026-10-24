package app.localgatekeys.android.ui.generator

import androidx.activity.compose.BackHandler
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Abc
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Emergency
import androidx.compose.material.icons.filled.FormatSize
import androidx.compose.material.icons.filled.Numbers
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material.icons.filled.SpaceBar
import androidx.compose.material.icons.filled.Straighten
import androidx.compose.material.icons.filled.TextFormat
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.generator.GeneratorModel
import app.localgatekeys.android.generator.GeneratorOptions
import app.localgatekeys.android.generator.GeneratorOptions.Mode
import app.localgatekeys.android.generator.GeneratorSlider
import app.localgatekeys.android.generator.GeneratorStrength
import app.localgatekeys.android.generator.PasswordGenerator
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGlass
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.ui.theme.lgkSwitchColors

/**
 * The password generator (port of `ios/App/Generator/GeneratorView.swift`), drawn over the editor in the same window
 * (so FLAG_SECURE and the autofill exclusion cover it): aurora behind, a solid hero card with the value and its
 * strength, glass controls (Password | Passphrase, Generate again, Copy) and a solid options card. Cancel or back
 * closes it; Use closes it and then hands the value to [onUse].
 */
@Composable
fun GeneratorSheet(model: GeneratorModel, onCancel: () -> Unit, onUse: (String) -> Unit) {
    val c = LgkTheme.colors
    val state by model.state.collectAsStateWithLifecycle()
    LaunchedEffect(model) { model.start() }
    BackHandler(onBack = onCancel)
    // Takes every touch, so none reaches the editor underneath.
    Box(Modifier.fillMaxSize().pointerInput(Unit) { awaitPointerEventScope { while (true) awaitPointerEvent() } }.testTag("generator")) {
        // What the glass controls blur: the aurora only (the controls scroll with the page above it).
        GlassBackdropHost(Modifier.fillMaxSize()) { AuroraBackground() }
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            Row(Modifier.fillMaxWidth().height(64.dp).padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                TextButton(onCancel) { Text("Cancel", color = c.accentText) }
                Text(
                    "Generator", color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    textAlign = TextAlign.Center, modifier = Modifier.weight(1f).semantics { heading() },
                )
                Button(
                    { model.use(dismiss = onCancel, deliver = onUse) },
                    enabled = model.canUse,
                    colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
                    modifier = Modifier.padding(end = 4.dp).testTag("generator-use"),
                ) { Text("Use", fontWeight = FontWeight.SemiBold) }
            }
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).navigationBarsPadding()
                    .padding(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                HeroCard(state, model.strength, onCopy = model::copy)
                ControlsLayout(
                    picker = { ModePicker(state.options.mode, { m -> model.update { it.copy(mode = m) } }) },
                    buttons = {
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            GlassCircle("Generate again", model::regenerate) { Icon(Icons.Filled.Refresh, null, tint = c.text) }
                            GlassCircle(if (state.copied) "Copied" else "Copy", model::copy, enabled = state.value.isNotEmpty()) {
                                Icon(if (state.copied) Icons.Filled.Check else Icons.Filled.ContentCopy, null, tint = c.text)
                            }
                        }
                    },
                )
                OptionsCard(state.options, model)
            }
        }
    }
}

/**
 * Password | Passphrase, then regenerate and copy, on one row when the picker's labels fit beside the buttons, else the
 * picker above the centred buttons (the iPhone's ViewThatFits), so a large text size never cuts a label.
 */
@Composable
private fun ControlsLayout(picker: @Composable () -> Unit, buttons: @Composable () -> Unit) {
    Layout(
        contents = listOf(picker, buttons),
        modifier = Modifier.fillMaxWidth().testTag("generator-controls"),
    ) { (pickerM, buttonsM), constraints ->
        val width = constraints.maxWidth
        val gap = 12.dp.roundToPx()
        val b = buttonsM.first().measure(Constraints())
        val p0 = pickerM.first()
        val stacked = ControlsFit.stacks(p0.maxIntrinsicWidth(b.height), b.width, gap, width)
        if (!stacked) {
            val p = p0.measure(Constraints.fixedWidth(width - gap - b.width))
            val h = maxOf(p.height, b.height)
            layout(width, h) {
                p.place(0, (h - p.height) / 2)
                b.place(width - b.width, (h - b.height) / 2)
            }
        } else {
            val p = p0.measure(Constraints.fixedWidth(width))
            layout(width, p.height + gap + b.height) {
                p.place(0, 0)
                b.place((width - b.width) / 2, p.height + gap)
            }
        }
    }
}

/** The ControlsLayout decision, plain so it can be unit tested. */
internal object ControlsFit {
    /** True when the picker at its natural width, the gap and the buttons do not fit in [width]. */
    fun stacks(pickerWidth: Int, buttonsWidth: Int, gap: Int, width: Int): Boolean = pickerWidth + gap + buttonsWidth > width
}

/** The value, large and coloured by character class, with its strength. Solid, never glass. Tap to copy. */
@Composable
private fun HeroCard(state: GeneratorModel.State, strength: GeneratorStrength.Level, onCopy: () -> Unit) {
    val c = LgkTheme.colors
    // glowOrange reads well on the dark surface only; on the white surface the darker amber warning is used.
    val symbol = if (LgkTheme.isDark) c.glowOrange else c.warning
    Column(
        Modifier.fillMaxWidth().lgkGroupSurface().clip(RoundedCornerShape(22.dp))
            .clickable(role = Role.Button, onClickLabel = "Copy", onClick = onCopy)
            .padding(18.dp).testTag("generator-hero"),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                if (state.options.mode == Mode.PASSWORD) "Password" else "Passphrase",
                color = c.secondaryText, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f),
            )
            Text(
                if (state.copied) "Copied" else "Tap to copy",
                color = if (state.copied) c.success else c.secondaryText, style = MaterialTheme.typography.bodySmall,
            )
        }
        val error = state.error
        if (error != null) {
            Text(
                error, color = c.danger, style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.fillMaxWidth().heightIn(min = 60.dp).testTag("generator-error"),
            )
        } else {
            Text(
                colored(state.value, c.accent, c.text, symbol),
                style = MaterialTheme.typography.titleLarge, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold,
                modifier = Modifier.fillMaxWidth().heightIn(min = 60.dp).testTag("generator-value"),
            )
        }
        StrengthMeter(strength)
    }
}

/** Digits in accent, symbols in orange, letters in the text colour. */
internal fun colored(value: String, digit: Color, letter: Color, symbol: Color): AnnotatedString = buildAnnotatedString {
    var i = 0
    while (i < value.length) {
        val cp = value.codePointAt(i)
        val color = when {
            cp in '0'.code..'9'.code -> digit
            Character.isLetter(cp) -> letter
            else -> symbol
        }
        withStyle(SpanStyle(color = color)) { append(String(Character.toChars(cp))) }
        i += Character.charCount(cp)
    }
}

/** Four segments and the strength's name: danger, warning, accent, success. Also under a saved password on the detail. */
@Composable
fun StrengthMeter(level: GeneratorStrength.Level, modifier: Modifier = Modifier) {
    val c = LgkTheme.colors
    val fill = when (level) {
        GeneratorStrength.Level.WEAK -> c.danger
        GeneratorStrength.Level.FAIR -> c.warning
        GeneratorStrength.Level.STRONG -> c.accent
        GeneratorStrength.Level.VERY_STRONG -> c.success
    }
    Row(
        modifier.fillMaxWidth().semantics(mergeDescendants = true) { contentDescription = "Strength: ${level.label}" }
            .testTag("strength-meter"),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(Modifier.weight(1f), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            for (i in 0 until 4) {
                val color by animateColorAsState(if (i < level.segments) fill else c.separator, label = "segment")
                Box(Modifier.weight(1f).height(6.dp).clip(CircleShape).background(color))
            }
        }
        Text(level.label, color = c.text, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold, maxLines = 1)
    }
}

/** Password | Passphrase as a glass capsule; the selected side gets the accent pill. */
@Composable
private fun ModePicker(mode: Mode, onSelect: (Mode) -> Unit, modifier: Modifier = Modifier) {
    val c = LgkTheme.colors
    Row(modifier.heightIn(min = 48.dp).lgkGlass(CircleShape).padding(4.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        for ((m, title) in listOf(Mode.PASSWORD to "Password", Mode.PASSPHRASE to "Passphrase")) {
            val selected = mode == m
            Box(
                Modifier.weight(1f).clip(CircleShape)
                    .background(if (selected) c.accent.copy(alpha = 0.18f) else Color.Transparent)
                    .selectable(selected, role = Role.Tab, onClick = { onSelect(m) })
                    .testTag("generator-mode-${m.raw}")
                    .padding(horizontal = 10.dp, vertical = 10.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    title, color = if (selected) c.accentText else c.text, style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun GlassCircle(description: String, onClick: () -> Unit, enabled: Boolean = true, content: @Composable () -> Unit) {
    Box(
        Modifier.size(48.dp).lgkGlass(CircleShape).clip(CircleShape)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .semantics { contentDescription = description },
        contentAlignment = Alignment.Center,
    ) { content() }
}

/** The options for the current mode on a solid card. minDigits, minSymbols, exclude and symbolSet have no controls. */
@Composable
private fun OptionsCard(o: GeneratorOptions, model: GeneratorModel) {
    val set: ((GeneratorOptions) -> GeneratorOptions) -> Unit = { model.update(it) }
    Column(Modifier.fillMaxWidth().lgkGroupSurface().padding(vertical = 4.dp).testTag("generator-options")) {
        if (o.mode == Mode.PASSWORD) {
            LengthRow(o.length, model)
            Divider()
            ToggleRow("Lowercase (a-z)", Icons.Filled.Abc, o.lowercase) { v -> set { it.copy(lowercase = v) } }
            Divider()
            ToggleRow("Uppercase (A-Z)", Icons.Filled.TextFormat, o.uppercase) { v -> set { it.copy(uppercase = v) } }
            Divider()
            ToggleRow("Digits (0-9)", Icons.Filled.Numbers, o.digits) { v -> set { it.copy(digits = v) } }
            Divider()
            ToggleRow("Symbols", Icons.Filled.Emergency, o.symbols) { v -> set { it.copy(symbols = v) } }
            Divider()
            ToggleRow("Avoid look-alike characters", Icons.Filled.VisibilityOff, o.avoidAmbiguous) { v ->
                set { it.copy(avoidAmbiguous = v) }
            }
        } else {
            WordsRow(o.words, model)
            Divider()
            SeparatorRow(o.separator) { s -> set { it.copy(separator = s) } }
            Divider()
            ToggleRow("Capitalize words", Icons.Filled.FormatSize, o.capitalize) { v -> set { it.copy(capitalize = v) } }
            Divider()
            ToggleRow("Add a number", Icons.Filled.Numbers, o.appendNumber) { v -> set { it.copy(appendNumber = v) } }
        }
    }
}

@Composable
private fun Divider() {
    Box(Modifier.padding(start = 56.dp).fillMaxWidth().height(1.dp).background(LgkTheme.colors.separator))
}

@Composable
private fun OptionIcon(icon: ImageVector) {
    val c = LgkTheme.colors
    Box(
        Modifier.size(30.dp).clip(RoundedCornerShape(8.dp)).background(c.innerTile),
        contentAlignment = Alignment.Center,
    ) { Icon(icon, null, tint = c.accentText, modifier = Modifier.size(18.dp)) }
}

@Composable
private fun ToggleRow(title: String, icon: ImageVector, checked: Boolean, onChange: (Boolean) -> Unit) {
    val c = LgkTheme.colors
    Row(
        Modifier.fillMaxWidth().toggleable(checked, role = Role.Switch, onValueChange = onChange)
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OptionIcon(icon)
        Text(title, color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Switch(checked, onCheckedChange = null, colors = lgkSwitchColors())
    }
}

/** Slider 8-64 for the usual range; the stepper goes on to 256. */
@Composable
private fun LengthRow(length: Int, model: GeneratorModel) {
    val c = LgkTheme.colors
    val range = GeneratorSlider.LENGTH_RANGE
    Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OptionIcon(Icons.Filled.Straighten)
            Text("Length", color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Text("$length", color = c.text, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold,
                fontFamily = FontFamily.Monospace, modifier = Modifier.testTag("generator-length"))
            Row(Modifier.clip(CircleShape).background(c.innerTile)) {
                IconButton({ model.stepLength(-1) }, enabled = length > PasswordGenerator.LENGTH_RANGE.first,
                    modifier = Modifier.size(40.dp).semantics { contentDescription = "Decrease length" }) {
                    Icon(Icons.Filled.Remove, null, tint = c.accentText)
                }
                IconButton({ model.stepLength(+1) }, enabled = length < PasswordGenerator.LENGTH_RANGE.last,
                    modifier = Modifier.size(40.dp).semantics { contentDescription = "Increase length" }) {
                    Icon(Icons.Filled.Add, null, tint = c.accentText)
                }
            }
        }
        Slider(
            value = GeneratorSlider.position(length, range),
            onValueChange = { v -> GeneratorSlider.moved(v, length, range)?.let { n -> model.update { it.copy(length = n) } } },
            valueRange = range.first.toFloat()..range.last.toFloat(),
            steps = range.last - range.first - 1,
            colors = SliderDefaults.colors(
                thumbColor = c.accent, activeTrackColor = c.accent,
                activeTickColor = Color.Transparent, inactiveTickColor = Color.Transparent,
            ),
            modifier = Modifier.semantics { contentDescription = "Length"; stateDescription = "$length characters" },
        )
    }
}

@Composable
private fun WordsRow(words: Int, model: GeneratorModel) {
    val c = LgkTheme.colors
    val range = PasswordGenerator.WORDS_RANGE
    Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OptionIcon(Icons.Filled.SpaceBar)
            Text("Words", color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Text("$words", color = c.text, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.SemiBold,
                fontFamily = FontFamily.Monospace)
        }
        Slider(
            value = GeneratorSlider.position(words, range),
            onValueChange = { v -> GeneratorSlider.moved(v, words, range)?.let { n -> model.update { it.copy(words = n) } } },
            valueRange = range.first.toFloat()..range.last.toFloat(),
            steps = range.last - range.first - 1,
            colors = SliderDefaults.colors(
                thumbColor = c.accent, activeTrackColor = c.accent,
                activeTickColor = Color.Transparent, inactiveTickColor = Color.Transparent,
            ),
            modifier = Modifier.semantics { contentDescription = "Words"; stateDescription = "$words words" },
        )
    }
}

/** The separators as chips that wrap onto further rows, so every chip is fully visible at any text size. */
@Composable
private fun SeparatorRow(selected: String, onSelect: (String) -> Unit) {
    val c = LgkTheme.colors
    Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OptionIcon(Icons.Filled.Remove)
            Text("Separator", color = c.text, style = MaterialTheme.typography.bodyLarge)
        }
        ChipFlowLayout(spacing = 8.dp) {
            for ((sep, name) in SEPARATORS) {
                val on = selected == sep
                Box(
                    Modifier.clip(CircleShape)
                        .background(if (on) c.accent.copy(alpha = 0.18f) else c.innerTile)
                        .then(if (on) Modifier.border(1.dp, c.accent.copy(alpha = 0.5f), CircleShape) else Modifier)
                        .selectable(on, role = Role.RadioButton, onClick = { onSelect(sep) })
                        .semantics { contentDescription = "Separator: $name" }
                        .padding(horizontal = 14.dp, vertical = 8.dp),
                ) {
                    Text(
                        name, color = if (on) c.accentText else c.text, style = MaterialTheme.typography.bodyMedium,
                        fontWeight = if (on) FontWeight.SemiBold else FontWeight.Normal,
                    )
                }
            }
        }
    }
}

/** The separator choices and their names, in the iPhone's order. */
internal val SEPARATORS = listOf("-" to "Dash", " " to "Space", "." to "Dot", "_" to "Underscore", "" to "None")
